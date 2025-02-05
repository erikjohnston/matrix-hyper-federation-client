//! Module for sending Matrix federation requests

use std::convert::TryInto;
use std::sync::Arc;

use anyhow::{bail, format_err, Context, Error};
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::request::{Builder, Parts};
use http::{HeaderValue, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::Connect;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde_json::value::RawValue;
use signed_json::signed::Wrap;
use signed_json::{Canonical, CanonicalWrapper, Signed};

use crate::server_resolver::{handle_delegated_server, MatrixConnector};

/// A [`hyper_util::client::legacy::Client`] that routes `matrix://` (Synapse <1.87.0rc1
/// (2023-06-27)) and `matrix-federation://` (Synapse >=1.87.0rc1 (2023-06-27)) URIs
/// correctly, but does not sign the requests.
///
/// Either use [`SigningFederationClient`] if you want requests to be automatically
/// signed, or [`sign_and_build_json_request`] to sign the requests.
#[derive(Debug, Clone)]
pub struct FederationClient {
    pub client: Client<MatrixConnector, Full<Bytes>>,
}

impl FederationClient {
    pub fn new(client: Client<MatrixConnector, Full<Bytes>>) -> Self {
        FederationClient { client }
    }

    /// Helper function to build a [`FederationClient`].
    pub fn new_with_default_resolver() -> Result<FederationClient, Error> {
        let connector = MatrixConnector::with_default_resolver()?;

        Ok(FederationClient {
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    pub async fn request(
        &self,
        mut req: Request<Full<Bytes>>,
    ) -> Result<Response<hyper::body::Incoming>, Error> {
        req = handle_delegated_server(&self.client, req).await?;

        self.client.request(req).await.map_err(Into::into)
    }
}

/// A HTTP client that correctly resolves `matrix://` and `matrix-federation://` URIs and signs the
/// requests.
///
/// This will fail for requests to a `matrix://` or `matrix-federation://` URI that have a non-JSON body.
///
/// **Note**: Using this is less efficient than using a [`Client`] with a
/// [`MatrixConnector`] and manually signing the requests, as the implementation
/// needs to deserialize the JSON request body so that it can be correctly
/// signed.
#[derive(Debug, Clone)]
pub struct SigningFederationClient<C = MatrixConnector> {
    client: Client<C, Full<Bytes>>,
    server_name: String,
    key_id: String,
    secret_key: Arc<SigningKey>,
}

impl SigningFederationClient<MatrixConnector> {
    /// Create a new client with the default resolver.
    pub fn new(
        server_name: impl ToString,
        key_id: impl ToString,
        secret_key: SigningKey,
    ) -> Result<Self, Error> {
        let connector = MatrixConnector::with_default_resolver()?;

        Ok(SigningFederationClient {
            client: Client::builder(TokioExecutor::new()).build(connector),
            server_name: server_name.to_string(),
            key_id: key_id.to_string(),
            secret_key: Arc::new(secret_key),
        })
    }
}

impl<C> SigningFederationClient<C> {
    /// Create a new [`SigningFederationClient`] using the given [`Client`].
    ///
    /// Note, the connector used by the [`Client`] must support `matrix://` and
    /// `matrix-federation://` URIs.
    pub fn with_client(
        client: Client<C, Full<Bytes>>,
        server_name: String,
        key_name: String,
        secret_key: SigningKey,
    ) -> Self {
        SigningFederationClient {
            client,
            server_name,
            key_id: key_name,
            secret_key: Arc::new(secret_key),
        }
    }
}

impl<C> SigningFederationClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Make a GET request to the given URI.
    ///
    /// Will sign the request if the URI has a `matrix` scheme.
    pub async fn get(&self, uri: Uri) -> Result<Response<hyper::body::Incoming>, Error> {
        let req = Request::builder().uri(uri).body(Full::new(Bytes::new()))?;

        self.request(req).await
    }

    /// Send the request.
    ///
    /// For `matrix://` or `matrix-federation://` URIs the request body must be JSON (if
    /// not empty) and the request will be signed.
    pub async fn request(
        &self,
        mut req: Request<Full<Bytes>>,
    ) -> Result<Response<hyper::body::Incoming>, Error> {
        req = handle_delegated_server(&self.client, req).await?;

        // Return-early and make a normal request if the URI scheme is not `matrix://`
        // or `matrix-federation://`.
        match req.uri().scheme_str() {
            Some("matrix") | Some("matrix-federation") => {}
            _ => {
                return self.client.request(req).await.map_err(Into::into);
            }
        }

        if !req.body().is_end_stream()
            && req.headers().get(CONTENT_TYPE)
                != Some(&HeaderValue::from_static("application/json"))
        {
            bail!("Request has a non-JSON body")
        }

        let (mut parts, body) = req.into_parts();

        let content = if body.is_end_stream() {
            None
        } else {
            let bytes = BodyExt::collect(body).await.unwrap().to_bytes();
            let json_string = String::from_utf8(bytes.to_vec())?;
            Some(RawValue::from_string(json_string)?)
        };

        let auth_header = make_auth_header_from_parts(
            &self.server_name,
            &self.key_id,
            &self.secret_key,
            &parts,
            content.as_ref(),
        )
        .context("Failed to sign request")?;

        parts.headers.insert(AUTHORIZATION, auth_header.parse()?);

        let new_body = if let Some(raw_value) = content {
            raw_value.to_string().into()
        } else {
            Full::new(Bytes::new())
        };

        let new_req = Request::from_parts(parts, new_body);

        self.client.request(new_req).await.map_err(Into::into)
    }
}

/// Make an appropriate auth header value from the given values.
pub fn make_auth_header<T: serde::Serialize>(
    server_name: &str,
    key_id: &str,
    secret_key: &SigningKey,
    method: &str,
    path: &str,
    destination: &str,
    content: Option<T>,
) -> Result<String, Error> {
    let request_json = RequestJson {
        method,
        uri: path,
        origin: server_name,
        destination,
        content,
    };

    let signed: Signed<_> = Signed::wrap(request_json).context("Failed to serialize content")?;
    let sig = signed.sign_detached(secret_key);
    let b64_sig = BASE64_STANDARD_NO_PAD.encode(sig.to_bytes());

    Ok(format!(
        r#"X-Matrix origin={},destination="{}",key="{}",sig="{}""#,
        server_name, destination, key_id, b64_sig,
    ))
}

/// Make an appropriate auth header value from [`http::request::Parts`].
pub fn make_auth_header_from_parts<T: serde::Serialize>(
    server_name: &str,
    key_id: &str,
    secret_key: &SigningKey,
    parts: &Parts,
    content: Option<T>,
) -> Result<String, Error> {
    make_auth_header(
        server_name,
        key_id,
        secret_key,
        parts.method.as_str(),
        parts
            .uri
            .path_and_query()
            .ok_or_else(|| format_err!("Path is required"))?
            .as_str(),
        parts
            .uri
            .host()
            .ok_or_else(|| format_err!("Host is required"))?,
        content,
    )
}

/// Takes a [`http::request::Builder`], signs it and builds it.
pub fn sign_and_build_json_request<T: serde::Serialize>(
    server_name: &str,
    key_id: &str,
    secret_key: &SigningKey,
    mut request_builder: Builder,
    content: Option<T>,
) -> Result<Request<Full<Bytes>>, Error> {
    let uri = request_builder
        .uri_ref()
        .ok_or_else(|| format_err!("URI must be set"))?;

    let host = uri
        .host()
        .ok_or_else(|| format_err!("Host is required in URI"))?;

    let path = uri
        .path_and_query()
        .ok_or_else(|| format_err!("Path is required in URI"))?
        .as_str();

    let method = request_builder
        .method_ref()
        .ok_or_else(|| format_err!("Method must be set"))?;

    // We wrap any content in `Canonical` so that the content only get
    // serialized once.
    let canonical_content = if let Some(content) = content {
        Some(Canonical::<_>::wrap(content).context("Failed to serialize content")?)
    } else {
        None
    };

    let header_string = make_auth_header(
        server_name,
        key_id,
        secret_key,
        method.as_str(),
        path,
        host,
        canonical_content.as_ref(),
    )?;

    let header_value = header_string.try_into()?;

    let body = if let Some(c) = canonical_content {
        Full::new(Bytes::from(c.into_canonical()))
    } else {
        Full::new(Bytes::new())
    };

    request_builder
        .headers_mut()
        .map(|header_map| header_map.insert(AUTHORIZATION, header_value));

    let request = request_builder.body(body)?;
    Ok(request)
}

/// The JSON structure used to generate signatures for requests.
#[derive(Serialize, Debug)]
pub struct RequestJson<'a, T> {
    method: &'a str,
    uri: &'a str,
    origin: &'a str,
    destination: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<T>,
}

impl<'a, T> RequestJson<'a, T> {
    pub fn new(
        method: &'a str,
        uri: &'a str,
        origin: &'a str,
        destination: &'a str,
        content: Option<T>,
    ) -> Self {
        Self {
            method,
            uri,
            origin,
            destination,
            content,
        }
    }
}

/// An extension trait for [`Builder`] that adds helper functions to create
/// signed requests.
pub trait SignedRequestBuilderExt {
    /// Sign and build the request with and empty body.
    fn signed(
        self,
        server_name: &str,
        key_id: &str,
        secret_key: &SigningKey,
    ) -> Result<Request<Full<Bytes>>, Error>;

    /// Sign and build the request with the given JSON body.
    fn signed_json<T: Serialize>(
        self,
        server_name: &str,
        key_id: &str,
        secret_key: &SigningKey,
        content: T,
    ) -> Result<Request<Full<Bytes>>, Error>;

    /// Sign and build the request with optional JSON body.
    fn signed_json_opt<T: Serialize>(
        self,
        server_name: &str,
        key_id: &str,
        secret_key: &SigningKey,
        content: Option<T>,
    ) -> Result<Request<Full<Bytes>>, Error>;
}

impl SignedRequestBuilderExt for Builder {
    fn signed(
        self,
        server_name: &str,
        key_id: &str,
        secret_key: &SigningKey,
    ) -> Result<Request<Full<Bytes>>, Error> {
        sign_and_build_json_request::<()>(server_name, key_id, secret_key, self, None)
    }

    fn signed_json<T: Serialize>(
        self,
        server_name: &str,
        key_id: &str,
        secret_key: &SigningKey,
        content: T,
    ) -> Result<Request<Full<Bytes>>, Error> {
        sign_and_build_json_request(server_name, key_id, secret_key, self, Some(content))
    }

    fn signed_json_opt<T: Serialize>(
        self,
        server_name: &str,
        key_id: &str,
        secret_key: &SigningKey,
        content: Option<T>,
    ) -> Result<Request<Full<Bytes>>, Error> {
        if let Some(content) = content {
            self.signed_json(server_name, key_id, secret_key, content)
        } else {
            self.signed(server_name, key_id, secret_key)
        }
    }
}

/// A parsed Matrix `Authorization` header.
pub struct AuthHeader<'a> {
    pub origin: &'a str,
    pub destination: Option<&'a str>,
    pub key_id: &'a str,
    pub signature: &'a str,
}

pub fn parse_auth_header(header: &str) -> Option<AuthHeader> {
    let header = header.strip_prefix("X-Matrix ")?;

    let mut origin = None;
    let mut destination = None;
    let mut key_id = None;
    let mut signature = None;
    for item in header.split(',') {
        let (key, value) = item.split_at(item.find('=')?);
        let value = value.trim_matches('=');

        // Strip out any quotes.
        let value = if value.starts_with('"') && value.ends_with('"') {
            &value[1..value.len() - 1]
        } else {
            value
        };

        match key {
            "origin" => origin = Some(value),
            "destination" => destination = Some(value),
            "key" => key_id = Some(value),
            "sig" => signature = Some(value),
            _ => {}
        }
    }

    Some(AuthHeader {
        origin: origin?,
        destination,
        key_id: key_id?,
        signature: signature?,
    })
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn test_parse_auth_header() {
        let header = parse_auth_header(
            r#"X-Matrix origin=foo.com,destination=baz.com,key="key_id",sig="some_signature""#,
        )
        .unwrap();

        assert_eq!(header.origin, "foo.com");
        assert_eq!(header.destination, Some("baz.com"));
        assert_eq!(header.key_id, "key_id");
        assert_eq!(header.signature, "some_signature");
    }

    /// The "destination" parameter of an X-Matrix scheme Authorization header was added in Matrix v1.3,
    /// therefore some implementations may not include it.
    /// https://spec.matrix.org/v1.3/server-server-api/#request-authentication.
    #[test]
    fn test_parse_auth_header_no_destination() {
        let header =
            parse_auth_header(r#"X-Matrix origin=foo.com,key="key_id",sig="some_signature""#)
                .unwrap();

        assert_eq!(header.origin, "foo.com");
        assert_eq!(header.destination, None);
        assert_eq!(header.key_id, "key_id");
        assert_eq!(header.signature, "some_signature");
    }

    #[tokio::test]
    async fn auth_header_no_content() {
        let secret_key = SigningKey::from_bytes(&[0u8; 32]);

        let header = make_auth_header::<()>(
            "localhost",
            "ed25519:test",
            &secret_key,
            "GET",
            "/test",
            "matrix.org",
            None,
        )
        .unwrap();

        assert_eq!(
            header,
            r#"X-Matrix origin=localhost,destination="matrix.org",key="ed25519:test",sig="aemgn56SKst12mSbh2X0l3pBuzyWmAkURVknrTqz/ev2p8KDnKHXnFw/UsLOfwbD6V/om4Lh+DzeyE0MlJ1GBA""#
        );
    }

    #[tokio::test]
    async fn auth_header_content() {
        let secret_key = SigningKey::from_bytes(&[0u8; 32]);

        let mut map = BTreeMap::new();
        map.insert("foo", "bar");

        let header = make_auth_header(
            "localhost",
            "ed25519:test",
            &secret_key,
            "GET",
            "/test",
            "matrix.org",
            Some(map),
        )
        .unwrap();

        assert_eq!(
            header,
            r#"X-Matrix origin=localhost,destination="matrix.org",key="ed25519:test",sig="JwOvw9q9rGU1FOX+nVqZkXL9P6WhsKE3aNV2Q+Ftj0urJHv8olv7r7gOMZM3nITm0gVwYBN8s0FBGJymeQt9DA""#
        );
    }
}
