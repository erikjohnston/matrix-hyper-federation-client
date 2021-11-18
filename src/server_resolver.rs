//! Module for resolving Matrix server names.

use anyhow::{bail, format_err, Error};
use futures::FutureExt;
use futures_util::stream::StreamExt;
use http::Uri;
use hyper::client::connect::{Connection, HttpConnector};
use hyper::service::Service;
use hyper::Client;
use hyper_tls::{HttpsConnector, MaybeHttpsStream};
use log::{debug, trace};
use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as AsyncTlsConnector;
use trust_dns_resolver::error::ResolveErrorKind;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{self, Poll};

/// A resolved host for a Matrix server.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The host name to connect to.
    ///
    /// These can be resolved as normal `A`/`AAAA` records.
    pub host: String,

    /// The port to connect to.
    pub port: u16,

    /// The value to use in the `Host` header of requests to this endpoint.
    pub host_header: String,

    /// The TLS server name to use when connecting to this endpoint.
    ///
    /// *Note*: This can be different from the `host_header` field if the server
    /// name has been delegated to a different server name using a `.well-known`
    /// file.
    pub tls_name: String,
}

/// A resolver for Matrix server names.
#[derive(Debug, Clone)]
pub struct MatrixResolver {
    resolver: trust_dns_resolver::TokioAsyncResolver,
    http_client: Client<HttpsConnector<HttpConnector>>,
}

impl MatrixResolver {
    /// Create a new [`MatrixResolver`] with a default HTTP client.
    pub async fn new() -> Result<MatrixResolver, Error> {
        let http_client = hyper::Client::builder().build(HttpsConnector::new());

        MatrixResolver::with_http_client(http_client).await
    }

    /// Resolves a Matrix server name to a list of [`Endpoint`]s to try.
    ///
    /// This will first do a `.well-known` lookup to check if the server has
    /// delegated Matrix traffic to another host, and then will do the
    /// appropriate SRV lookups.
    ///
    /// *Note*: The [`Endpoint`]s returned include host names that will need to
    /// be resolved as normal.
    pub async fn resolve_server_name(&self, server_name: &str) -> Result<Vec<Endpoint>, Error> {
        let host;
        let port;

        // Check if we have a port on the end, being careful of the case where
        // `server_name` is a IPv6 literal.
        if let Some((maybe_host, maybe_port)) = server_name.rsplit_once(':') {
            // There is a colon, so now we just need to check that the right
            // hand part is as valid port, i.e. a positive number. (Note that in
            // the case of IPv6 literals there would be a `]` in the right hand portion)
            if let Ok(parsed_port) = maybe_port.parse::<u16>() {
                host = maybe_host.to_string();
                port = Some(parsed_port);
            } else {
                host = server_name.to_string();
                port = None;
            }
        } else {
            host = server_name.to_string();
            port = None;
        }

        self.resolve_server_name_from_host_port(host, port).await
    }

    /// Create a new [`MatrixResolver`] with a given HTTP client.
    pub async fn with_http_client(
        http_client: Client<HttpsConnector<HttpConnector>>,
    ) -> Result<MatrixResolver, Error> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;

        Ok(MatrixResolver {
            resolver,
            http_client,
        })
    }

    /// Resolves a [`Uri`] to a list of [`Endpoint`]s to try.
    ///
    /// See [`MatrixResolver::resolve_server_name`].
    pub async fn resolve_server_name_from_uri(&self, uri: &Uri) -> Result<Vec<Endpoint>, Error> {
        let host = uri.host().expect("URI has no host").to_string();
        let port = uri.port_u16();

        self.resolve_server_name_from_host_port(host, port).await
    }

    /// Resolves a host and optional port to a list of [`Endpoint`]s to try.
    ///
    /// *Note*: The host *must not* contain a port.
    ///
    /// See [`MatrixResolver::resolve_server_name`].
    pub async fn resolve_server_name_from_host_port(
        &self,
        mut host: String,
        mut port: Option<u16>,
    ) -> Result<Vec<Endpoint>, Error> {
        debug!("Resolving host={}, port={:?}", host, port);

        let mut authority = if let Some(p) = port {
            format!("{}:{}", host, p)
        } else {
            host.to_string()
        };

        // If a literal IP or includes port then we shortcircuit.
        if host.parse::<IpAddr>().is_ok() || port.is_some() {
            return Ok(vec![Endpoint {
                host: host.to_string(),
                port: port.unwrap_or(8448),

                host_header: authority.to_string(),
                tls_name: host.to_string(),
            }]);
        }

        // Do well-known delegation lookup.
        if let Some(server) = get_well_known(&self.http_client, &host).await {
            let a = http::uri::Authority::from_str(&server.server)?;
            host = a.host().to_string();
            port = a.port_u16();
            authority = a.to_string();

            debug!("Found .well-known, returned {}", &server.server);
        } else {
            debug!("No .well-known found");
        }

        // If a literal IP or includes port then we short circuit.
        if host.parse::<IpAddr>().is_ok() || port.is_some() {
            debug!("Host is IP or port is set");

            return Ok(vec![Endpoint {
                host: host.clone(),
                port: port.unwrap_or(8448),

                host_header: authority.to_string(),
                tls_name: host.clone(),
            }]);
        }

        let result = self
            .resolver
            .srv_lookup(format!("_matrix._tcp.{}", host).as_ref())
            .await;

        let records = match result {
            Ok(records) => records,
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    debug!("SRV returned not found, using host and port 8448");
                    return Ok(vec![Endpoint {
                        host: host.clone(),
                        port: 8448,
                        host_header: authority.to_string(),
                        tls_name: host.clone(),
                    }]);
                }
                _ => return Err(err.into()),
            },
        };

        let mut priority_map: BTreeMap<u16, Vec<_>> = BTreeMap::new();

        let mut count = 0;
        for record in records {
            count += 1;
            let priority = record.priority();
            priority_map.entry(priority).or_default().push(record);
        }

        let mut results = Vec::with_capacity(count);

        for (_priority, records) in priority_map {
            // TODO: Correctly shuffle records
            results.extend(records.into_iter().map(|record| Endpoint {
                host: record.target().to_utf8(),
                port: record.port(),

                host_header: host.to_string(),
                tls_name: host.to_string(),
            }))
        }

        debug!(
            "SRV returned {} results. First: host={} port={}",
            count, &results[0].host, &results[0].port
        );

        Ok(results)
    }
}

/// Check if there is a `.well-known` file present on the given host.
pub async fn get_well_known<C>(http_client: &Client<C>, host: &str) -> Option<WellKnownServer>
where
    C: Service<Uri> + Clone + Sync + Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    C::Future: Unpin + Send,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
{
    // TODO: Add timeout and cache result

    let uri = hyper::Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query("/.well-known/matrix/server")
        .build()
        .ok()?;

    let mut body = http_client.get(uri).await.ok()?.into_body();

    let mut vec = Vec::new();
    while let Some(next) = body.next().await {
        // TODO: Limit size of body.
        let chunk = next.ok()?;
        vec.extend(chunk);
    }

    serde_json::from_slice(&vec).ok()?
}

/// A parsed Matrix `.well-known` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownServer {
    #[serde(rename = "m.server")]
    pub server: String,
}

/// A connector that can be used with a [`hyper::Client`] that correctly
/// resolves and connects to `matrix://` URIs.
#[derive(Debug, Clone)]
pub struct MatrixConnector {
    resolver: MatrixResolver,
}

impl MatrixConnector {
    /// Create new [`MatrixConnector`] with the given [`MatrixResolver`].
    pub fn with_resolver(resolver: MatrixResolver) -> MatrixConnector {
        MatrixConnector { resolver }
    }

    /// Create new [`MatrixConnector`] with a default [`MatrixResolver`].
    pub async fn with_default_resolver() -> Result<MatrixConnector, Error> {
        let resolver = MatrixResolver::new().await?;

        Ok(MatrixConnector { resolver })
    }
}

type ConnectorFuture =
    Pin<Box<dyn Future<Output = Result<MaybeHttpsStream<TcpStream>, Error>> + Send>>;

impl Service<Uri> for MatrixConnector {
    type Response = MaybeHttpsStream<TcpStream>;
    type Error = Error;
    type Future = ConnectorFuture;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let resolver = self.resolver.clone();
        async move {
            let endpoints = resolver
                .resolve_server_name_from_host_port(
                    dst.host().expect("hostname").to_string(),
                    dst.port_u16(),
                )
                .await?;

            for endpoint in endpoints {
                match try_connecting(&dst, &endpoint).await {
                    Ok(r) => {
                        trace!(
                            "Connected to host={} port={}",
                            &endpoint.host,
                            &endpoint.port
                        );
                        return Ok(r);
                    }
                    // Errors here are not unexpected, and we just move on
                    // with our lives.
                    Err(e) => debug!(
                        "Failed to connect to {} via {}:{} because {}",
                        dst.host().expect("hostname"),
                        endpoint.host,
                        endpoint.port,
                        e,
                    ),
                }
            }

            Err(format_err!("help"))
        }
        .boxed()
    }
}

/// Attempts to connect to a particular endpoint.
async fn try_connecting(
    dst: &Uri,
    endpoint: &Endpoint,
) -> Result<MaybeHttpsStream<TcpStream>, Error> {
    let tcp = TcpStream::connect((&endpoint.host as &str, endpoint.port)).await?;

    match dst.scheme_str() {
        Some("http") => return Ok(tcp.into()),
        Some("https" | "matrix") => {}
        Some(s) => bail!("Unknown scheme '{}'", s),
        None => bail!("URL missing scheme"),
    }

    let connector: AsyncTlsConnector = if dst.host().expect("hostname").contains("localhost") {
        TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?
            .into()
    } else {
        TlsConnector::new().unwrap().into()
    };

    let tls = connector.connect(&endpoint.tls_name, tcp).await?;

    Ok(tls.into())
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use futures::FutureExt;
    use http::Uri;
    use hyper::client::connect::Connected;
    use hyper::client::connect::Connection;
    use hyper::server::conn::Http;
    use hyper::service::Service;
    use std::future::Future;
    use std::pin::Pin;
    use std::{
        io::Cursor,
        sync::{Arc, Mutex},
        task::{self, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};

    type TestConnectorFuture = Pin<Box<dyn Future<Output = Result<TestConnection, Error>> + Send>>;

    /// A connector that returns a connection which returns 200 OK to all connections.
    #[derive(Clone)]
    pub struct TestConnector;

    impl Service<Uri> for TestConnector {
        type Response = TestConnection;
        type Error = Error;
        type Future = TestConnectorFuture;

        fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            // This connector is always ready, but others might not be.
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _dst: Uri) -> Self::Future {
            let (client, server) = TestConnection::double_ended();

            {
                let service = hyper::service::service_fn(|_| async move {
                    Ok(hyper::Response::new(hyper::Body::from("Hello World")))
                        as Result<_, hyper::http::Error>
                });
                let fut = Http::new().serve_connection(server, service);
                tokio::spawn(fut);
            }

            futures::future::ok(client).boxed()
        }
    }

    #[derive(Default)]
    struct TestConnectionInner {
        outbound_buffer: Cursor<Vec<u8>>,
        inbound_buffer: Cursor<Vec<u8>>,
        wakers: Vec<futures::task::Waker>,
    }

    /// A in memory connection for use with tests.
    #[derive(Clone, Default)]
    pub struct TestConnection {
        inner: Arc<Mutex<TestConnectionInner>>,
        direction: bool,
    }

    impl TestConnection {
        pub fn double_ended() -> (TestConnection, TestConnection) {
            let inner: Arc<Mutex<TestConnectionInner>> = Arc::default();

            let a = TestConnection {
                inner: inner.clone(),
                direction: false,
            };

            let b = TestConnection {
                inner,
                direction: true,
            };

            (a, b)
        }
    }

    impl AsyncRead for TestConnection {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let mut conn = self.inner.lock().expect("mutex");

            let buffer = if self.direction {
                &mut conn.inbound_buffer
            } else {
                &mut conn.outbound_buffer
            };

            let mut slice = [0; 1024];

            let bytes_read = std::io::Read::read(buffer, &mut slice)?;
            if bytes_read > 0 {
                buf.put_slice(&slice[..bytes_read]);
                Poll::Ready(Ok(()))
            } else {
                conn.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for TestConnection {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut task::Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            let mut conn = self.inner.lock().expect("mutex");

            if self.direction {
                conn.outbound_buffer.get_mut().extend_from_slice(buf);
            } else {
                conn.inbound_buffer.get_mut().extend_from_slice(buf);
            }

            for waker in conn.wakers.drain(..) {
                waker.wake()
            }

            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let mut conn = self.inner.lock().expect("mutex");

            if self.direction {
                Pin::new(&mut conn.outbound_buffer).poll_flush(cx)
            } else {
                Pin::new(&mut conn.inbound_buffer).poll_flush(cx)
            }
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut task::Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let mut conn = self.inner.lock().expect("mutex");

            if self.direction {
                Pin::new(&mut conn.outbound_buffer).poll_shutdown(cx)
            } else {
                Pin::new(&mut conn.inbound_buffer).poll_shutdown(cx)
            }
        }
    }

    impl Connection for TestConnection {
        fn connected(&self) -> Connected {
            Connected::new()
        }
    }

    #[tokio::test]
    async fn test_memory_connection() {
        // TODO: Flesh out tests.
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(TestConnector);

        let response = client
            .get("http://localhost".parse().unwrap())
            .await
            .unwrap();

        assert!(response.status().is_success());

        let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&bytes[..], b"Hello World");
    }
}
