//! A crate for sending Matrix federation HTTP requests using [`hyper`].
//!
//! # [`SigningFederationClient`]
//!
//! The [`SigningFederationClient`] correctly routes `matrix://` URIs and
//! automatically signs such requests:
//!
//! ```no_run
//! # use ed25519_dalek::Keypair;
//! # use matrix_hyper_federation_client::SigningFederationClient;
//! #
//! # async fn run(secret_key: Keypair) -> Result<(), anyhow::Error> {
//! #
//! let client = SigningFederationClient::new("local_server", "ed25519:sg5Sa", secret_key).await?;
//!
//! let uri = "matrix://matrix.org/_matrix/federation/v1/version".parse()?;
//! let resp = client.get(uri).await?;
//!
//! assert_eq!(resp.status(), 200);
//!
//! # Ok(())
//! # }
//! ```
//!
//! Note however, that this incurs some overhead due to have to deserialize the
//! request body back into JSON so that it can be signed.
//!
//! # [`FederationClient`]
//!
//! The [`FederationClient`] is just a standard [`hyper::Client`] with a
//! [`MatrixConnector`] that can route `matrix://` URIs, but does *not* sign the
//! requests automatically:
//!
//! ```no_run
//! # use matrix_hyper_federation_client::client::{new_federation_client, sign_and_build_json_request};
//! # use hyper::Request;
//! use matrix_hyper_federation_client::SignedRequestBuilderExt;
//! # use ed25519_dalek::Keypair;
//! #
//! # async fn run(secret_key: &Keypair) -> Result<(), anyhow::Error> {
//! #
//! let client = new_federation_client().await?;
//!
//! let request = Request::builder()
//!     .method("GET")
//!     .uri("matrix://matrix.org/_matrix/federation/v1/version")
//!     .signed("localhost", "ed25519:sg5Sa", &secret_key)?;
//!
//! let resp = client.request(request).await?;
//!
//! assert_eq!(resp.status(), 200);
//!
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod server_resolver;
pub mod well_known;

#[doc(inline)]
pub use client::{FederationClient, SignedRequestBuilderExt, SigningFederationClient};
#[doc(inline)]
pub use server_resolver::MatrixConnector;

/// Uses the [`doc-comment`] crate to run mark the examples in the README as doc
/// tests.
#[cfg(doctest)]
mod readme_tests {
    use doc_comment::doctest;
    doctest!("../README.md");
}
