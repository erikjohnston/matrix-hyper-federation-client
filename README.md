# Matrix Hyper Federation Client

A hyper client for connecting over Matrix federation.


## Example

```rust,no_run
use ed25519_dalek::Keypair;
use matrix_hyper_federation_client::SigningFederationClient;

async fn run(secret_key: Keypair) -> Result<(), anyhow::Error> {
    let client = SigningFederationClient::new("local_server", "ed25519:sg5Sa", secret_key).await?;

    let resp = client.get("matrix://matrix.org/_matrix/federation/v1/version".parse()?).await?;

    assert_eq!(resp.status(), 200);

    Ok(())
}
```
