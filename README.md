# Matrix Hyper Federation Client

A hyper client for connecting over Matrix federation.


## Example

```rust,no_run
use sodiumoxide::crypto::sign::gen_keypair;
use matrix_hyper_federation_client::SigningFederationClient;

async fn run() -> Result<(), anyhow::Error> {
    let (_, secret_key) = gen_keypair();

    let client = SigningFederationClient::new("local_server", "ed25519:sg5Sa", secret_key).await?;

    let resp = client.get("matrix://matrix.org/_matrix/federation/v1/version".parse()?).await?;

    assert_eq!(resp.status(), 200);

    Ok(())
}
```
