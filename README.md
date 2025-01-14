# Matrix Hyper Federation Client

A hyper client for handling internal Synapse routing of outbound federation traffic.

 - `matrix-federation://`: Used in Synapse >= [1.87.0rc1][synapse-1.87.0rc1-changelog]
   (2023-06-27)
 - `matrix://`: Used in Synapse < [1.87.0rc1][synapse-1.87.0rc1-changelog] (2023-06-27)

[synapse-1.87.0rc1-changelog]: https://github.com/element-hq/synapse/blob/develop/docs/changelogs/CHANGES-2023.md#synapse-1870rc1-2023-06-27

## Example

```rust,no_run
use ed25519_dalek::SigningKey;
use matrix_hyper_federation_client::SigningFederationClient;

async fn run(secret_key: SigningKey) -> Result<(), anyhow::Error> {
    let client = SigningFederationClient::new("local_server", "ed25519:sg5Sa", secret_key)?;

    let resp = client.get("matrix-federation://matrix.org/_matrix/federation/v1/version".parse()?).await?;
    // let resp = client.get("matrix://matrix.org/_matrix/federation/v1/version".parse()?).await?;

    assert_eq!(resp.status(), 200);

    Ok(())
}
```
