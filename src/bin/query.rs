use anyhow::{Context, Error};
use http::Request;
use hyper::{body, Body};
use matrix_hyper_federation_client::{
    client::new_federation_client,
    server_resolver::MatrixResolver,
    well_known::{get_well_known, WellKnownCache},
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let host = std::env::args().nth(1).context("Missing arg")?;

    let resolver = MatrixResolver::new().await?;
    let http_client = new_federation_client().await?.client;
    let well_known_cache = WellKnownCache::new();

    let well_known = get_well_known(&http_client, &well_known_cache, &host).await;

    println!("Well known: {well_known:#?}");

    let endpoints = resolver
        .resolve_server_name(
            well_known
                .as_ref()
                .map(|w| w.server.as_str())
                .unwrap_or(&host),
        )
        .await?;

    println!("Endpoints: {endpoints:#?}");

    let fed_client = new_federation_client().await?;

    let req = Request::builder()
        .method("GET")
        .uri(format!("matrix-federation://{host}/_matrix/key/v2/server"))
        .body(Body::empty())?;

    let resp = fed_client.request(req).await?;
    println!("Got {} response", resp.status().as_str());

    let bytes = body::to_bytes(resp.into_body()).await?;
    println!("Response:\n\t{}", String::from_utf8_lossy(&bytes));

    Ok(())
}
