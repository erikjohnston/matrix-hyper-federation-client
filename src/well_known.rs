use std::borrow::Borrow;
use std::hash::Hash;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Error};
use compact_str::CompactString;
use futures_util::stream::StreamExt;
use http::header::{HOST, LOCATION};
use http::{Request, Uri};
use hyper::client::connect::Connect;
use hyper::{Body, Client};
use log::{debug, info};
use rand::{thread_rng, Rng};
use ritelinked::LinkedHashMap;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use url::Url;

/// period to cache .well-known results for by default
const WELL_KNOWN_DEFAULT_CACHE_PERIOD: Duration = Duration::from_secs(24 * 3600);

/// jitter factor to add to the .well-known default cache ttls
const WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER: f64 = 0.1;

/// period to cache failure to fetch .well-known for
const WELL_KNOWN_INVALID_CACHE_PERIOD: Duration = Duration::from_secs(1 * 3600);

/// period to cache failure to fetch .well-known if there has recently been a
/// valid well-known for that domain.
const WELL_KNOWN_DOWN_CACHE_PERIOD: Duration = Duration::from_secs(2 * 60);

/// period to remember there was a valid well-known after valid record expires
const WELL_KNOWN_REMEMBER_DOMAIN_HAD_VALID: Duration = Duration::from_secs(2 * 3600);

/// cap for .well-known cache period
const WELL_KNOWN_MAX_CACHE_PERIOD: Duration = Duration::from_secs(48 * 3600);

/// lower bound for .well-known cache period
const WELL_KNOWN_MIN_CACHE_PERIOD: Duration = Duration::from_secs(5 * 60);

/// The maximum size (in bytes) to allow a well-known file to be.
const WELL_KNOWN_MAX_SIZE: usize = 50 * 1024; // 50 KiB

/// Attempt to refetch a cached well-known N% of the TTL before it expires.
/// e.g. if set to 0.2 and we have a cached entry with a TTL of 5mins, then
/// we'll start trying to refetch 1 minute before it expires.
const WELL_KNOWN_GRACE_PERIOD_FACTOR: f64 = 0.2;

/// Number of times we retry fetching a well-known for a domain we know recently
/// had a valid entry.
const WELL_KNOWN_RETRY_ATTEMPTS: u64 = 3;

#[derive(Debug, Clone, Default)]
pub struct WellKnownCache {
    cache: Arc<Mutex<LinkedHashMap<CompactString, (Option<WellKnownServer>, Instant)>>>,
}

impl WellKnownCache {
    pub fn new() -> WellKnownCache {
        Default::default()
    }

    pub fn get<Q>(&self, host: &Q) -> Option<(Option<WellKnownServer>, Instant)>
    where
        CompactString: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let cache = self.cache.lock().unwrap();

        let (res, expiry) = cache.get(host)?;

        if *expiry < Instant::now() {
            return None;
        }

        Some((res.clone(), *expiry))
    }

    pub fn insert(&self, host: CompactString, res: Option<WellKnownServer>, ttl: Duration) {
        let jitter = (ttl.as_secs_f64() * WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER) as u64;
        let mut new_seconds =
            thread_rng().gen_range(ttl.as_secs() - jitter..ttl.as_secs() + jitter);

        new_seconds = new_seconds.clamp(
            WELL_KNOWN_MIN_CACHE_PERIOD.as_secs(),
            WELL_KNOWN_MAX_CACHE_PERIOD.as_secs(),
        );

        let expiry = Instant::now() + Duration::from_secs(new_seconds);

        self.cache.lock().unwrap().insert(host, (res, expiry));
    }

    pub fn clean_expired(&mut self) {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();

        loop {
            let Some((_, (_, expiry))) = cache.front() else {
                break
            };

            if *expiry < now {
                cache.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Check if there is a `.well-known` file present on the given host.
pub async fn get_well_known<C>(
    http_client: &Client<C>,
    cache: &WellKnownCache,
    host: &str,
) -> Option<WellKnownServer>
where
    C: Connect + Clone + Sync + Send + 'static,
{
    match timeout(
        Duration::from_secs(90),
        get_well_known_inner(http_client, cache, host),
    )
    .await
    .context("timeout")
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) | Err(e) => {
            cache.insert(host.into(), None, WELL_KNOWN_INVALID_CACHE_PERIOD);
            debug!("Error getting well-known {e:?}");
            None
        }
    }
}

pub async fn get_well_known_inner<C>(
    http_client: &Client<C>,
    cache: &WellKnownCache,
    host: &str,
) -> Result<Option<WellKnownServer>, Error>
where
    C: Connect + Clone + Sync + Send + 'static,
{
    if let Some((result, _expiry)) = cache.get(host) {
        return Ok(result);
    }

    let mut uri = hyper::Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query("/.well-known/matrix/server")
        .build()?;

    for _ in 0..10 {
        debug!("Querying well-known: {}", uri);

        let resp = http_client.get(uri.clone()).await?;

        debug!("Got well-known response: {}", resp.status().as_u16());

        if resp.status().is_redirection() {
            if let Some(loc) = resp.headers().get(LOCATION) {
                let location = loc.to_str()?;
                debug!("Got location header: {location}");

                let mut url = Url::parse(&uri.to_string())?;
                url = url.join(location)?;
                uri = hyper::Uri::from_str(url.as_str())?;

                debug!("New uri: {uri}");

                continue;
            } else {
                debug!("Got 3xx status with no location header");
                bail!("No location header in redirect");
            };
        }

        if !resp.status().is_success() {
            bail!("Got non 200 OK status");
        }

        let mut body = resp.into_body();

        let mut vec = Vec::new();
        while let Some(next) = body.next().await {
            // TODO: Limit size of body.
            let chunk = next?;

            if vec.len() > WELL_KNOWN_MAX_SIZE || chunk.len() > WELL_KNOWN_MAX_SIZE {
                info!("Well known response for {host} is too large");

                bail!("Well known response for {host} is too large");
            }

            vec.extend(chunk);
        }

        let result: WellKnownServer = serde_json::from_slice(&vec)?;

        cache.insert(
            host.into(),
            Some(result.clone()),
            WELL_KNOWN_DEFAULT_CACHE_PERIOD,
        );

        return Ok(Some(result));
    }

    debug!("Redirection loop exhausted");
    bail!("Redirection loop exhausted");
}

/// Check if the request is pointing at a delegated server, and if so replace
/// with delegated info.
pub async fn handle_delegated_server<C>(
    http_client: &Client<C>,
    cache: &WellKnownCache,
    mut req: Request<Body>,
) -> Result<Request<Body>, Error>
where
    C: Connect + Clone + Sync + Send + 'static,
{
    debug!("URI: {:?}", req.uri());
    if req.uri().scheme_str() != Some("matrix-federation") {
        debug!("Got scheme: {:?}", req.uri().scheme_str());
        return Ok(req);
    }

    let host = req.uri().host().context("missing host")?;
    let port = req.uri().port();

    if host.parse::<IpAddr>().is_ok() || port.is_some() {
        debug!("Literals");
    } else {
        let well_known = get_well_known(
            http_client,
            cache,
            req.uri().host().context("missing host")?,
        )
        .await;

        let host = if let Some(w) = &well_known {
            debug!("Found well-known: {}", &w.server);

            let a = http::uri::Authority::from_str(&w.server)?;
            let mut builder = Uri::builder().scheme("matrix-federation").authority(a);
            if let Some(p) = req.uri().path_and_query() {
                builder = builder.path_and_query(p.clone());
            }

            *req.uri_mut() = builder.build()?;

            &w.server
        } else {
            debug!("No well-known");
            req.uri().host().context("missing host")?
        };

        let host_val = host.parse()?;
        req.headers_mut().insert(HOST, host_val);
    }

    Ok(req)
}

/// A parsed Matrix `.well-known` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownServer {
    #[serde(rename = "m.server")]
    pub server: CompactString,
}
