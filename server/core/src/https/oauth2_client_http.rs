//! Kubidm: outbound HTTP for OAuth2 client providers (`OAuth2Client` and
//! `OAuth2Federation`), used by the login views for the access token exchange, the
//! RFC 7662 token introspection and the JWKS that verifies an OpenID Connect id_token.
//!
//! The clients are built at startup and shared through [super::ServerState]. They never
//! follow redirects (the requests carry the client secret and the access token), have a
//! connect and a total timeout, and response bodies are capped (after decompression).
//! The endpoints are required to use https (except on loopback) when the provider is
//! loaded.
//!
//! Requests to a non loopback endpoint honour the system proxy settings (`HTTP_PROXY`,
//! `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`), so a deployment can reach its IdP through a
//! proxy. Requests to a loopback endpoint, which may be plain http, never go through a
//! proxy, and `localhost` is resolved to loopback without DNS.
//!
//! The introspection response is parsed leniently, as an
//! [OAuth2ClientIntrospectResponse], so that common providers interoperate.
//!
//! The JWKS of each provider (and jwks uri) is cached for [JWKS_CACHE_TTL]. A refresh,
//! requested when an id_token names a key the cached JWKS does not have, bypasses the
//! cache. The JWKS is never fetched more often than every [JWKS_MIN_REFRESH_INTERVAL]
//! (counting failed attempts), and concurrent logins through one provider share a single
//! fetch. When the cache has expired and the IdP is unavailable (a transport error, a
//! timeout or a 5xx response), a JWKS up to [JWKS_STALE_IF_ERROR] old is used instead.
//! Any other answer of the IdP is authoritative: a JWKS without usable keys, a 4xx, a
//! redirect or an invalid body replaces the cached JWKS, so a key the IdP stopped
//! publishing is never used again.

use compact_jwt::Jwk;
use kubidm_proto::{
    oauth2::{AccessTokenIntrospectRequest, AccessTokenRequest, AccessTokenResponse},
    oauth2_federation::OAuth2ClientIntrospectResponse,
};
use kubidmd_lib::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

/// Time allowed to establish the connection to the provider.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for the whole request, including reading the response body.
pub(crate) const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest accepted response body. Token and introspection responses, and JWKS, are
/// small.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// How long a provider's JWKS is used before it is fetched again.
pub(crate) const JWKS_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
/// The JWKS of a provider is not fetched again (the cached JWKS is used) within this
/// time of the last attempt, successful or not, so that tokens with unknown keys or a
/// failing IdP can not make the server hammer the IdP.
pub(crate) const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// When the cache has expired and the IdP is unavailable, the last JWKS is used if it is
/// younger than this, so that a short IdP outage does not stop every login. The same
/// default as the "last known good" configuration of Microsoft.IdentityModel.
pub(crate) const JWKS_STALE_IF_ERROR: Duration = Duration::from_secs(60 * 60);

/// The shared OAuth2 client provider HTTP clients: one for loopback endpoints, which
/// never uses a proxy, and one for every other endpoint, which uses the system proxy
/// settings. [Self::for_url] picks the client for a request.
#[derive(Clone)]
pub(crate) struct OAuth2ClientHttp {
    /// Non loopback endpoints, through the system (or, in tests, a given) proxy.
    remote: reqwest::Client,
    /// Loopback endpoints, never through a proxy.
    loopback: reqwest::Client,
    /// The JWKS of each provider, by provider uuid and jwks uri, so that sessions
    /// started before and after a change of the jwks uri do not share (or wipe) an
    /// entry. The std mutex is only held to look up an entry, never across an await.
    jwks_cache: Arc<Mutex<BTreeMap<(Uuid, Url), SharedJwksCacheEntry>>>,
}

type SharedJwksCacheEntry = Arc<tokio::sync::Mutex<JwksCacheEntry>>;

/// The JWKS of one provider. Its async mutex is held while the JWKS is fetched, so that
/// concurrent logins wait for that fetch and then use its result.
#[derive(Default)]
struct JwksCacheEntry {
    /// The JWKS the IdP last published, and when it was fetched. It may have no usable
    /// key, then every login is denied until the IdP publishes one.
    keys: Option<(Vec<Jwk>, Instant)>,
    /// The last fetch attempt, and its outcome.
    last_attempt: Option<(Instant, JwksFetchOutcome)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwksFetchOutcome {
    Fetched,
    Unavailable,
    Rejected,
}

/// Why a JWKS was not fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwksFetchError {
    /// The IdP could not be reached or failed: a transport error, a timeout, a 5xx
    /// response, or a body cut short. The last JWKS may bridge this.
    Unavailable,
    /// The IdP answered, but not with a JWKS: a 4xx response, a redirect, or a body that
    /// is too large or not a JWKS. The last JWKS must not be used any more.
    Rejected,
}

impl JwksCacheEntry {
    /// The last JWKS, if it is younger than `max_age`.
    fn keys_younger_than(&self, max_age: Duration, now: Instant) -> Option<Vec<Jwk>> {
        self.keys
            .as_ref()
            .filter(|(_, fetched_at)| now.saturating_duration_since(*fetched_at) < max_age)
            .map(|(keys, _)| keys.clone())
    }

    /// The JWKS to use while the IdP is unavailable: the last one, if it is not older
    /// than [JWKS_STALE_IF_ERROR].
    fn stale_keys(&self, jwks_uri: &Url, now: Instant) -> Result<Vec<Jwk>, OperationError> {
        let keys = self
            .keys_younger_than(JWKS_STALE_IF_ERROR, now)
            .ok_or(OperationError::InvalidState)?;
        warn!(
            url = ?jwks_uri,
            "the jwks is unavailable, using the last jwks fetched (stale-if-error)"
        );
        usable_keys(keys, jwks_uri)
    }

    /// Record the outcome of the fetch started at `now`, and return the keys to use.
    fn record_fetch(
        &mut self,
        result: Result<Vec<Jwk>, JwksFetchError>,
        jwks_uri: &Url,
        refresh: bool,
        now: Instant,
    ) -> Result<Vec<Jwk>, OperationError> {
        match result {
            Ok(keys) => {
                self.last_attempt = Some((now, JwksFetchOutcome::Fetched));
                self.keys = Some((keys.clone(), now));
                usable_keys(keys, jwks_uri)
            }
            Err(JwksFetchError::Unavailable) => {
                self.last_attempt = Some((now, JwksFetchOutcome::Unavailable));
                if refresh {
                    // A refresh is only needed for a key the last JWKS does not have,
                    // so the last JWKS would not help.
                    Err(OperationError::InvalidState)
                } else {
                    self.stale_keys(jwks_uri, now)
                }
            }
            Err(JwksFetchError::Rejected) => {
                self.last_attempt = Some((now, JwksFetchOutcome::Rejected));
                // The IdP no longer publishes the last JWKS.
                self.keys = None;
                Err(OperationError::InvalidState)
            }
        }
    }
}

/// `keys`, unless there are none. Logins are denied while the IdP publishes no usable
/// key.
fn usable_keys(keys: Vec<Jwk>, jwks_uri: &Url) -> Result<Vec<Jwk>, OperationError> {
    if keys.is_empty() {
        error!(url = ?jwks_uri, "jwks has no usable key");
        Err(OperationError::InvalidState)
    } else {
        Ok(keys)
    }
}

impl OAuth2ClientHttp {
    fn for_url(&self, url: &Url) -> &reqwest::Client {
        if is_loopback_host(url) {
            &self.loopback
        } else {
            &self.remote
        }
    }

    /// The usable keys of the JWKS of the provider `provider_id`, from the cache or
    /// fetched from `jwks_uri`. `refresh` bypasses the cache. The JWKS is not fetched
    /// within [JWKS_MIN_REFRESH_INTERVAL] of the last attempt; the cached JWKS is used
    /// instead. `now` is a monotonic time.
    pub(crate) async fn provider_jwks(
        &self,
        provider_id: Uuid,
        jwks_uri: Url,
        refresh: bool,
        now: Instant,
    ) -> Result<Vec<Jwk>, OperationError> {
        let entry = self
            .jwks_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((provider_id, jwks_uri.clone()))
            .or_default()
            .clone();

        // Held across the fetch: a concurrent login for this provider waits here, and
        // then finds the JWKS this one fetched.
        let mut entry = entry.lock_owned().await;

        if !refresh {
            if let Some(keys) = entry.keys_younger_than(JWKS_CACHE_TTL, now) {
                return usable_keys(keys, &jwks_uri);
            }
        }

        if let Some((_, outcome)) = entry
            .last_attempt
            .filter(|(at, _)| now.saturating_duration_since(*at) < JWKS_MIN_REFRESH_INTERVAL)
        {
            debug!(url = ?jwks_uri, ?refresh, ?outcome, "jwks fetched recently, not fetching it again");
            return match outcome {
                // The cache expired (or the key is not in it) and the IdP is down.
                JwksFetchOutcome::Unavailable if !refresh => entry.stale_keys(&jwks_uri, now),
                // A refresh right after a fetch: the key is not in the JWKS.
                JwksFetchOutcome::Fetched => entry
                    .keys_younger_than(JWKS_STALE_IF_ERROR, now)
                    .ok_or(OperationError::InvalidState)
                    .and_then(|keys| usable_keys(keys, &jwks_uri)),
                JwksFetchOutcome::Unavailable | JwksFetchOutcome::Rejected => {
                    Err(OperationError::InvalidState)
                }
            };
        }

        // The fetch runs in its own task, which owns the lock of this entry: if this
        // login is dropped (the browser went away), the fetch still completes and
        // records its real outcome, and the logins waiting on the lock use it. Aborted
        // logins can therefore neither cancel a fetch nor start more than one fetch per
        // interval.
        let client = self.clone();
        let fetch = tokio::spawn(async move {
            let result = fetch_jwks(&client, jwks_uri.clone()).await;
            entry.record_fetch(result, &jwks_uri, refresh, now)
        });

        fetch.await.map_err(|err| {
            error!(?err, "jwks fetch task failed");
            OperationError::InvalidState
        })?
    }
}

/// Is the host of `url` loopback (`localhost`, `127.0.0.0/8` or `::1`). The same rule as
/// the https check at provider load in `kubidmd_lib::idm::oauth2_client`.
fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Build the shared OAuth2 client provider HTTP clients.
pub(crate) fn build_client() -> Result<OAuth2ClientHttp, OperationError> {
    build_client_with(CONNECT_TIMEOUT, TOTAL_TIMEOUT, None)
}

/// `remote_proxy`: the proxy for non loopback endpoints. `None` uses the system proxy
/// settings, as in production.
fn build_client_with(
    connect_timeout: Duration,
    total_timeout: Duration,
    remote_proxy: Option<reqwest::Proxy>,
) -> Result<OAuth2ClientHttp, OperationError> {
    let builder = || {
        reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(total_timeout)
            .redirect(reqwest::redirect::Policy::none())
    };

    let remote = match remote_proxy {
        Some(proxy) => builder().proxy(proxy),
        None => builder(),
    };

    let loopback = builder()
        // Loopback requests may be plain http: they must not leave the host.
        .no_proxy()
        // http is accepted for `localhost` because it is loopback. Never ask DNS for it,
        // so that a resolver that answers otherwise can not redirect the secret.
        .resolve_to_addrs(
            "localhost",
            &[
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
            ],
        );

    let build = |builder: reqwest::ClientBuilder| {
        builder.build().map_err(|err| {
            error!(?err, "Invalid oauth2 http client builder parameters");
            OperationError::InvalidState
        })
    };

    Ok(OAuth2ClientHttp {
        remote: build(remote)?,
        loopback: build(loopback)?,
        jwks_cache: Arc::new(Mutex::new(BTreeMap::new())),
    })
}

pub(crate) async fn submit_access_token_request(
    client: &OAuth2ClientHttp,
    token_url: Url,
    client_id: String,
    client_secret: String,
    request: AccessTokenRequest,
) -> Result<AccessTokenResponse, OperationError> {
    post_form(
        client,
        "access token",
        token_url,
        client_id,
        client_secret,
        &request,
    )
    .await
}

pub(crate) async fn submit_access_token_introspect_request(
    client: &OAuth2ClientHttp,
    introspection_url: Url,
    client_id: String,
    client_secret: String,
    request: AccessTokenIntrospectRequest,
) -> Result<OAuth2ClientIntrospectResponse, OperationError> {
    post_form(
        client,
        "access token introspect",
        introspection_url,
        client_id,
        client_secret,
        &request,
    )
    .await
}

/// A JWKS as published by an IdP. The keys are parsed one by one, see [fetch_jwks].
#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<serde_json::Value>,
}

/// Fetch the JWKS at `jwks_uri`, and return the keys that `compact_jwt` can use. Real
/// JWKS often also hold keys of other kinds (an `OKP` or `P-384` key, an `RSA-OAEP`
/// encryption key) which are skipped, rather than failing the whole set. The result may
/// be empty: the IdP publishes no key Kubidm can use.
pub(crate) async fn fetch_jwks(
    client: &OAuth2ClientHttp,
    jwks_uri: Url,
) -> Result<Vec<Jwk>, JwksFetchError> {
    let kind = "jwks";
    let res = client
        .for_url(&jwks_uri)
        .get(jwks_uri.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| {
            error!(?err, url = ?jwks_uri, "Unable to submit {kind} request");
            JwksFetchError::Unavailable
        })?;

    let status = res.status();
    if status != reqwest::StatusCode::OK {
        error!(?status, url = ?jwks_uri, "{kind} request failed");
        // Throttling (429) and request timeouts (408) say nothing about the key set.
        return Err(
            if status.is_server_error()
                || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || status == reqwest::StatusCode::REQUEST_TIMEOUT
            {
                JwksFetchError::Unavailable
            } else {
                JwksFetchError::Rejected
            },
        );
    }

    let body = read_body(res, kind, &jwks_uri)
        .await
        .map_err(|err| match err {
            ReadBodyError::Transport => JwksFetchError::Unavailable,
            ReadBodyError::TooLarge => JwksFetchError::Rejected,
        })?;

    let document: JwksDocument = serde_json::from_slice(&body).map_err(|err| {
        error!(?err, url = ?jwks_uri, "response was not a valid JSON {kind} response");
        JwksFetchError::Rejected
    })?;

    Ok(document
        .keys
        .into_iter()
        .filter_map(|key| match serde_json::from_value::<Jwk>(key) {
            Ok(key) => Some(key),
            Err(err) => {
                debug!(?err, url = ?jwks_uri, "skipping unsupported jwks key");
                None
            }
        })
        .collect())
}

enum ReadBodyError {
    /// The body could not be read: the connection failed or timed out.
    Transport,
    /// The body is larger than [MAX_RESPONSE_BYTES].
    TooLarge,
}

/// Read a response body of at most [MAX_RESPONSE_BYTES] (after decompression).
async fn read_body(
    mut res: reqwest::Response,
    kind: &str,
    url: &Url,
) -> Result<Vec<u8>, ReadBodyError> {
    if res
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        error!(?url, "{kind} response exceeds {MAX_RESPONSE_BYTES} bytes");
        return Err(ReadBodyError::TooLarge);
    }

    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|err| {
        error!(?err, ?url, "Unable to read {kind} response");
        ReadBodyError::Transport
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            error!(?url, "{kind} response exceeds {MAX_RESPONSE_BYTES} bytes");
            return Err(ReadBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// POST `request` as a form with HTTP basic client authentication, and parse a `200 OK`
/// JSON response. Anything else, including a redirect, is an error.
async fn post_form<Req: Serialize, Resp: DeserializeOwned>(
    client: &OAuth2ClientHttp,
    kind: &str,
    url: Url,
    client_id: String,
    client_secret: String,
    request: &Req,
) -> Result<Resp, OperationError> {
    let res = client
        .for_url(&url)
        .post(url.as_str())
        .basic_auth(&client_id, Some(client_secret))
        .form(request)
        .send()
        .await
        .map_err(|err| {
            error!(?err, ?url, ?client_id, "Unable to submit {kind} request");
            OperationError::InvalidState
        })?;

    read_json_response(res, kind, &url).await
}

/// Parse a `200 OK` JSON response of at most [MAX_RESPONSE_BYTES]. Anything else,
/// including a redirect, is an error.
async fn read_json_response<Resp: DeserializeOwned>(
    res: reqwest::Response,
    kind: &str,
    url: &Url,
) -> Result<Resp, OperationError> {
    if res.status() != reqwest::StatusCode::OK {
        error!(status = ?res.status(), ?url, "{kind} request failed");
        return Err(OperationError::InvalidState);
    }

    let body = read_body(res, kind, url)
        .await
        .map_err(|_| OperationError::InvalidState)?;

    serde_json::from_slice(&body).map_err(|err| {
        error!(?err, "response was not a valid JSON {kind} response");
        OperationError::InvalidState
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A tiny HTTP server on a std thread that answers one connection with `response`,
    /// and returns the request it saw. With `stall_after: Some(n)`, it sends only the
    /// first `n` bytes of the response and then stalls until the client hangs up, like
    /// an endpoint that never responds (`n == 0`) or stops in the middle of the body.
    fn serve_once(
        response: Vec<u8>,
        stall_after: Option<usize>,
    ) -> (Url, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let addr = listener.local_addr().expect("no local address");
        let handle = std::thread::spawn(move || {
            let (sock, _) = listener.accept().expect("failed to accept");
            answer(sock, &response, stall_after)
        });
        let url = Url::parse(&format!("http://{addr}/token")).expect("invalid url");
        (url, handle)
    }

    /// Answer one connection with `response`, and return the request.
    fn answer(
        mut sock: std::net::TcpStream,
        response: &[u8],
        stall_after: Option<usize>,
    ) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        // Read the head and the (form) body, so closing does not reset the connection.
        let request_len = |buf: &[u8]| {
            let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
            let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
            let body_len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            Some(head_end + body_len)
        };
        while request_len(&buf).is_none_or(|len| buf.len() < len) {
            let n = sock.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let mut response = response;
        if let Some(n) = stall_after {
            let (head, rest) = response.split_at(n.min(response.len()));
            let _ = sock.write_all(head);
            let _ = sock.flush();
            response = rest;
            // Blocks until the client gives up and closes the connection (bounded,
            // so a broken client can not hang the test forever).
            let _ = sock.set_read_timeout(Some(Duration::from_secs(30)));
            while sock.read(&mut chunk).is_ok_and(|n| n > 0) {}
        }
        // The client may hang up early (body too large, timeout).
        let _ = sock.write_all(response);
        String::from_utf8_lossy(&buf).to_string()
    }

    /// A complete introspection response, as Kubidm's own endpoint returns it.
    const VALID_INTROSPECT_BODY: &str = r#"{"active":true,"scope":"openid","sub":"subject","jti":"00000000-0000-0000-0000-000000000001"}"#;

    /// Join a server thread without blocking the test runtime, which must keep running
    /// so that the client side of the connection can be closed.
    async fn join<T: Send + 'static>(handle: std::thread::JoinHandle<T>) -> T {
        tokio::task::spawn_blocking(move || handle.join().expect("server thread failed"))
            .await
            .expect("join task failed")
    }

    fn http_response(status: &str, extra_headers: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// A valid introspection response, padded through `sub` to `len` bytes.
    fn padded_body(len: usize) -> String {
        let empty = VALID_INTROSPECT_BODY.replace("subject", "");
        VALID_INTROSPECT_BODY.replace("subject", &"a".repeat(len - empty.len()))
    }

    /// A `200 OK` response with a gzip encoded `body`.
    fn gzip_response(body: &str) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(body.as_bytes())
            .expect("failed to compress");
        let compressed = encoder.finish().expect("failed to compress");
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        response.extend_from_slice(&compressed);
        response
    }

    fn introspect_request() -> AccessTokenIntrospectRequest {
        AccessTokenIntrospectRequest::from("access_token".to_string())
    }

    async fn introspect(
        client: &OAuth2ClientHttp,
        url: Url,
    ) -> Result<OAuth2ClientIntrospectResponse, OperationError> {
        submit_access_token_introspect_request(
            client,
            url,
            "client_id".to_string(),
            "client_secret".to_string(),
            introspect_request(),
        )
        .await
    }

    #[tokio::test]
    async fn test_oauth2_client_http_ok() {
        let client = build_client().expect("failed to build client");
        let (url, handle) = serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), None);

        let response = introspect(&client, url).await.expect("request failed");
        assert!(response.active);
        assert_eq!(response.sub.as_deref(), Some("subject"));

        let head = join(handle).await;
        assert!(head.starts_with("POST /token "));
        assert!(head.to_lowercase().contains("authorization: basic "));
    }

    /// `localhost` is pinned to loopback (the test server listens on 127.0.0.1).
    #[tokio::test]
    async fn test_oauth2_client_http_localhost() {
        let client = build_client().expect("failed to build client");
        let (mut url, handle) =
            serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), None);
        url.set_host(Some("localhost")).expect("invalid host");

        let response = introspect(&client, url).await.expect("request failed");
        assert!(response.active);
        join(handle).await;
    }

    #[tokio::test]
    async fn test_oauth2_client_http_redirect_not_followed() {
        let client = build_client().expect("failed to build client");
        // The redirect target would answer successfully if it were followed.
        let (target, target_handle) =
            serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), None);
        let (url, handle) = serve_once(
            http_response(
                "307 Temporary Redirect",
                &format!("Location: {target}\r\n"),
                "",
            ),
            None,
        );

        assert_eq!(
            introspect(&client, url).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        join(handle).await;

        // Nothing was sent to the redirect target. Unblock its accept and check that the
        // only request it saw is this probe, not the credentials.
        let probe = std::net::TcpStream::connect(
            target
                .socket_addrs(|| None)
                .expect("no target address")
                .first()
                .copied()
                .expect("no target address"),
        );
        drop(probe);
        let target_head = join(target_handle).await;
        assert!(target_head.is_empty());
    }

    #[tokio::test]
    async fn test_oauth2_client_http_oversized_body() {
        let client = build_client().expect("failed to build client");

        // Exactly at the limit is accepted.
        let body = padded_body(MAX_RESPONSE_BYTES);
        let (url, handle) = serve_once(http_response("200 OK", "", &body), None);
        introspect(&client, url)
            .await
            .expect("a body at the limit must be accepted");
        join(handle).await;

        let body = padded_body(MAX_RESPONSE_BYTES + 1);

        // Announced with a content length.
        let (url, handle) = serve_once(http_response("200 OK", "", &body), None);
        assert_eq!(
            introspect(&client, url).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        join(handle).await;

        // Without a content length (read until close).
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
        )
        .into_bytes();
        let (url, handle) = serve_once(response, None);
        assert_eq!(
            introspect(&client, url).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        join(handle).await;
    }

    #[tokio::test]
    async fn test_oauth2_client_http_slow_endpoint_times_out() {
        // Short timeouts so the test is fast. The production values are checked below.
        let client = build_client_with(CONNECT_TIMEOUT, Duration::from_millis(300), None)
            .expect("failed to build client");
        let (url, handle) = serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), Some(0));

        let started = std::time::Instant::now();
        assert_eq!(
            introspect(&client, url).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        join(handle).await;

        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(TOTAL_TIMEOUT, Duration::from_secs(10));
        assert_eq!(MAX_RESPONSE_BYTES, 65536);
    }

    /// A configured proxy is used for non loopback endpoints (so a deployment can reach
    /// its IdP through `HTTPS_PROXY`), and never for loopback ones.
    #[tokio::test]
    async fn test_oauth2_client_http_proxy_only_for_remote() {
        // The proxy fails every request, so a loopback request that went through it
        // would fail too.
        let (proxy_url, proxy_handle) = serve_once(http_response("502 Bad Gateway", "", ""), None);
        let proxy =
            reqwest::Proxy::all(proxy_url.origin().ascii_serialization()).expect("invalid proxy");
        let client = build_client_with(CONNECT_TIMEOUT, TOTAL_TIMEOUT, Some(proxy))
            .expect("failed to build client");

        for host in ["127.0.0.1", "localhost"] {
            let (mut url, handle) =
                serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), None);
            url.set_host(Some(host)).expect("invalid host");
            introspect(&client, url)
                .await
                .unwrap_or_else(|err| panic!("{host} must be reached directly: {err:?}"));
            assert!(join(handle).await.starts_with("POST /token "));
        }

        // A non loopback endpoint goes through the proxy (absolute form request).
        let remote = Url::parse("http://idp.example.invalid/token").expect("invalid url");
        assert_eq!(
            introspect(&client, remote).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        let proxy_head = join(proxy_handle).await;
        assert!(
            proxy_head.starts_with("POST http://idp.example.invalid/token "),
            "the proxy must see the remote request, got {proxy_head:?}"
        );
    }

    /// The size cap applies to the decompressed body: a small gzip body that inflates
    /// past the cap is rejected (a "zip bomb").
    #[tokio::test]
    async fn test_oauth2_client_http_oversized_gzip_body() {
        let client = build_client().expect("failed to build client");

        // A gzip body that inflates to exactly the limit is decoded and accepted.
        let response = gzip_response(&padded_body(MAX_RESPONSE_BYTES));
        assert!(response.len() < MAX_RESPONSE_BYTES / 16);
        let (url, handle) = serve_once(response, None);
        let introspected = introspect(&client, url)
            .await
            .expect("a gzip body inflating to the limit must be accepted");
        assert_eq!(
            introspected.sub.map(|sub| sub.len()),
            Some(MAX_RESPONSE_BYTES - VALID_INTROSPECT_BODY.replace("subject", "").len())
        );
        let head = join(handle).await.to_lowercase();
        assert!(head.contains("accept-encoding:") && head.contains("gzip"));

        // One byte more once inflated, and far more, are rejected.
        for len in [MAX_RESPONSE_BYTES + 1, 64 * MAX_RESPONSE_BYTES] {
            let response = gzip_response(&padded_body(len));
            assert!(response.len() < MAX_RESPONSE_BYTES);
            let (url, handle) = serve_once(response, None);
            assert_eq!(
                introspect(&client, url).await.map(|_| ()),
                Err(OperationError::InvalidState),
                "a gzip body inflating to {len} bytes must be rejected"
            );
            join(handle).await;
        }
    }

    /// An endpoint that sends the head and part of the body, then stalls, is cut off by
    /// the total timeout.
    #[tokio::test]
    async fn test_oauth2_client_http_stall_mid_body_times_out() {
        let client = build_client_with(CONNECT_TIMEOUT, Duration::from_millis(300), None)
            .expect("failed to build client");
        let response = http_response("200 OK", "", VALID_INTROSPECT_BODY);
        let head_len = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("no end of head")
            + 4;
        let (url, handle) = serve_once(response, Some(head_len + VALID_INTROSPECT_BODY.len() / 2));

        let started = std::time::Instant::now();
        assert_eq!(
            introspect(&client, url).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        join(handle).await;
    }

    /// Introspection responses of common providers are accepted: Keycloak (an `aud`
    /// array, a non UUID `jti`, extra fields) and a bare RFC 7662 inactive response.
    #[tokio::test]
    async fn test_oauth2_client_http_lenient_introspection() {
        let client = build_client().expect("failed to build client");

        let keycloak = r#"{"exp":1761650000,"iat":1761649700,"jti":"onrtac:1b2c","iss":"https://idp.example.com/realms/main","aud":["kubidm","account"],"sub":"subject","typ":"Bearer","azp":"kubidm","realm_access":{"roles":["offline_access"]},"scope":"openid email","client_id":"kubidm","active":true}"#;
        let (url, handle) = serve_once(http_response("200 OK", "", keycloak), None);
        let response = introspect(&client, url).await.expect("request failed");
        assert!(response.active);
        assert_eq!(response.sub.as_deref(), Some("subject"));
        assert_eq!(response.aud, vec!["kubidm", "account"]);
        assert_eq!(response.jti.as_deref(), Some("onrtac:1b2c"));
        join(handle).await;

        let (url, handle) = serve_once(http_response("200 OK", "", r#"{"active":false}"#), None);
        let response = introspect(&client, url).await.expect("request failed");
        assert!(!response.active);
        join(handle).await;
    }

    // =========================================
    // Kubidm: JWKS for id_token verification.

    /// Serve `responses` to consecutive connections (repeating the last one) on a
    /// detached thread, counting the requests. For tests that check whether a request is
    /// made at all.
    fn serve_counted(responses: Vec<Vec<u8>>) -> (Url, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let addr = listener.local_addr().expect("no local address");
        let count = Arc::new(AtomicUsize::new(0));
        let thread_count = count.clone();
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(sock) = sock else { break };
                let n = thread_count.fetch_add(1, Ordering::SeqCst);
                let served = responses.get(n); // not an axum route: skip_route_check
                let response = served.or(responses.last()).expect("no response");
                answer(sock, response, None);
            }
        });
        let url = Url::parse(&format!("http://{addr}/jwks")).expect("invalid url");
        (url, count)
    }

    /// As [serve_counted], with one response, sent only once `gate` is signalled for
    /// that connection.
    fn serve_gated(
        response: Vec<u8>,
    ) -> (
        Url,
        Arc<std::sync::atomic::AtomicUsize>,
        std::sync::mpsc::Sender<()>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
        let addr = listener.local_addr().expect("no local address");
        let count = Arc::new(AtomicUsize::new(0));
        let thread_count = count.clone();
        let (gate, gate_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(sock) = sock else { break };
                thread_count.fetch_add(1, Ordering::SeqCst);
                if gate_rx.recv().is_err() {
                    break;
                }
                answer(sock, &response, None);
            }
        });
        let url = Url::parse(&format!("http://{addr}/jwks")).expect("invalid url");
        (url, count, gate)
    }

    /// A public key JSON, with `kid`.
    fn es256_jwk(kid: &str) -> serde_json::Value {
        use compact_jwt::{JwsEs256Signer, JwsSigner, JwsSignerToVerifier};
        let mut signer = JwsEs256Signer::generate_es256().expect("failed to generate key");
        signer.set_kid(kid);
        let jwk = signer
            .get_verifier()
            .and_then(|verifier| verifier.public_key_as_jwk())
            .expect("failed to export key");
        serde_json::to_value(jwk).expect("failed to serialise key")
    }

    fn jwks_body(keys: &[serde_json::Value]) -> Vec<u8> {
        http_response(
            "200 OK",
            "",
            &serde_json::json!({ "keys": keys }).to_string(),
        )
    }

    fn kids(keys: &[Jwk]) -> Vec<String> {
        keys.iter()
            .filter_map(|key| match key {
                Jwk::EC { kid, .. } | Jwk::RSA { kid, .. } => kid.clone(),
            })
            .collect()
    }

    #[tokio::test]
    async fn test_oauth2_client_http_jwks_fetch() {
        let client = build_client().expect("failed to build client");

        // Keys compact_jwt can not use are skipped, the rest are kept.
        let keycloak_enc = serde_json::json!({
            "kid": "enc", "kty": "RSA", "alg": "RSA-OAEP", "use": "enc",
            "n": "AQAB", "e": "AQAB"
        });
        let okp = serde_json::json!({
            "kid": "ed", "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let p384 = serde_json::json!({
            "kid": "p384", "kty": "EC", "crv": "P-384", "x": "AQAB", "y": "AQAB"
        });
        let body = jwks_body(&[keycloak_enc, okp, es256_jwk("sig"), p384]);
        let (url, handle) = serve_once(body, None);
        let keys = fetch_jwks(&client, url).await.expect("jwks fetch failed");
        assert_eq!(kids(&keys), vec!["sig"]);
        let head = join(handle).await;
        assert!(head.starts_with("GET /token "), "{head}");
        assert!(!head.to_lowercase().contains("authorization:"));

        // A valid JWKS without usable keys is an (empty) answer, not an error.
        for response in [
            jwks_body(&[]),
            jwks_body(&[serde_json::json!({"kty": "oct", "k": "c2VjcmV0"})]),
        ] {
            let (url, handle) = serve_once(response, None);
            let keys = fetch_jwks(&client, url).await.expect("jwks fetch failed");
            assert!(keys.is_empty());
            join(handle).await;
        }

        // The IdP answered, but not with a JWKS: rejected.
        let too_large = format!(
            r#"{{"keys":[],"pad":"{}"}}"#,
            "a".repeat(MAX_RESPONSE_BYTES)
        );
        for response in [
            http_response("200 OK", "", "{}"),
            http_response("200 OK", "", "not json"),
            http_response("404 Not Found", "", ""),
            http_response("401 Unauthorized", "", ""),
            http_response("302 Found", "Location: http://127.0.0.1:1/jwks\r\n", ""),
            http_response("200 OK", "", &too_large),
        ] {
            let (url, handle) = serve_once(response, None);
            assert_eq!(
                fetch_jwks(&client, url).await.map(|_| ()),
                Err(JwksFetchError::Rejected)
            );
            join(handle).await;
        }

        // The IdP is unavailable: a 5xx, throttling, or no connection.
        for response in [
            http_response("500 Internal Server Error", "", ""),
            http_response("503 Service Unavailable", "", ""),
            http_response("429 Too Many Requests", "", ""),
            http_response("408 Request Timeout", "", ""),
        ] {
            let (url, handle) = serve_once(response, None);
            assert_eq!(
                fetch_jwks(&client, url).await.map(|_| ()),
                Err(JwksFetchError::Unavailable)
            );
            join(handle).await;
        }
        let refused = Url::parse("http://127.0.0.1:1/jwks").expect("invalid url");
        assert_eq!(
            fetch_jwks(&client, refused).await.map(|_| ()),
            Err(JwksFetchError::Unavailable)
        );
    }

    /// A body that stalls is a timeout: unavailable.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_timeout_unavailable() {
        let client = build_client_with(CONNECT_TIMEOUT, Duration::from_millis(300), None)
            .expect("failed to build client");
        let body = jwks_body(&[es256_jwk("key")]);
        for stall_after in [0, body.len() - 10] {
            let (url, handle) = serve_once(body.clone(), Some(stall_after));
            assert_eq!(
                fetch_jwks(&client, url).await.map(|_| ()),
                Err(JwksFetchError::Unavailable)
            );
            join(handle).await;
        }
    }

    /// The JWKS is cached per provider for the TTL. A refresh bypasses the cache, but
    /// at most once per minimum refresh interval.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_cache() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (url, count) = serve_counted(vec![
            jwks_body(&[es256_jwk("first")]),
            jwks_body(&[es256_jwk("second")]),
            jwks_body(&[es256_jwk("third")]),
        ]);
        let provider = Uuid::new_v4();
        let start = Instant::now();
        let jwks = |refresh: bool, after: Duration| {
            client.provider_jwks(provider, url.clone(), refresh, start + after)
        };

        let keys = jwks(false, Duration::ZERO).await.expect("fetch failed");
        assert_eq!(kids(&keys), vec!["first"]);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Cached.
        let keys = jwks(false, JWKS_CACHE_TTL - Duration::from_secs(1))
            .await
            .expect("cache failed");
        assert_eq!(kids(&keys), vec!["first"]);
        // A refresh right after a fetch is rate limited.
        let keys = jwks(true, JWKS_MIN_REFRESH_INTERVAL - Duration::from_secs(1))
            .await
            .expect("cache failed");
        assert_eq!(kids(&keys), vec!["first"]);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // A refresh after the minimum interval fetches again.
        let keys = jwks(true, JWKS_MIN_REFRESH_INTERVAL)
            .await
            .expect("refresh failed");
        assert_eq!(kids(&keys), vec!["second"]);
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // The TTL counts from the last fetch.
        let keys = jwks(false, JWKS_MIN_REFRESH_INTERVAL + JWKS_CACHE_TTL)
            .await
            .expect("fetch failed");
        assert_eq!(kids(&keys), vec!["third"]);
        assert_eq!(count.load(Ordering::SeqCst), 3);

        // Other providers, and a changed jwks uri, have their own entry.
        let (other_url, other_count) = serve_counted(vec![jwks_body(&[es256_jwk("other")])]);
        let keys = client
            .provider_jwks(Uuid::new_v4(), url.clone(), false, start)
            .await
            .expect("fetch failed");
        assert_eq!(kids(&keys), vec!["third"]);
        assert_eq!(count.load(Ordering::SeqCst), 4);
        let keys = client
            .provider_jwks(provider, other_url, false, start + JWKS_CACHE_TTL)
            .await
            .expect("fetch failed");
        assert_eq!(kids(&keys), vec!["other"]);
        assert_eq!(other_count.load(Ordering::SeqCst), 1);
    }

    fn server_error() -> Vec<u8> {
        http_response("500 Internal Server Error", "", "")
    }

    /// A failed fetch without a usable cached JWKS is an error (the login is denied).
    /// The failed attempt counts for the rate limit: the JWKS is not fetched again (by a
    /// normal request or a refresh) until the minimum interval has passed.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_fetch_failure() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (url, count) = serve_counted(vec![server_error(), jwks_body(&[es256_jwk("key")])]);
        let provider = Uuid::new_v4();
        let start = Instant::now();
        let jwks = |refresh: bool, after: Duration| {
            client.provider_jwks(provider, url.clone(), refresh, start + after)
        };

        for (refresh, after) in [
            (false, Duration::ZERO),
            (false, Duration::from_secs(1)),
            (true, Duration::from_secs(1)),
            (false, JWKS_MIN_REFRESH_INTERVAL - Duration::from_secs(1)),
        ] {
            assert_eq!(
                jwks(refresh, after).await.map(|_| ()),
                Err(OperationError::InvalidState)
            );
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "no refetch within the window"
            );
        }

        let keys = jwks(false, JWKS_MIN_REFRESH_INTERVAL)
            .await
            .expect("fetch failed");
        assert_eq!(kids(&keys), vec!["key"]);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    /// Repeated failures are rate limited too: one attempt per minimum interval.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_repeated_failures() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (url, count) = serve_counted(vec![server_error()]);
        let provider = Uuid::new_v4();
        let start = Instant::now();

        for step in 0..60u32 {
            let after = Duration::from_secs(u64::from(step));
            assert!(client
                .provider_jwks(provider, url.clone(), step % 2 == 1, start + after)
                .await
                .is_err());
        }
        // Attempts at 0s and 30s only.
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    /// When the cache expired and the IdP fails, the last JWKS is used for up to
    /// [JWKS_STALE_IF_ERROR]. A failed refresh does not fall back.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_stale_if_error() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (url, count) = serve_counted(vec![jwks_body(&[es256_jwk("key")]), server_error()]);
        let provider = Uuid::new_v4();
        let start = Instant::now();
        let jwks = |refresh: bool, after: Duration| {
            client.provider_jwks(provider, url.clone(), refresh, start + after)
        };

        jwks(false, Duration::ZERO).await.expect("fetch failed");

        // Expired, the fetch fails: the stale JWKS is used.
        let keys = jwks(false, JWKS_CACHE_TTL).await.expect("stale fallback");
        assert_eq!(kids(&keys), vec!["key"]);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        // Within the rate limit window of that failure, too, without a fetch.
        let keys = jwks(false, JWKS_CACHE_TTL + Duration::from_secs(1))
            .await
            .expect("stale fallback");
        assert_eq!(kids(&keys), vec!["key"]);
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // A refresh that fails is an error.
        assert!(jwks(true, JWKS_CACHE_TTL + JWKS_MIN_REFRESH_INTERVAL)
            .await
            .is_err());
        assert_eq!(count.load(Ordering::SeqCst), 3);

        // Just before the bound, the stale JWKS is still used, past it it is not.
        let keys = jwks(false, JWKS_STALE_IF_ERROR - Duration::from_secs(1))
            .await
            .expect("stale fallback");
        assert_eq!(kids(&keys), vec!["key"]);
        assert_eq!(count.load(Ordering::SeqCst), 4);
        assert_eq!(
            jwks(false, JWKS_STALE_IF_ERROR + JWKS_MIN_REFRESH_INTERVAL)
                .await
                .map(|_| ()),
            Err(OperationError::InvalidState)
        );
        assert_eq!(count.load(Ordering::SeqCst), 5);
    }

    /// Concurrent logins through one provider share a single fetch.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_concurrent_single_fetch() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (url, count) = serve_counted(vec![jwks_body(&[es256_jwk("key")])]);
        let provider = Uuid::new_v4();
        let now = Instant::now();

        let results = futures::future::join_all(
            (0..8).map(|_| client.provider_jwks(provider, url.clone(), false, now)),
        )
        .await;
        for keys in results {
            assert_eq!(kids(&keys.expect("fetch failed")), vec!["key"]);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Concurrent refreshes right after share it as well (rate limited).
        let results = futures::future::join_all(
            (0..8).map(|_| client.provider_jwks(provider, url.clone(), true, now)),
        )
        .await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// A parseable 200 is authoritative: a JWKS that is empty, or has no usable key,
    /// replaces the cached one, and so do a 4xx and a redirect. Only an unavailable IdP
    /// (5xx) falls back to the last JWKS.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_authoritative_answers() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let ed25519 = serde_json::json!({
            "kid": "ed", "kty": "OKP", "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let p384 = serde_json::json!({
            "kid": "p384", "kty": "EC", "crv": "P-384", "x": "AQAB", "y": "AQAB"
        });
        for (name, answer, falls_back) in [
            ("200 with empty keys", jwks_body(&[]), false),
            (
                "200 with only unusable keys",
                jwks_body(&[ed25519, p384]),
                false,
            ),
            ("404", http_response("404 Not Found", "", ""), false),
            (
                "redirect",
                http_response("302 Found", "Location: http://127.0.0.1:1/jwks\r\n", ""),
                false,
            ),
            (
                "503",
                http_response("503 Service Unavailable", "", ""),
                true,
            ),
        ] {
            let (url, count) = serve_counted(vec![
                jwks_body(&[es256_jwk("revoked")]),
                answer,
                http_response("503 Service Unavailable", "", ""),
            ]);
            let provider = Uuid::new_v4();
            let start = Instant::now();
            let jwks = |refresh: bool, after: Duration| {
                client.provider_jwks(provider, url.clone(), refresh, start + after)
            };
            jwks(false, Duration::ZERO).await.expect("fetch failed");

            // The cache expired, and the IdP answers.
            let result = jwks(false, JWKS_CACHE_TTL).await;
            assert_eq!(result.is_ok(), falls_back, "{name}");
            if let Ok(keys) = result {
                assert_eq!(kids(&keys), vec!["revoked"], "{name}");
            }
            assert_eq!(count.load(Ordering::SeqCst), 2, "{name}");
            // Within the rate limit window, and refreshes, never bring the key back.
            assert_eq!(
                jwks(false, JWKS_CACHE_TTL + Duration::from_secs(1))
                    .await
                    .is_ok(),
                falls_back,
                "{name}"
            );
            assert!(
                jwks(true, JWKS_CACHE_TTL + Duration::from_secs(1))
                    .await
                    .is_err(),
                "{name}"
            );
            // A later outage (503), once the answer itself expired, does not bring the
            // replaced key back either.
            let result = jwks(false, JWKS_CACHE_TTL * 2).await;
            assert_eq!(result.is_ok(), falls_back, "{name}");
            assert_eq!(count.load(Ordering::SeqCst), 3, "{name}");
        }
    }

    /// The cache is keyed by provider and jwks uri: logins started before and after a
    /// change of the jwks uri keep their own entry and rate limit, instead of wiping
    /// each other's.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_keyed_by_uri() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (old_url, old_count) = serve_counted(vec![jwks_body(&[es256_jwk("old")])]);
        let (new_url, new_count) = serve_counted(vec![jwks_body(&[es256_jwk("new")])]);
        let provider = Uuid::new_v4();
        let start = Instant::now();

        for step in 0..4u64 {
            let now = start + Duration::from_secs(step);
            let keys = client
                .provider_jwks(provider, old_url.clone(), false, now)
                .await
                .expect("old fetch failed");
            assert_eq!(kids(&keys), vec!["old"]);
            let keys = client
                .provider_jwks(provider, new_url.clone(), false, now)
                .await
                .expect("new fetch failed");
            assert_eq!(kids(&keys), vec!["new"]);
        }
        assert_eq!(old_count.load(Ordering::SeqCst), 1);
        assert_eq!(new_count.load(Ordering::SeqCst), 1);

        // Each uri has its own rate limit: a refresh on the new uri right after its
        // fetch is limited, whatever happens on the old one.
        assert!(client
            .provider_jwks(
                provider,
                new_url.clone(),
                true,
                start + Duration::from_secs(5)
            )
            .await
            .is_ok());
        assert_eq!(new_count.load(Ordering::SeqCst), 1);
    }

    /// Logins dropped while the JWKS is fetched (the browser went away) neither cancel
    /// that fetch nor start new ones: the fetch completes, records its outcome, and the
    /// next login uses it.
    #[tokio::test]
    async fn test_oauth2_client_http_jwks_cancelled_logins() {
        use std::sync::atomic::Ordering;
        let client = build_client().expect("failed to build client");
        let (url, count, gate) = serve_gated(jwks_body(&[es256_jwk("key")]));
        let provider = Uuid::new_v4();
        let start = Instant::now();

        for step in 0..5u64 {
            let login = client.provider_jwks(
                provider,
                url.clone(),
                step % 2 == 1,
                start + Duration::from_secs(step),
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), login)
                    .await
                    .is_err(),
                "the fetch is still in flight"
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // The one fetch completes although its login was dropped.
        gate.send(()).expect("server gone");
        let keys = client
            .provider_jwks(provider, url.clone(), false, start + Duration::from_secs(6))
            .await
            .expect("the dropped login's fetch must be used");
        assert_eq!(kids(&keys), vec!["key"]);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
