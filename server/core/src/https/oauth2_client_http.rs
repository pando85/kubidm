//! Kubidm: outbound HTTP for OAuth2 client providers (`OAuth2Client` and
//! `OAuth2Federation`), used by the login views for the access token exchange and the
//! RFC 7662 token introspection.
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

use kubidm_proto::{
    oauth2::{AccessTokenIntrospectRequest, AccessTokenRequest, AccessTokenResponse},
    oauth2_federation::OAuth2ClientIntrospectResponse,
};
use kubidmd_lib::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

/// Time allowed to establish the connection to the provider.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for the whole request, including reading the response body.
pub(crate) const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest accepted response body. Token and introspection responses are small.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The shared OAuth2 client provider HTTP clients: one for loopback endpoints, which
/// never uses a proxy, and one for every other endpoint, which uses the system proxy
/// settings. [Self::for_url] picks the client for a request.
#[derive(Clone)]
pub(crate) struct OAuth2ClientHttp {
    /// Non loopback endpoints, through the system (or, in tests, a given) proxy.
    remote: reqwest::Client,
    /// Loopback endpoints, never through a proxy.
    loopback: reqwest::Client,
}

impl OAuth2ClientHttp {
    fn for_url(&self, url: &Url) -> &reqwest::Client {
        if is_loopback_host(url) {
            &self.loopback
        } else {
            &self.remote
        }
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
    let mut res = client
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

    if res.status() != reqwest::StatusCode::OK {
        error!(status = ?res.status(), ?url, "{kind} request failed");
        return Err(OperationError::InvalidState);
    }

    if res
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        error!(?url, "{kind} response exceeds {MAX_RESPONSE_BYTES} bytes");
        return Err(OperationError::InvalidState);
    }

    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|err| {
        error!(?err, ?url, "Unable to read {kind} response");
        OperationError::InvalidState
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            error!(?url, "{kind} response exceeds {MAX_RESPONSE_BYTES} bytes");
            return Err(OperationError::InvalidState);
        }
        body.extend_from_slice(&chunk);
    }

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
            let (mut sock, _) = listener.accept().expect("failed to accept");
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
            let mut response = response.as_slice();
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
        });
        let url = Url::parse(&format!("http://{addr}/token")).expect("invalid url");
        (url, handle)
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
}
