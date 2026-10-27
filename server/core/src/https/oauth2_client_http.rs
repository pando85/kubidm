//! Kubidm: outbound HTTP for OAuth2 client providers (`OAuth2Client` and
//! `OAuth2Federation`), used by the login views for the access token exchange and the
//! RFC 7662 token introspection.
//!
//! One client is built at startup and shared through [super::ServerState]. It never
//! follows redirects (the requests carry the client secret and the access token), has a
//! connect and a total timeout, and response bodies are capped. The endpoints are
//! required to use https (except on loopback) when the provider is loaded.

use kubidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse,
};
use kubidmd_lib::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

/// Time allowed to establish the connection to the provider.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for the whole request, including reading the response body.
pub(crate) const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest accepted response body. Token and introspection responses are small.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Build the shared OAuth2 client provider HTTP client.
pub(crate) fn build_client() -> Result<reqwest::Client, OperationError> {
    build_client_with_timeouts(CONNECT_TIMEOUT, TOTAL_TIMEOUT)
}

fn build_client_with_timeouts(
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<reqwest::Client, OperationError> {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| {
            error!(?err, "Invalid oauth2 http client builder parameters");
            OperationError::InvalidState
        })
}

pub(crate) async fn submit_access_token_request(
    client: &reqwest::Client,
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
    client: &reqwest::Client,
    introspection_url: Url,
    client_id: String,
    client_secret: String,
    request: AccessTokenIntrospectRequest,
) -> Result<AccessTokenIntrospectResponse, OperationError> {
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
    client: &reqwest::Client,
    kind: &str,
    url: Url,
    client_id: String,
    client_secret: String,
    request: &Req,
) -> Result<Resp, OperationError> {
    let mut res = client
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
    /// and returns the request it saw. With `stall`, it does not answer until the client
    /// hangs up, like an endpoint that never responds.
    fn serve_once(response: Vec<u8>, stall: bool) -> (Url, std::thread::JoinHandle<String>) {
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
            if stall {
                // Blocks until the client gives up and closes the connection (bounded,
                // so a broken client can not hang the test forever).
                let _ = sock.set_read_timeout(Some(Duration::from_secs(30)));
                while sock.read(&mut chunk).is_ok_and(|n| n > 0) {}
            }
            // The client may hang up early (body too large, timeout).
            let _ = sock.write_all(&response);
            String::from_utf8_lossy(&buf).to_string()
        });
        let url = Url::parse(&format!("http://{addr}/token")).expect("invalid url");
        (url, handle)
    }

    /// `scope` and `jti` are required by `AccessTokenIntrospectResponse`.
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

    fn introspect_request() -> AccessTokenIntrospectRequest {
        AccessTokenIntrospectRequest::from("access_token".to_string())
    }

    async fn introspect(
        client: &reqwest::Client,
        url: Url,
    ) -> Result<AccessTokenIntrospectResponse, OperationError> {
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
        let (url, handle) = serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), false);

        let response = introspect(&client, url).await.expect("request failed");
        assert!(response.active);
        assert_eq!(response.sub.as_deref(), Some("subject"));

        let head = join(handle).await;
        assert!(head.starts_with("POST /token "));
        assert!(head.to_lowercase().contains("authorization: basic "));
    }

    #[tokio::test]
    async fn test_oauth2_client_http_redirect_not_followed() {
        let client = build_client().expect("failed to build client");
        // The redirect target would answer successfully if it were followed.
        let (target, target_handle) =
            serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), false);
        let (url, handle) = serve_once(
            http_response(
                "307 Temporary Redirect",
                &format!("Location: {target}\r\n"),
                "",
            ),
            false,
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
        // A valid introspection response, padded through `sub` to `len` bytes.
        let padded_body = |len: usize| {
            let empty = VALID_INTROSPECT_BODY.replace("subject", "");
            VALID_INTROSPECT_BODY.replace("subject", &"a".repeat(len - empty.len()))
        };

        // Exactly at the limit is accepted.
        let body = padded_body(MAX_RESPONSE_BYTES);
        let (url, handle) = serve_once(http_response("200 OK", "", &body), false);
        introspect(&client, url)
            .await
            .expect("a body at the limit must be accepted");
        join(handle).await;

        let body = padded_body(MAX_RESPONSE_BYTES + 1);

        // Announced with a content length.
        let (url, handle) = serve_once(http_response("200 OK", "", &body), false);
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
        let (url, handle) = serve_once(response, false);
        assert_eq!(
            introspect(&client, url).await.map(|_| ()),
            Err(OperationError::InvalidState)
        );
        join(handle).await;
    }

    #[tokio::test]
    async fn test_oauth2_client_http_slow_endpoint_times_out() {
        // Short timeouts so the test is fast. The production values are checked below.
        let client = build_client_with_timeouts(CONNECT_TIMEOUT, Duration::from_millis(300))
            .expect("failed to build client");
        let (url, handle) = serve_once(http_response("200 OK", "", VALID_INTROSPECT_BODY), true);

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
}
