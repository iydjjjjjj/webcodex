use salvo::http::StatusCode;
use salvo::prelude::*;
use salvo::test::TestClient;

use crate::public_http_security::{
    InvalidAuthLimiter, InvalidAuthRateLimitPolicy, PublicHttpSecurity,
};

#[handler]
async fn ok_handler(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Text::Plain("ok"));
}

fn security_router() -> Router {
    Router::new()
        .hoop(PublicHttpSecurity)
        .push(Router::with_path("openapi.json").get(ok_handler))
        .push(Router::with_path("artifact-download").get(ok_handler))
        .push(Router::with_path("api/actions/runtime_status").post(ok_handler))
        .push(Router::with_path("api/tools/call").post(ok_handler))
        .push(
            Router::with_path("mcp")
                .get(ok_handler)
                .post(ok_handler)
                .options(ok_handler),
        )
        .push(Router::with_path(".well-known/oauth-protected-resource").get(ok_handler))
        .push(Router::with_path(".well-known/oauth-authorization-server").get(ok_handler))
        .push(Router::with_path("oauth/authorize").get(ok_handler))
        .push(Router::with_path("oauth/authorize/login").post(ok_handler))
        .push(Router::with_path("oauth/authorize/consent").post(ok_handler))
        .push(Router::with_path("oauth/token").post(ok_handler))
        .push(Router::with_path("oauth/revoke").post(ok_handler))
        .push(Router::with_path("oauth/authorize/bridge").post(ok_handler))
        .push(Router::with_path("oauth/authorize/project").post(ok_handler))
        .push(Router::with_path("api/oauth/clients/create").post(ok_handler))
        .push(Router::with_path("admin").get(ok_handler))
}

#[tokio::test]
async fn public_surface_allows_only_openapi_and_actions_while_loopback_stays_full() {
    let mut env = crate::test_support::TestEnvGuard::new();
    env.set("WEBPI_PUBLIC_URL", "https://webpi.example");
    env.set("WEBPI_PUBLIC_ACTIONS_ONLY", "true");
    let service = Service::new(security_router());

    let openapi = TestClient::get("http://webpi.example/openapi.json")
        .add_header("host", "webpi.example", true)
        .send(&service)
        .await;
    assert_eq!(openapi.status_code, Some(StatusCode::OK));

    let artifact_download = TestClient::get("http://webpi.example/artifact-download?id=opaque")
        .add_header("host", "webpi.example", true)
        .send(&service)
        .await;
    assert_eq!(artifact_download.status_code, Some(StatusCode::OK));

    let action = TestClient::post("http://webpi.example/api/actions/runtime_status")
        .add_header("host", "webpi.example", true)
        .send(&service)
        .await;
    assert_eq!(action.status_code, Some(StatusCode::OK));

    for url in [
        "http://webpi.example/api/tools/call",
        "http://webpi.example/mcp",
        "http://webpi.example/admin",
    ] {
        let response = if url.ends_with("/admin") {
            TestClient::get(url)
                .add_header("host", "webpi.example", true)
                .send(&service)
                .await
        } else {
            TestClient::post(url)
                .add_header("host", "webpi.example", true)
                .send(&service)
                .await
        };
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{url}");
    }

    let loopback = TestClient::post("http://127.0.0.1/api/tools/call")
        .send(&service)
        .await;
    assert_eq!(loopback.status_code, Some(StatusCode::OK));
}

#[tokio::test]
async fn explicit_public_plugin_mcp_mode_exposes_only_mcp_and_oauth_protocol_routes() {
    let mut env = crate::test_support::TestEnvGuard::new();
    env.set("WEBPI_PUBLIC_URL", "https://webpi.example");
    env.set("WEBPI_PUBLIC_ACTIONS_ONLY", "true");
    env.set("WEBPI_PUBLIC_PLUGIN_MCP_ENABLED", "true");
    let service = Service::new(security_router());

    let preflight = TestClient::options("http://webpi.example/mcp")
        .add_header("host", "webpi.example", true)
        .add_header("origin", "https://chatgpt.com", true)
        .add_header("access-control-request-method", "POST", true)
        .add_header(
            "access-control-request-headers",
            "content-type,mcp-protocol-version,mcp-session-id",
            true,
        )
        .send(&service)
        .await;
    assert_eq!(preflight.status_code, Some(StatusCode::NO_CONTENT));
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok()),
        Some("POST, GET, OPTIONS")
    );
    let allowed_headers = preflight
        .headers()
        .get("access-control-allow-headers")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    for header in ["content-type", "mcp-protocol-version", "mcp-session-id"] {
        assert!(
            allowed_headers.contains(header),
            "missing {header}: {allowed_headers}"
        );
    }
    assert_eq!(
        preflight
            .headers()
            .get("access-control-expose-headers")
            .and_then(|value| value.to_str().ok()),
        Some("Mcp-Session-Id")
    );

    for (method, path) in [
        ("GET", "/mcp"),
        ("POST", "/mcp"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/oauth/authorize"),
        ("POST", "/oauth/authorize/login"),
        ("POST", "/oauth/authorize/consent"),
        ("POST", "/oauth/token"),
        ("POST", "/oauth/revoke"),
    ] {
        let url = format!("http://webpi.example{path}");
        let response = if method == "GET" {
            TestClient::get(url)
                .add_header("host", "webpi.example", true)
                .send(&service)
                .await
        } else {
            TestClient::post(url)
                .add_header("host", "webpi.example", true)
                .send(&service)
                .await
        };
        assert_eq!(
            response.status_code,
            Some(StatusCode::OK),
            "{method} {path}"
        );
    }

    for (method, path) in [
        ("POST", "/api/tools/call"),
        ("GET", "/admin"),
        ("POST", "/oauth/authorize/bridge"),
        ("POST", "/oauth/authorize/project"),
        ("POST", "/api/oauth/clients/create"),
    ] {
        let url = format!("http://webpi.example{path}");
        let response = if method == "GET" {
            TestClient::get(url)
                .add_header("host", "webpi.example", true)
                .send(&service)
                .await
        } else {
            TestClient::post(url)
                .add_header("host", "webpi.example", true)
                .send(&service)
                .await
        };
        assert_eq!(
            response.status_code,
            Some(StatusCode::NOT_FOUND),
            "{method} {path}"
        );
    }
}

#[test]
fn public_plugin_mcp_mode_fails_closed_without_https_oauth_prerequisites() {
    let mut env = crate::test_support::TestEnvGuard::new();
    env.set("WEBPI_PUBLIC_PLUGIN_MCP_ENABLED", "true");
    env.set("WEBPI_PUBLIC_ACTIONS_ONLY", "true");
    env.set("WEBPI_PUBLIC_URL", "https://webpi.example");
    env.remove("WEBPI_OAUTH2_ENABLED");
    env.remove("WEBPI_OAUTH2_ISSUER");
    let config = crate::Config::from_env();
    assert!(crate::public_http_security::validate_public_plugin_mcp_config(&config).is_err());

    env.set("WEBPI_OAUTH2_ENABLED", "true");
    env.set("WEBPI_OAUTH2_ISSUER", "http://webpi.example");
    let config = crate::Config::from_env();
    assert!(crate::public_http_security::validate_public_plugin_mcp_config(&config).is_err());

    env.set("WEBPI_OAUTH2_ISSUER", "https://other.example");
    let config = crate::Config::from_env();
    assert!(crate::public_http_security::validate_public_plugin_mcp_config(&config).is_err());
}

#[test]
fn public_plugin_mcp_mode_accepts_matching_https_oauth_origin() {
    let mut env = crate::test_support::TestEnvGuard::new();
    env.set("WEBPI_PUBLIC_PLUGIN_MCP_ENABLED", "true");
    env.set("WEBPI_PUBLIC_ACTIONS_ONLY", "true");
    env.set("WEBPI_PUBLIC_URL", "https://webpi.example");
    env.set("WEBPI_OAUTH2_ENABLED", "true");
    env.set("WEBPI_OAUTH2_ISSUER", "https://webpi.example/");
    env.set("WEBPI_OAUTH2_REQUIRE_PKCE", "true");
    let config = crate::Config::from_env();
    assert_eq!(
        crate::public_http_security::validate_public_plugin_mcp_config(&config),
        Ok(())
    );
}

#[tokio::test]
async fn cloudflare_connecting_ip_marks_tunnel_request_public_even_if_origin_host_is_loopback() {
    let mut env = crate::test_support::TestEnvGuard::new();
    env.set("WEBPI_PUBLIC_URL", "https://webpi.example");
    env.set("WEBPI_PUBLIC_ACTIONS_ONLY", "true");
    let service = Service::new(security_router());

    let response = TestClient::post("http://127.0.0.1/api/tools/call")
        .add_header("cf-connecting-ip", "203.0.113.9", true)
        .send(&service)
        .await;
    assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
}

#[test]
fn invalid_auth_limiter_is_bounded_and_only_penalizes_after_the_configured_budget() {
    let policy = InvalidAuthRateLimitPolicy {
        max_failures: 3,
        window_secs: 60,
        penalty_secs: 90,
    };
    let mut limiter = InvalidAuthLimiter::default();

    assert_eq!(limiter.record_failure_at("203.0.113.9", 100, policy), None);
    assert_eq!(limiter.record_failure_at("203.0.113.9", 101, policy), None);
    assert_eq!(limiter.record_failure_at("203.0.113.9", 102, policy), None);
    assert_eq!(
        limiter.record_failure_at("203.0.113.9", 103, policy),
        Some(90)
    );
    assert_eq!(
        limiter.record_failure_at("203.0.113.9", 120, policy),
        Some(73)
    );

    // A different client is independent and still receives its full budget.
    assert_eq!(limiter.record_failure_at("198.51.100.7", 120, policy), None);

    // Once the penalty and original window have elapsed the client gets a fresh budget.
    assert_eq!(limiter.record_failure_at("203.0.113.9", 194, policy), None);
}
