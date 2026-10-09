use std::sync::Arc;

use agentsniff::config::ScanConfig;
use agentsniff::ebpf::EbpfChannels;
use agentsniff::server::create_router_with_storage;
use agentsniff::storage::SqliteBackend;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use std::collections::HashMap;
use tower::ServiceExt;

fn test_router() -> axum::Router {
    test_router_with_config(ScanConfig::default())
}

fn test_router_with_config(config: ScanConfig) -> axum::Router {
    let storage = Box::new(SqliteBackend::in_memory().unwrap());
    let channels = Arc::new(EbpfChannels::new());
    create_router_with_storage(config, storage, channels)
}

fn bearer_request(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_scan_status_idle() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scan/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_scan_history_empty() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scan/history?limit=10&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_agents_empty() {
    let app = test_router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_dashboard_serves() {
    let app = test_router();
    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_cross_origin_requests_are_not_enabled() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .header("Origin", "https://attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

#[tokio::test]
async fn test_scan_start_requires_json_body() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scan?network=192.0.2.1/32")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_local_mutations_reject_simple_cross_origin_forms() {
    for uri in ["/api/scan/stop", "/api/settings/test", "/api/db/reset"] {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Origin", "https://attacker.example")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from("action=run"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn test_api_token_protects_every_non_health_route_class() {
    let token = "0123456789abcdef0123456789abcdef";
    let mut config = ScanConfig::default();
    config.api_token = token.to_string();

    let public_health = test_router_with_config(config.clone())
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public_health.status(), StatusCode::OK);

    for (method, uri) in [
        ("GET", "/"),
        ("GET", "/api/scan/status"),
        ("GET", "/api/scan/stream"),
        ("GET", "/api/db/backup"),
        ("GET", "/api/settings"),
        ("POST", "/api/scan/stop"),
        ("POST", "/api/settings/test"),
        ("POST", "/api/db/reset"),
    ] {
        let response = test_router_with_config(config.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
        assert!(response.headers().get("www-authenticate").is_some());
    }

    let authorized = test_router_with_config(config.clone())
        .oneshot(bearer_request("GET", "/api/scan/status", token))
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    let basic = base64::engine::general_purpose::STANDARD.encode(format!("agentsniff:{token}"));
    let authorized = test_router_with_config(config)
        .oneshot(
            Request::builder()
                .uri("/")
                .header("Authorization", format!("Basic {basic}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_api_token_rejects_malformed_or_wrong_credentials() {
    let mut config = ScanConfig::default();
    config.api_token = "0123456789abcdef0123456789abcdef".to_string();

    for authorization in [
        "Bearer wrong",
        "bearer 0123456789abcdef0123456789abcdef",
        "Basic not-base64",
    ] {
        let response = test_router_with_config(config.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/scan/status")
                    .header("Authorization", authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[test]
fn test_remote_binding_requires_a_strong_api_token() {
    let mut config = ScanConfig {
        api_host: "0.0.0.0".to_string(),
        ..ScanConfig::default()
    };
    assert!(agentsniff::server::validate_api_security(&config).is_err());

    config.api_token = "too-short".to_string();
    assert!(agentsniff::server::validate_api_security(&config).is_err());

    config.api_token = "0123456789abcdef0123456789abcdef".to_string();
    assert!(agentsniff::server::validate_api_security(&config).is_ok());

    config.api_host = "127.0.0.1".to_string();
    config.api_token.clear();
    assert!(agentsniff::server::validate_api_security(&config).is_ok());
}

#[tokio::test]
async fn test_destination_changes_clear_retained_credentials() {
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer retained-secret".to_string(),
    );
    let config = ScanConfig {
        webhook_url: "https://old.example/hook".to_string(),
        webhook_headers: headers,
        smtp_host: "old-smtp.example".to_string(),
        smtp_user: "retained-user".to_string(),
        smtp_password: "retained-password".to_string(),
        ..ScanConfig::default()
    };

    let response = test_router_with_config(config)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"webhook_url":"https://new.example/hook","smtp_host":"new-smtp.example"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let updated = body["updated"].as_array().unwrap();
    for cleared in [
        "webhook_headers_cleared",
        "smtp_user_cleared",
        "smtp_password_cleared",
    ] {
        assert!(updated.iter().any(|value| value == cleared), "{cleared}");
    }
}

#[tokio::test]
async fn test_destination_change_accepts_replacement_smtp_credentials() {
    let config = ScanConfig {
        smtp_host: "old-smtp.example".to_string(),
        smtp_user: "old-user".to_string(),
        smtp_password: "old-password".to_string(),
        ..ScanConfig::default()
    };
    let app = test_router_with_config(config);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"smtp_host":"new-smtp.example","smtp_user":"new-user","smtp_password":"new-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["smtp_host"], "new-smtp.example");
    assert_eq!(body["smtp_user"], "new-user");
    assert_eq!(body["smtp_password"], "••••••••");
}
