use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentpin::credential::issue_credential;
use agentpin::crypto;
use agentpin::discovery::build_discovery_document;
use agentpin::jwk::verifying_key_to_jwk;
use agentpin::revocation::build_revocation_document;
use agentpin::types::bundle::TrustBundle;
use agentpin::types::capability::Capability;
use agentpin::types::discovery::{AgentDeclaration, AgentStatus, EntityType};
use agentsniff::config::ScanConfig;
use agentsniff::ebpf::EbpfChannels;
use agentsniff::server::{create_router_with_storage, validate_agentpin_server_config};
use agentsniff::storage::SqliteBackend;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use serde_json::{json, Value};
use tower::ServiceExt;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    credential: String,
    config: ScanConfig,
    temp_dir: std::path::PathBuf,
    pin_path: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn fixture() -> Fixture {
    let domain = "example.com";
    let audience = "verifier.example";
    let key_pair = crypto::generate_key_pair().unwrap();
    let signing_key = crypto::load_signing_key(&key_pair.private_key_pem).unwrap();
    let verifying_key = crypto::load_verifying_key(&key_pair.public_key_pem).unwrap();
    let kid = "example-2026-01";
    let agent = AgentDeclaration {
        agent_id: format!("urn:agentpin:{domain}:scanner"),
        agent_type: None,
        name: "scanner".to_string(),
        description: Some("AgentSniff MCP fixture".to_string()),
        version: Some("1.0.0".to_string()),
        capabilities: vec![Capability::from("read:data")],
        constraints: None,
        maker_attestation: None,
        credential_ttl_max: Some(3600),
        status: AgentStatus::Active,
        directory_listing: Some(false),
    };
    let discovery = build_discovery_document(
        domain,
        EntityType::Maker,
        vec![verifying_key_to_jwk(&verifying_key, kid)],
        vec![agent.clone()],
        1,
        &Utc::now().to_rfc3339(),
    );
    let credential = issue_credential(
        &signing_key,
        kid,
        domain,
        &agent.agent_id,
        Some(audience),
        agent.capabilities,
        None,
        None,
        3600,
    )
    .unwrap();
    let bundle = TrustBundle {
        agentpin_bundle_version: "0.1".to_string(),
        created_at: Utc::now().to_rfc3339(),
        documents: vec![discovery],
        revocations: vec![build_revocation_document(domain)],
    };

    let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_dir = std::env::temp_dir().join(format!(
        "agentsniff-agentpin-mcp-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let bundle_path = temp_dir.join("bundle.json");
    let pin_path = temp_dir.join("pins.json");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let config = ScanConfig {
        agentpin_trust_bundle_path: bundle_path.to_string_lossy().into_owned(),
        agentpin_pin_store_path: pin_path.to_string_lossy().into_owned(),
        agentpin_expected_audience: audience.to_string(),
        ..ScanConfig::default()
    };
    Fixture {
        credential,
        config,
        temp_dir,
        pin_path,
    }
}

fn test_router(config: ScanConfig) -> axum::Router {
    create_router_with_storage(
        config,
        Box::new(SqliteBackend::in_memory().unwrap()),
        Arc::new(EbpfChannels::new()),
    )
}

fn modern_request(method: &str, name: Option<&str>, params: Value) -> Request<Body> {
    let mut request = Request::builder()
        .header("Host", "localhost:9090")
        .method("POST")
        .uri("/mcp")
        .header("Content-Type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", method);
    if let Some(name) = name {
        request = request.header("Mcp-Name", name);
    }
    request
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            }))
            .unwrap(),
        ))
        .unwrap()
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "agentsniff-test", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn modern_mcp_discovers_only_the_operator_configured_verifier() {
    let fixture = fixture();
    validate_agentpin_server_config(&fixture.config).unwrap();
    let app = test_router(fixture.config.clone());

    let discover = app
        .clone()
        .oneshot(modern_request(
            "server/discover",
            None,
            json!({"_meta": modern_meta()}),
        ))
        .await
        .unwrap();
    assert_eq!(discover.status(), StatusCode::OK);
    let discover = response_json(discover).await;
    assert_eq!(discover["result"]["resultType"], "complete");
    assert_eq!(discover["result"]["supportedVersions"][0], "2026-07-28");
    assert!(discover["result"]["capabilities"]["tools"].is_object());

    let list = app
        .oneshot(modern_request(
            "tools/list",
            None,
            json!({"_meta": modern_meta()}),
        ))
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    let tool = &list["result"]["tools"][0];
    assert_eq!(tool["name"], "verify_agentpin_credential");
    assert!(tool["inputSchema"]["properties"]["credential"].is_object());
    assert!(tool["inputSchema"]["properties"]
        .get("trust_bundle")
        .is_none());
    assert!(tool["inputSchema"]["properties"].get("audience").is_none());
    assert_eq!(list["result"]["cacheScope"], "private");
}

#[tokio::test]
async fn mcp_verifies_a_credential_and_persists_tofu_pins() {
    let fixture = fixture();
    let app = test_router(fixture.config.clone());
    let response = app
        .oneshot(modern_request(
            "tools/call",
            Some("verify_agentpin_credential"),
            json!({
                "name": "verify_agentpin_credential",
                "arguments": {"credential": fixture.credential},
                "_meta": modern_meta()
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(body["result"]["structuredContent"]["valid"], true);
    assert_eq!(
        body["result"]["structuredContent"]["identity_assurance"],
        "trusted_verified"
    );
    assert!(fixture.pin_path.is_file());
}

#[tokio::test]
async fn rest_verifier_enforces_the_operator_configured_audience() {
    let mut fixture = fixture();
    fixture.config.agentpin_expected_audience = "wrong.example".to_string();
    let response = test_router(fixture.config.clone())
        .oneshot(
            Request::builder()
                .header("Host", "localhost:9090")
                .method("POST")
                .uri("/api/agentpin/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"credential": fixture.credential})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["valid"], false);
    assert!(!fixture.pin_path.exists());
}

#[tokio::test]
async fn modern_mcp_rejects_missing_routing_headers() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"_meta": modern_meta()}
    });
    let response = test_router(fixture().config.clone())
        .oneshot(
            Request::builder()
                .header("Host", "localhost:9090")
                .method("POST")
                .uri("/mcp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], -32020);
}

#[tokio::test]
async fn legacy_mcp_clients_can_initialize_and_list_tools() {
    let fixture = fixture();
    let app = test_router(fixture.config.clone());
    let initialize = app
        .clone()
        .oneshot(
            Request::builder().header("Host", "localhost:9090")
                .method("POST")
                .uri("/mcp")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initialize.status(), StatusCode::OK);
    let initialize = response_json(initialize).await;
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    let list = app
        .oneshot(
            Request::builder()
                .header("Host", "localhost:9090")
                .method("POST")
                .uri("/mcp")
                .header("Content-Type", "application/json")
                .header("MCP-Protocol-Version", "2025-11-25")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    assert_eq!(
        list["result"]["tools"][0]["name"],
        "verify_agentpin_credential"
    );
}

#[test]
fn server_config_rejects_partial_agentpin_trust_setup() {
    let config = ScanConfig {
        agentpin_expected_audience: "verifier.example".to_string(),
        ..ScanConfig::default()
    };
    assert!(validate_agentpin_server_config(&config).is_err());

    let config = ScanConfig {
        agentpin_trust_bundle_path: "/does/not/exist.json".to_string(),
        ..ScanConfig::default()
    };
    assert!(validate_agentpin_server_config(&config).is_err());
}

#[tokio::test]
async fn live_http_mcp_listener_verifies_a_real_credential() {
    let fixture = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = fixture.config.clone();
    config.api_port = address.port();
    let app = test_router(config);
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "verify_agentpin_credential")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "live-test",
            "method": "tools/call",
            "params": {
                "name": "verify_agentpin_credential",
                "arguments": {"credential": fixture.credential},
                "_meta": modern_meta()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["result"]["structuredContent"]["valid"], true);
    assert!(fixture.pin_path.is_file());

    server.abort();
}
