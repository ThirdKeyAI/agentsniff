use std::{net::IpAddr, sync::Arc, time::Duration};

use agentsniff::{
    config::ScanConfig,
    detectors::{dns_monitor::DnsMonitorDetector, mcp_detector::McpDetector, Detector},
    ebpf::EbpfChannels,
    models::{DetectedAgent, ScanResult},
    server::create_router_with_storage,
    storage::{SqliteBackend, StorageBackend},
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;

fn router(config: ScanConfig) -> Router {
    create_router_with_storage(
        config,
        Box::new(SqliteBackend::in_memory().unwrap()),
        Arc::new(EbpfChannels::new()),
    )
}

#[tokio::test]
async fn loopback_authority_and_origin_are_enforced() {
    for host in [
        None,
        Some("attacker.example:9090"),
        Some("localhost.evil:9090"),
        Some("attacker@localhost:9090"),
        Some("127.0.0.1:80"),
    ] {
        let mut request = Request::builder().uri("/api/settings");
        if let Some(host) = host {
            request = request.header("Host", host);
        }
        let response = router(ScanConfig::default())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{host:?}");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["content-security-policy"],
            "frame-ancestors 'none'"
        );
    }
    for host in ["localhost:9090", "127.0.0.1:9090", "[::1]:9090"] {
        let response = router(ScanConfig::default())
            .oneshot(
                Request::builder()
                    .uri("/api/settings")
                    .header("Host", host)
                    .header("Origin", format!("http://{host}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{host}");
    }
    for origin in [
        "null",
        "http://evil.example:9090",
        "http://localhost:9090/evil",
        "http://localhost:9091",
    ] {
        let response = router(ScanConfig::default())
            .oneshot(
                Request::builder()
                    .uri("/api/settings")
                    .header("Host", "localhost:9090")
                    .header("Origin", origin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin}");
    }
    let response = router(ScanConfig::default())
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("Host", "localhost:9090")
                .header("Host", "evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = router(ScanConfig::default())
        .oneshot(
            Request::builder()
                .uri("http://evil.example/api/settings")
                .header("Host", "localhost:9090")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authenticated_reverse_proxy_still_works_and_invalid_router_fails_closed() {
    let token = "0123456789abcdef0123456789abcdef";
    let config = ScanConfig {
        api_host: "0.0.0.0".into(),
        api_token: token.into(),
        ..ScanConfig::default()
    };
    let response = router(config)
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("Host", "scanner.example")
                .header("Origin", "https://scanner.example")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let config = ScanConfig {
        api_host: "0.0.0.0".into(),
        ..ScanConfig::default()
    };
    let response = router(config)
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("Host", "localhost:9090")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

async fn start_fixture(app: Router) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, task)
}

#[tokio::test]
async fn large_mcp_catalogs_and_discovery_are_sampled() {
    let app = Router::new().route("/mcp", post(|Json(req): Json<Value>| async move {
        let large = "x".repeat(200_000);
        let result = match req["method"].as_str().unwrap_or("") {
            "initialize" => json!({"protocolVersion":"2025-11-25", "serverInfo":{"name":large},
                "capabilities":{"tools":{}, "padding":large, "experimental":{"org.agentpin/credential-binding":{"padding":large}}}}),
            "tools/list" => json!({"tools":[{"name":"large", "description":large}]}),
            "resources/list" => json!({"resources":[{"uri":"test://resource", "description":large}]}),
            "prompts/list" => json!({"prompts":[{"name":"prompt", "description":large}]}),
            _ => json!({}),
        };
        Json(json!({"jsonrpc":"2.0", "id":1, "result":result}))
    }));
    let (port, task) = start_fixture(app).await;
    let config = ScanConfig {
        probe_port: Some(port),
        http_timeout: 1.0,
        ..ScanConfig::default()
    };
    let detector = McpDetector::new(&config);
    let signals = detector
        .scan(&["127.0.0.1".parse().unwrap()])
        .await
        .unwrap();
    task.abort();
    assert!(!signals.is_empty());
    let retained = serde_json::to_vec(&signals).unwrap();
    assert!(
        retained.len() < 64 * 1024,
        "retained {} bytes",
        retained.len()
    );
    assert!(String::from_utf8(retained).unwrap().contains("truncated"));
}

#[tokio::test]
async fn dns_flood_stops_with_an_explicit_incomplete_error() {
    for (count, expected) in [(257, "budget exceeded"), (1025, "events dropped")] {
        let channels = Arc::new(EbpfChannels::new());
        let producer = channels.clone();
        let config = ScanConfig {
            dns_monitor_duration: 2,
            ..ScanConfig::default()
        };
        let detector = DnsMonitorDetector::new(&config, Some(channels));
        let task = tokio::spawn(async move {
            let mut event = agentsniff_common::DnsEvent {
                src_addr: u32::from(std::net::Ipv4Addr::LOCALHOST),
                dst_addr: 0,
                query_name: [0; 256],
                query_len: 14,
                timestamp_ns: 0,
            };
            event.query_name[..14].copy_from_slice(b"api.openai.com");
            while producer.dns_tx.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
            for _ in 0..count {
                assert!(producer.dns_tx.send(event).is_ok());
            }
        });
        let error = detector
            .scan(&["127.0.0.1".parse::<IpAddr>().unwrap()])
            .await
            .unwrap_err();
        task.await.unwrap();
        assert!(error.to_string().contains(expected));
    }
}

#[tokio::test]
async fn a2a_retained_evidence_is_bounded_before_task_collection() {
    use agentsniff::detectors::a2a_detector::A2aDetector;
    let app = Router::new().fallback(|| async {
        Json(
            json!({"name":"x".repeat(200_000), "version":"1", "description":"large fixture",
            "capabilities":{}, "skills":[], "defaultInputModes":[], "defaultOutputModes":[],
            "url":"https://fixture.invalid/"}),
        )
    });
    let (port, server) = start_fixture(app).await;
    let config = ScanConfig {
        probe_port: Some(port),
        http_timeout: 2.0,
        ..ScanConfig::default()
    };
    let detector = A2aDetector::new(&config);
    let error = detector
        .scan(&vec!["127.0.0.1".parse().unwrap(); 64])
        .await
        .unwrap_err();
    server.abort();
    assert!(error.to_string().contains("evidence budget exceeded"));
}

#[tokio::test]
async fn passive_dns_honors_configured_duration() {
    let channels = Arc::new(EbpfChannels::new());
    let producer = channels.clone();
    let detector = DnsMonitorDetector::new(
        &ScanConfig {
            dns_monitor_duration: 1,
            ..ScanConfig::default()
        },
        Some(channels),
    );
    let task = tokio::spawn(async move {
        let mut event = agentsniff_common::DnsEvent {
            src_addr: 0x7f000001,
            dst_addr: 0,
            query_name: [0; 256],
            query_len: 14,
            timestamp_ns: 0,
        };
        event.query_name[..14].copy_from_slice(b"api.openai.com");
        while producer.dns_tx.receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
        assert!(producer.dns_tx.send(event).is_ok());
    });
    let started = std::time::Instant::now();
    let signals = tokio::time::timeout(
        Duration::from_secs(3),
        detector.scan(&["127.0.0.1".parse().unwrap()]),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(signals.len(), 1);
    assert!(started.elapsed() >= Duration::from_millis(900));
    task.await.unwrap();
}

#[tokio::test]
async fn passive_tls_flood_and_lag_fail_explicitly() {
    use agentsniff::detectors::tls_fingerprint::TlsFingerprintDetector;
    for (count, expected) in [(257, "budget exceeded"), (513, "events dropped")] {
        let channels = Arc::new(EbpfChannels::new());
        let producer = channels.clone();
        let detector = TlsFingerprintDetector::new(&ScanConfig::default(), Some(channels));
        let task = tokio::spawn(async move {
            let event = agentsniff_common::TlsEvent {
                src_addr: 0x7f000001,
                dst_addr: 0,
                dst_port: 443,
                tls_version: 0x303,
                cipher_suites: [0; 64],
                cipher_count: 0,
                extensions: [0; 64],
                extension_count: 0,
                timestamp_ns: 0,
            };
            while producer.tls_tx.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
            for _ in 0..count {
                assert!(producer.tls_tx.send(event).is_ok());
            }
        });
        let error = detector
            .scan(&["127.0.0.1".parse().unwrap()])
            .await
            .unwrap_err();
        task.await.unwrap();
        assert!(error.to_string().contains(expected));
    }
}

#[tokio::test]
async fn cancellation_interrupts_stalled_detector_and_releases_connection() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (started, receive) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        // MCP probes TCP reachability before opening its HTTP request.
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = [0; 4096];
            let n = stream.read(&mut data).await.unwrap();
            if n == 0 {
                continue;
            }
            started.send(()).unwrap();
            return stream.read(&mut data).await.unwrap_or(0);
        }
    });
    let config = ScanConfig {
        target_network: "127.0.0.1/32".into(),
        probe_port: Some(port),
        http_timeout: 30.0,
        enable_dns_monitor: false,
        enable_port_scanner: false,
        enable_agentpin_prober: false,
        enable_a2a_detector: false,
        enable_endpoint_prober: false,
        enable_tls_fingerprint: false,
        enable_traffic_analyzer: false,
        enable_sse_detector: false,
        ..ScanConfig::default()
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let token = cancel.clone();
    let scan = tokio::spawn(async move {
        agentsniff::scanner::run_scan(&config, None, Some(token), None).await
    });
    tokio::time::timeout(Duration::from_secs(2), receive)
        .await
        .unwrap()
        .unwrap();
    cancel.cancel();
    let result = tokio::time::timeout(Duration::from_secs(1), scan)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(result.cancelled);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn storage_rejects_oversized_updates_and_backups_are_consistent() {
    let directory = tempfile::tempdir().unwrap();
    let storage = SqliteBackend::new(directory.path().join("state.db").to_str().unwrap()).unwrap();
    let mut result = ScanResult::new();
    result.scan_id = "bounded-storage".into();
    storage.save_scan(&result).await.unwrap();
    let mut agent = DetectedAgent::new("host".into(), "127.0.0.1".parse().unwrap());
    agent.metadata = json!({"large": "x".repeat(17 * 1024 * 1024)});
    assert!(storage.save_agent(&result.scan_id, &agent).await.is_err());
    result.agents.push(agent);
    assert!(storage.save_scan(&result).await.is_err());
    assert!(storage
        .get_scan(&result.scan_id)
        .await
        .unwrap()
        .unwrap()
        .agents
        .is_empty());
    let mut backup = storage.backup().await.unwrap();
    let mut destination = tempfile::NamedTempFile::new().unwrap();
    std::io::copy(&mut backup.file, &mut destination).unwrap();
    let conn = rusqlite::Connection::open(destination.path()).unwrap();
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[cfg(unix)]
#[test]
fn sqlite_and_sidecars_are_private_and_existing_modes_are_repaired() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".agentsniff/state.db");
    let backend = SqliteBackend::new(path.to_str().unwrap()).unwrap();
    for name in ["state.db", "state.db-wal", "state.db-shm"] {
        let meta = std::fs::metadata(path.parent().unwrap().join(name)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
    }
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    drop(backend);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let _reopened = SqliteBackend::new(path.to_str().unwrap()).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn slow_webhook_does_not_block_scan_completion_or_next_scan() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let notify = entered.clone();
    let webhook = Router::new().route(
        "/",
        post(move || {
            let notify = notify.clone();
            async move {
                notify.notify_one();
                std::future::pending::<StatusCode>().await
            }
        }),
    );
    let (port, server) = start_fixture(webhook).await;
    let config = ScanConfig {
        alert_enabled: true,
        alert_min_agents: 0,
        alert_changes_only: false,
        webhook_url: format!("http://127.0.0.1:{port}/"),
        ..ScanConfig::default()
    };
    let app = router(config);
    let start = || {
        Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("Host", "localhost:9090")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"network":"127.0.0.1/32","detectors":""}"#))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(start()).await.unwrap().status(),
        StatusCode::OK
    );
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scan/status")
                .header("Host", "localhost:9090")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("completed"));
    assert_eq!(app.oneshot(start()).await.unwrap().status(), StatusCode::OK);
    server.abort();
}

#[tokio::test]
async fn webhook_timeout_and_redirect_policy_have_healthy_control() {
    let (port, server) = start_fixture(
        Router::new()
            .route("/ok", post(|| async { StatusCode::NO_CONTENT }))
            .route(
                "/redirect",
                post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/ok")]) }),
            )
            .route("/slow", post(|| std::future::pending::<StatusCode>())),
    )
    .await;
    let result = ScanResult::new();
    for (path, expected) in [
        ("ok", "webhook:ok:204"),
        ("redirect", "webhook:failed:307"),
        ("slow", "webhook:failed:"),
    ] {
        let config = ScanConfig {
            webhook_url: format!("http://127.0.0.1:{port}/{path}"),
            ..ScanConfig::default()
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(12),
            agentsniff::notifier::send_alerts(&result, &config),
        )
        .await
        .unwrap();
        assert!(outcome[0].starts_with(expected), "{outcome:?}");
    }
    server.abort();
}

#[tokio::test]
async fn history_quota_and_result_paging_preserve_existing_scans() {
    let storage = SqliteBackend::in_memory().unwrap();
    for i in 0..agentsniff::storage::MAX_HISTORY_SCANS {
        let mut result = ScanResult::new();
        result.scan_id = format!("scan-{i}");
        storage.save_scan(&result).await.unwrap();
    }
    assert!(storage.save_scan(&ScanResult::new()).await.is_err());
    assert_eq!(storage.get_scan_count().await.unwrap(), 1000);
    assert_eq!(storage.list_scans(u32::MAX, 0).await.unwrap().len(), 100);
    let mut result = ScanResult::new();
    result.scan_id = "scan-0".into();
    for port in 1..=101 {
        result.agents.push(DetectedAgent::for_endpoint(
            "local".into(),
            "127.0.0.1".parse().unwrap(),
            Some(port),
            "tcp",
        ));
    }
    storage.save_scan(&result).await.unwrap(); // replacing a scan does not consume a new slot
    let app = create_router_with_storage(
        ScanConfig::default(),
        Box::new(storage),
        Arc::new(EbpfChannels::new()),
    );
    for (offset, expected) in [(0, 100), (100, 1)] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/scan/scan-0?limit=4294967295&offset={offset}"))
                    .header("Host", "localhost:9090")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["agents"].as_array().unwrap().len(), expected);
        assert_eq!(body["pagination"]["total"], 101);
        assert_eq!(body["pagination"]["limit"], 100);
    }
}
