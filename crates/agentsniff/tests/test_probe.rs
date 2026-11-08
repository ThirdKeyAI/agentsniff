//! `agentsniff probe` touches only the given host:port, honors --rate, and
//! exits zero when the target is simply not an agent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A server that answers every request with 404 and counts connections.
fn not_an_agent_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (port, accepts)
}

fn probe(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentsniff"))
        .arg("probe")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn probe_non_agent_prints_empty_record_and_respects_rate() {
    let (port, accepts) = not_an_agent_server();
    let target = format!("127.0.0.1:{port}");
    let started = Instant::now();
    let output = probe(&[
        &target,
        "--detectors",
        "mcp_detector,a2a_detector",
        "--rate",
        "10",
    ]);
    let elapsed = started.elapsed();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["ip_address"], "127.0.0.1");
    assert_eq!(record["port"], port);
    assert_eq!(record["transport"], "tcp");
    assert_eq!(record["signals"].as_array().unwrap().len(), 0);
    assert!(record["id"].as_str().unwrap().starts_with("asset-"));

    // Every request opened a new connection (Connection: close), so N
    // connections under a 10/s cap keep the process alive for at least
    // (N - 1) * 100ms. Wall time can only grow under load, unlike per-accept
    // timestamps taken by the server thread. Allow some scheduler slack.
    let n = accepts.load(Ordering::SeqCst);
    assert!(n >= 3, "only {n} connections");
    let floor = Duration::from_millis(80 * (n as u64 - 1));
    assert!(
        elapsed >= floor,
        "{n} connections in {elapsed:?} under a 10/s cap"
    );
}

#[test]
fn probe_rejects_passive_detectors_and_bad_targets() {
    let output = probe(&["127.0.0.1:9", "--detectors", "dns_monitor"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot probe a single target"));

    let output = probe(&["example.com:80", "--detectors", "mcp_detector"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("IP:PORT"));

    let output = probe(&["127.0.0.1:9", "--detectors", "mcp_detector", "--rate", "0"]);
    assert!(!output.status.success());
}

#[test]
fn probe_times_out_as_a_failure() {
    let (port, _accepts) = not_an_agent_server();
    let target = format!("127.0.0.1:{port}");
    let output = probe(&[
        &target,
        "--detectors",
        "endpoint_prober",
        "--rate",
        "1",
        "--max-time",
        "2",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--max-time"));
}
