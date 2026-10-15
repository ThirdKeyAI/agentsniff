//! The Nmap XML import must work without Nmap installed and must never run it.

use std::process::Command;

use agentsniff::models::{DetectedAgent, ScanResult};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("agentsniff-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn enrich_imports_nmap_xml_with_no_nmap_on_path() {
    let dir = temp_dir("nmap-import");
    let empty_path = dir.join("empty-path");
    std::fs::create_dir_all(&empty_path).unwrap();

    let mut result = ScanResult::default();
    result.agents.push(DetectedAgent::new(
        "agent".to_string(),
        "192.0.2.10".parse().unwrap(),
    ));
    let scan_path = dir.join("scan.json");
    std::fs::write(&scan_path, serde_json::to_vec(&result).unwrap()).unwrap();

    let xml_path = dir.join("scan.xml");
    std::fs::write(
        &xml_path,
        r#"<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="11434"><state state="open"/><service name="http" product="ollama"/></port>
</ports></host></nmaprun>"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agentsniff"))
        .env("PATH", &empty_path)
        .args([
            "enrich",
            "--input",
            scan_path.to_str().unwrap(),
            "--nmap-xml",
            xml_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let enriched: ScanResult = serde_json::from_slice(&output.stdout).unwrap();
    let agent = &enriched.agents[0];
    assert!(agent
        .signals
        .iter()
        .any(|s| s.signal_type == "nmap_service_match"));
    assert_eq!(agent.metadata["nmap_services"][0]["product"], "ollama");
}

#[test]
fn removed_nmap_flag_points_to_replacements() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentsniff"))
        .args(["scan", "--nmap", "--quiet", "127.0.0.1/32"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--enrich"), "{stderr}");
    assert!(stderr.contains("--nmap-xml"), "{stderr}");
}
