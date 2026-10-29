use agentsniff::config::default_config_yaml;

#[test]
fn test_default_config_yaml_is_valid() {
    let yaml = default_config_yaml();
    let uncommented: String = yaml
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let config: agentsniff::config::ScanConfig = serde_saphyr::from_str(&uncommented).unwrap();
    assert_eq!(config.target_network, "192.168.1.0/24");
    assert!(config.enable_dns_monitor);
}

#[test]
fn yaml_environment_and_explicit_cli_precedence() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    std::fs::write(
        &config,
        "target_network: 127.0.0.2/32\noutput_format: json\nquiet: true\n",
    )
    .unwrap();
    let run = |network: Option<&str>| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agentsniff"));
        command
            .args(["scan", "--config"])
            .arg(&config)
            .args(["--detectors", "", "--db", ":memory:"])
            .env("AGENTSNIFF_TARGET_NETWORK", "127.0.0.3/32");
        if let Some(network) = network {
            command.arg(network);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert_eq!(run(None)["target_network"], "127.0.0.3/32");
    assert_eq!(run(Some("127.0.0.4/32"))["target_network"], "127.0.0.4/32");
}

#[cfg(unix)]
#[test]
fn release_tag_input_is_data_and_must_match_source() {
    use std::process::Command;
    let directory = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(directory.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-q"]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "-qm",
        "fixture",
        "--allow-empty",
    ]);
    git(&["tag", "v1.2.3"]);
    let sha = git(&["rev-parse", "HEAD"]);
    let output = directory.path().join("output");
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/release-version.sh");
    let check = |tag: &str, reference: &str| {
        Command::new("bash")
            .arg(&script)
            .current_dir(directory.path())
            .env("RELEASE_TAG", tag)
            .env("GITHUB_REF", reference)
            .env("GITHUB_SHA", &sha)
            .env("GITHUB_OUTPUT", &output)
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(check("v1.2.3", "refs/tags/v1.2.3"));
    assert!(!check("v1.2.3", "refs/heads/main"));
    assert!(!check("v9.9.9", "refs/tags/v9.9.9"));
    assert!(!check(
        "v1.2.3$(touch injected)",
        "refs/tags/v1.2.3$(touch injected)"
    ));
    assert!(!check("v1.2.3\nversion=evil", "refs/tags/v1.2.3"));
    assert!(!directory.path().join("injected").exists());
    assert_eq!(std::fs::read_to_string(output).unwrap(), "version=v1.2.3\n");
}
