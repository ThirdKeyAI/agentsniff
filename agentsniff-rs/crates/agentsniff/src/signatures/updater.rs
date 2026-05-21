//! Signature update — downloads latest signatures from GitHub and verifies them.

use std::path::PathBuf;

use crate::signatures::{verify_signature, VerificationStatus, SIGNATURE_FILES};

const DEFAULT_BASE_URL: &str =
    "https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/agentsniff/signatures/";

/// Download and update signatures from a remote URL.
pub async fn update_signatures(verify: bool, base_url: Option<&str>) -> anyhow::Result<()> {
    let base = base_url.unwrap_or(DEFAULT_BASE_URL);
    let client = reqwest::Client::new();

    let sig_dir = signature_dir()?;
    std::fs::create_dir_all(&sig_dir)?;

    let mut updated = 0usize;
    let mut verified_count = 0usize;
    let mut failed = Vec::new();

    for &(name, data_file, sig_file) in SIGNATURE_FILES {
        let data_url = format!("{}{}", base, data_file);
        let data_bytes = match client.get(&data_url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) => b,
                Err(e) => { failed.push(format!("{}: {}", data_file, e)); continue; }
            },
            Ok(resp) => { failed.push(format!("{}: HTTP {}", data_file, resp.status())); continue; }
            Err(e) => { failed.push(format!("{}: {}", data_file, e)); continue; }
        };

        let sig_url = format!("{}{}", base, sig_file);
        let sig_bytes = match client.get(&sig_url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) => b,
                Err(e) => { failed.push(format!("{}: {}", sig_file, e)); continue; }
            },
            Ok(resp) => { failed.push(format!("{}: HTTP {}", sig_file, resp.status())); continue; }
            Err(e) => { failed.push(format!("{}: {}", sig_file, e)); continue; }
        };

        if verify {
            let data: serde_json::Value = match serde_json::from_slice(&data_bytes) {
                Ok(v) => v,
                Err(e) => { failed.push(format!("{}: invalid JSON: {}", data_file, e)); continue; }
            };
            let sig_json: serde_json::Value = match serde_json::from_slice(&sig_bytes) {
                Ok(v) => v,
                Err(e) => { failed.push(format!("{}: invalid sig JSON: {}", sig_file, e)); continue; }
            };

            match verify_signature(&data, &sig_json) {
                VerificationStatus::Verified => { verified_count += 1; }
                VerificationStatus::Invalid => {
                    failed.push(format!("{}: SIGNATURE INVALID — possible tampering", name));
                    continue;
                }
                VerificationStatus::Unavailable => {
                    println!("  Warning: could not verify {} (missing key in signature)", name);
                }
                VerificationStatus::Unverified => {
                    println!("  Warning: no signature available for {}", name);
                }
            }
        }

        std::fs::write(sig_dir.join(data_file), &data_bytes)?;
        std::fs::write(sig_dir.join(sig_file), &sig_bytes)?;
        updated += 1;
    }

    println!("\nSignature update complete:");
    println!("  {} file(s) updated", updated);
    if verify {
        println!("  {} verified", verified_count);
    }
    if !failed.is_empty() {
        println!("  {} failed:", failed.len());
        for f in &failed {
            println!("    - {}", f);
        }
    }

    Ok(())
}

fn signature_dir() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(PathBuf::from(home).join(".agentsniff").join("signatures"))
}
