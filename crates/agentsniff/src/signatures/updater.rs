//! Signature update — downloads latest signatures from GitHub and verifies them.

use std::path::PathBuf;

use crate::http::read_body_limited;
use crate::signatures::{verify_signature, SignatureData, VerificationStatus, SIGNATURE_FILES};

const DEFAULT_BASE_URL: &str =
    "https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/crates/agentsniff/assets/signatures/";

const MAX_SIGNATURE_DATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_SIGNATURE_METADATA_BYTES: usize = 64 * 1024;

/// Download and update signatures from a remote URL.
pub async fn update_signatures(base_url: Option<&str>) -> anyhow::Result<()> {
    let base = base_url.unwrap_or(DEFAULT_BASE_URL);
    let client = reqwest::Client::new();

    let mut downloaded = Vec::with_capacity(SIGNATURE_FILES.len());

    for &(name, data_file, sig_file) in SIGNATURE_FILES {
        let data_url = format!("{}{}", base, data_file);
        let data_bytes = match client.get(&data_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                read_body_limited(resp, MAX_SIGNATURE_DATA_BYTES)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to read {}: {}", data_file, e))?
            }
            Ok(resp) => anyhow::bail!("failed to download {}: HTTP {}", data_file, resp.status()),
            Err(e) => anyhow::bail!("failed to download {}: {}", data_file, e),
        };

        let sig_url = format!("{}{}", base, sig_file);
        let sig_bytes = match client.get(&sig_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                read_body_limited(resp, MAX_SIGNATURE_METADATA_BYTES)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to read {}: {}", sig_file, e))?
            }
            Ok(resp) => anyhow::bail!("failed to download {}: HTTP {}", sig_file, resp.status()),
            Err(e) => anyhow::bail!("failed to download {}: {}", sig_file, e),
        };

        let data: serde_json::Value = serde_json::from_slice(&data_bytes)
            .map_err(|e| anyhow::anyhow!("{} contains invalid JSON: {}", data_file, e))?;
        let sig_json: serde_json::Value = serde_json::from_slice(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("{} contains invalid JSON: {}", sig_file, e))?;
        if verify_signature(&data, &sig_json) != VerificationStatus::Verified {
            anyhow::bail!("signature verification failed for {}", name);
        }

        downloaded.push((data_file, data_bytes, sig_file, sig_bytes));
    }

    let sig_dir = signature_dir()?;
    let parent = sig_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("signature directory has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let nonce = uuid::Uuid::new_v4();
    let staging = parent.join(format!(".signatures-{}.tmp", nonce));
    let backup = parent.join(format!(".signatures-{}.bak", nonce));
    std::fs::create_dir(&staging)?;

    for (data_file, data_bytes, sig_file, sig_bytes) in &downloaded {
        std::fs::write(staging.join(data_file), data_bytes)?;
        std::fs::write(staging.join(sig_file), sig_bytes)?;
    }

    if let Err(e) = SignatureData::load_from_dir(&staging) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e.context("staged signature set failed verification"));
    }

    if sig_dir.exists() {
        std::fs::rename(&sig_dir, &backup)?;
    }
    if let Err(e) = std::fs::rename(&staging, &sig_dir) {
        if backup.exists() {
            let _ = std::fs::rename(&backup, &sig_dir);
        }
        anyhow::bail!("failed to activate signature set: {}", e);
    }
    if backup.exists() {
        std::fs::remove_dir_all(&backup)?;
    }

    println!("\nSignature update complete:");
    println!(
        "  {} signature set(s) verified and updated",
        downloaded.len()
    );
    Ok(())
}

fn signature_dir() -> anyhow::Result<PathBuf> {
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME environment variable not set"))?;
    Ok(PathBuf::from(home).join(".agentsniff").join("signatures"))
}
