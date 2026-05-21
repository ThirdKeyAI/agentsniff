//! Signature loader with SchemaPin verification.
//!
//! Loads detection signatures from embedded assets or runtime directories,
//! and verifies their ECDSA P-256 signatures to detect tampering.

pub mod updater;

use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/signatures/"]
struct EmbeddedSignatures;

/// Verification status for a signature file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Signature verified successfully.
    Verified,
    /// No signature file found — data is unverified.
    Unverified,
    /// Signature verification failed — possible tampering.
    Invalid,
    /// Verification could not be performed (missing key, etc.).
    Unavailable,
}

/// Container for loaded and verified signature data.
pub struct SignatureData {
    pub llm_domains: Vec<String>,
    pub agent_infra_domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub frameworks: serde_json::Value,
    pub ports: HashMap<u16, String>,
    pub tls_fingerprints: serde_json::Value,
    pub mcp_methods: Vec<String>,
    pub verification_status: HashMap<String, VerificationStatus>,
}

/// Signature file names and their corresponding data files.
pub(crate) const SIGNATURE_FILES: &[(&str, &str, &str)] = &[
    ("llm_domains", "llm_domains.json", "llm_domains.sig"),
    (
        "agent_infra_domains",
        "agent_infra_domains.json",
        "agent_infra_domains.sig",
    ),
    (
        "domain_suffixes",
        "domain_suffixes.json",
        "domain_suffixes.sig",
    ),
    ("frameworks", "frameworks.json", "frameworks.sig"),
    ("ports", "ports.json", "ports.sig"),
    (
        "tls_fingerprints",
        "tls_fingerprints.json",
        "tls_fingerprints.sig",
    ),
    ("mcp_methods", "mcp_methods.json", "mcp_methods.sig"),
];

/// Canonicalize a JSON value by sorting object keys recursively and
/// serializing with no whitespace, matching Python's
/// `json.dumps(data, ensure_ascii=False, separators=(',', ':'), sort_keys=True)`.
fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| {
                    let v = canonicalize_json(&map[*k]);
                    format!("{}:{}", serde_json::to_string(k).unwrap(), v)
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

/// Verify a SchemaPin ECDSA P-256 signature against JSON data.
///
/// The verification process mirrors the Python SchemaPin library:
/// 1. Canonicalize the JSON (sorted keys, no whitespace)
/// 2. SHA-256 hash the canonical string
/// 3. Verify the ECDSA-P256-SHA256 signature against the hash bytes
///    (the p256 crate's verify hashes the message internally with SHA-256,
///    matching Python's `ECDSA(hashes.SHA256())` which also hashes internally)
pub fn verify_signature(
    data: &serde_json::Value,
    sig_data: &serde_json::Value,
) -> VerificationStatus {
    let signature_b64 = match sig_data.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return VerificationStatus::Unavailable,
    };

    let public_key_pem = sig_data
        .get("public_key_pem")
        .or_else(|| sig_data.get("public_key"))
        .and_then(|v| v.as_str());

    let public_key_pem = match public_key_pem {
        Some(s) if !s.is_empty() => s,
        _ => return VerificationStatus::Unavailable,
    };

    // Canonicalize the data
    let canonical = canonicalize_json(data);

    // SHA-256 hash the canonical string
    let hash_bytes = Sha256::digest(canonical.as_bytes());

    // Decode the base64 signature (DER-encoded)
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return VerificationStatus::Invalid,
    };

    // Parse the DER-encoded ECDSA signature
    let signature = match Signature::from_der(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return VerificationStatus::Invalid,
    };

    // Load the public key from PEM
    let verifying_key = match load_verifying_key_from_pem(public_key_pem) {
        Some(k) => k,
        None => return VerificationStatus::Unavailable,
    };

    // Verify: the p256 crate's verify method takes the raw message and
    // internally hashes it with SHA-256 before ECDSA verification.
    // The Python code does: sign(sha256(canonical), ECDSA(SHA256)) which
    // means it signs sha256(sha256(canonical)). So we pass hash_bytes as
    // the "message" to verify, which will be hashed again internally.
    match verifying_key.verify(&hash_bytes, &signature) {
        Ok(()) => VerificationStatus::Verified,
        Err(_) => VerificationStatus::Invalid,
    }
}

/// Load an ECDSA P-256 verifying key from a PEM-encoded public key string.
fn load_verifying_key_from_pem(pem: &str) -> Option<VerifyingKey> {
    // Extract the base64 content between the PEM headers
    let pem = pem.trim();
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;

    // The DER is a SubjectPublicKeyInfo structure. For P-256, the key bytes
    // are at the end: the SPKI header is 26 bytes for P-256.
    // Format: SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { 0x04 || x || y } }
    // The uncompressed point (65 bytes) starts after the SPKI header.
    use p256::PublicKey;
    let public_key = PublicKey::from_sec1_bytes(extract_ec_point_from_spki(&der)?).ok()?;
    Some(VerifyingKey::from(public_key))
}

/// Extract the EC point bytes from a SubjectPublicKeyInfo DER encoding.
fn extract_ec_point_from_spki(der: &[u8]) -> Option<&[u8]> {
    // For P-256 SPKI, the structure is well-known:
    // 30 59 30 13 06 07 ... 06 08 ... 03 42 00 <65 bytes of point>
    // The uncompressed point (0x04 + 32 + 32 = 65 bytes) is at the end.
    // We look for the BIT STRING tag (0x03) followed by length 0x42 (66),
    // then 0x00 (no unused bits), then 65 bytes of key data.
    if der.len() < 26 + 65 {
        return None;
    }

    // Find the BIT STRING containing the public key
    // In standard P-256 SPKI, it's at offset 23: 03 42 00 04...
    let mut i = 0;
    while i < der.len() - 2 {
        if der[i] == 0x03 && der[i + 1] == 0x42 && der[i + 2] == 0x00 {
            let start = i + 3;
            let end = start + 65;
            if end <= der.len() {
                return Some(&der[start..end]);
            }
        }
        i += 1;
    }
    None
}

impl SignatureData {
    /// Load signatures from embedded (compile-time) assets with verification.
    pub fn load_embedded() -> Self {
        let mut verification_status = HashMap::new();
        let mut data_map: HashMap<String, serde_json::Value> = HashMap::new();

        for &(name, data_file, sig_file) in SIGNATURE_FILES {
            let data_bytes = match EmbeddedSignatures::get(data_file) {
                Some(f) => f.data,
                None => {
                    tracing::error!("Embedded signature file missing: {}", data_file);
                    verification_status
                        .insert(name.to_string(), VerificationStatus::Unavailable);
                    continue;
                }
            };

            let data: serde_json::Value =
                match serde_json::from_slice(&data_bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Invalid JSON in {}: {}", data_file, e);
                        verification_status
                            .insert(name.to_string(), VerificationStatus::Invalid);
                        continue;
                    }
                };

            // Try to verify
            let status = match EmbeddedSignatures::get(sig_file) {
                Some(sig_bytes) => {
                    match serde_json::from_slice::<serde_json::Value>(&sig_bytes.data) {
                        Ok(sig_json) => verify_signature(&data, &sig_json),
                        Err(_) => VerificationStatus::Invalid,
                    }
                }
                None => VerificationStatus::Unverified,
            };

            if status == VerificationStatus::Invalid {
                tracing::warn!(
                    "SIGNATURE INVALID: {} may have been tampered with",
                    data_file
                );
            }

            verification_status.insert(name.to_string(), status);
            data_map.insert(name.to_string(), data);
        }

        Self::from_data_map(data_map, verification_status)
    }

    /// Load signatures from a directory on disk with verification.
    pub fn load_from_dir(dir: &Path) -> anyhow::Result<Self> {
        let mut verification_status = HashMap::new();
        let mut data_map: HashMap<String, serde_json::Value> = HashMap::new();

        for &(name, data_file, sig_file) in SIGNATURE_FILES {
            let data_path = dir.join(data_file);
            let sig_path = dir.join(sig_file);

            let data_bytes = std::fs::read(&data_path).map_err(|e| {
                anyhow::anyhow!("Failed to read {}: {}", data_path.display(), e)
            })?;

            let data: serde_json::Value = serde_json::from_slice(&data_bytes)?;

            let status = if sig_path.exists() {
                let sig_bytes = std::fs::read(&sig_path)?;
                match serde_json::from_slice::<serde_json::Value>(&sig_bytes) {
                    Ok(sig_json) => verify_signature(&data, &sig_json),
                    Err(_) => VerificationStatus::Invalid,
                }
            } else {
                VerificationStatus::Unverified
            };

            if status == VerificationStatus::Invalid {
                tracing::warn!(
                    "SIGNATURE INVALID: {} may have been tampered with",
                    data_file
                );
            }

            verification_status.insert(name.to_string(), status);
            data_map.insert(name.to_string(), data);
        }

        Ok(Self::from_data_map(data_map, verification_status))
    }

    /// Load with overlay: try runtime dir first, fall back to embedded.
    ///
    /// Checks `~/.agentsniff/signatures/` for user-provided signature files.
    /// Falls back to compiled-in embedded signatures.
    pub fn load_with_overlay() -> Self {
        if let Some(home) = dirs_path() {
            let runtime_dir = home.join(".agentsniff").join("signatures");
            if runtime_dir.is_dir() {
                match Self::load_from_dir(&runtime_dir) {
                    Ok(data) => {
                        tracing::info!(
                            "Loaded signatures from {}",
                            runtime_dir.display()
                        );
                        return data;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load runtime signatures from {}: {}. Falling back to embedded.",
                            runtime_dir.display(),
                            e
                        );
                    }
                }
            }
        }

        Self::load_embedded()
    }

    /// Returns true if all signature files were verified successfully.
    pub fn all_verified(&self) -> bool {
        self.verification_status
            .values()
            .all(|v| *v == VerificationStatus::Verified)
    }

    /// Returns true if any signature file has an invalid signature.
    pub fn has_invalid(&self) -> bool {
        self.verification_status
            .values()
            .any(|v| *v == VerificationStatus::Invalid)
    }

    /// Build SignatureData from a map of parsed JSON values.
    fn from_data_map(
        mut data_map: HashMap<String, serde_json::Value>,
        verification_status: HashMap<String, VerificationStatus>,
    ) -> Self {
        let llm_domains = extract_string_vec(data_map.remove("llm_domains"));
        let agent_infra_domains =
            extract_string_vec(data_map.remove("agent_infra_domains"));
        let domain_suffixes = extract_string_vec(data_map.remove("domain_suffixes"));
        let mcp_methods = extract_string_vec(data_map.remove("mcp_methods"));

        let frameworks = data_map
            .remove("frameworks")
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let tls_fingerprints = data_map
            .remove("tls_fingerprints")
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        // Parse ports: JSON has string keys, we need u16 keys
        let ports = match data_map.remove("ports") {
            Some(serde_json::Value::Object(map)) => {
                let mut ports = HashMap::new();
                for (k, v) in map {
                    if let Ok(port) = k.parse::<u16>() {
                        if let Some(name) = v.as_str() {
                            ports.insert(port, name.to_string());
                        }
                    }
                }
                ports
            }
            _ => HashMap::new(),
        };

        SignatureData {
            llm_domains,
            agent_infra_domains,
            domain_suffixes,
            frameworks,
            ports,
            tls_fingerprints,
            mcp_methods,
            verification_status,
        }
    }
}

/// Extract a Vec<String> from a JSON Value that should be an array of strings.
fn extract_string_vec(value: Option<serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// Get the user's home directory path.
fn dirs_path() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}
