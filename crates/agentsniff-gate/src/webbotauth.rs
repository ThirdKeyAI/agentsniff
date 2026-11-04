//! Web Bot Auth request verification (draft-meunier-web-bot-auth-architecture,
//! HTTP Message Signatures per RFC 9421, Ed25519 only).
//!
//! Only operator-pinned keys are trusted. The `Signature-Agent` header names
//! the agent's key directory, but the gate never fetches it: an issuer-chosen
//! URL on the request path would be an SSRF and latency primitive. Operators
//! pin keys out of band, the same model AgentSniff uses for A2A and AgentPin.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::sfv::{self, BareItem, Dictionary, Member};

/// Most signatures examined per request.
const MAX_LABELS: usize = 4;
const SIGNATURE_AGENT_MAX_BYTES: usize = 2048;
const MAX_CLOCK_SKEW_SECS: i64 = 3_600;
const MAX_NONCES: usize = 10_000_000;

/// An Ed25519 public key in JWK form (RFC 8037).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OkpJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

/// One operator-pinned Web Bot Auth signing key.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TrustedAgentKey {
    /// Catalog agent id (or your own id) this key identifies.
    pub agent_id: String,
    /// Key id the agent sends. Empty means the RFC 7638 JWK thumbprint,
    /// which Web Bot Auth requires.
    pub keyid: String,
    pub jwk: OkpJwk,
    /// When set, a verified request must also name this Signature-Agent origin.
    pub signature_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WebBotAuthConfig {
    pub enabled: bool,
    pub trusted_keys: Vec<TrustedAgentKey>,
    /// Longest accepted `expires - created`. The draft allows up to 24h; a
    /// shorter cap narrows the window in which a captured request can be
    /// replayed against another gate instance.
    pub max_lifetime_secs: i64,
    pub clock_skew_secs: i64,
    /// Upper bound on remembered nonces for replay detection.
    pub max_nonces: usize,
    /// Reject signatures without a nonce. Without one, a captured request
    /// replays until it expires.
    pub require_nonce: bool,
    /// When non-empty, a signature verifies only if the request's authority
    /// (host, plus port if non-default) is listed. This stops a signature
    /// captured on another site from verifying here when a proxy forwards a
    /// client-supplied Host.
    pub authorities: Vec<String>,
}

impl Default for WebBotAuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_keys: Vec::new(),
            max_lifetime_secs: 3_600,
            clock_skew_secs: 60,
            max_nonces: 100_000,
            require_nonce: true,
            authorities: Vec::new(),
        }
    }
}

impl WebBotAuthConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_lifetime_secs <= 0 {
            anyhow::bail!("gate.web_bot_auth.max_lifetime_secs must be positive");
        }
        if !(0..=MAX_CLOCK_SKEW_SECS).contains(&self.clock_skew_secs) {
            anyhow::bail!(
                "gate.web_bot_auth.clock_skew_secs must be between 0 and {MAX_CLOCK_SKEW_SECS}"
            );
        }
        if !(1..=MAX_NONCES).contains(&self.max_nonces) {
            anyhow::bail!("gate.web_bot_auth.max_nonces must be between 1 and {MAX_NONCES}");
        }
        if let Some(bad) = self
            .authorities
            .iter()
            .find(|a| a.is_empty() || a.contains(['/', ' ', '@']))
        {
            anyhow::bail!("gate.web_bot_auth.authorities entry {bad:?} must be a host[:port]");
        }
        Ok(())
    }
}

/// The original request as the edge saw it.
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum WebBotAuthOutcome {
    /// No Web Bot Auth signature on the request.
    Absent,
    /// Signature verified against a pinned key.
    Verified {
        agent_id: String,
        keyid: String,
        signature_agent: Option<String>,
    },
    /// The request declares itself a signed agent, but nothing verified.
    Unverified {
        reason: &'static str,
        keyid: Option<String>,
        signature_agent: Option<String>,
    },
}

struct PinnedKey {
    agent_id: String,
    key: VerifyingKey,
    signature_agent: Option<String>,
}

pub struct WebBotAuthVerifier {
    config: WebBotAuthConfig,
    keys: HashMap<String, PinnedKey>,
    authorities: HashSet<String>,
    nonces: Mutex<HashMap<String, i64>>,
}

/// RFC 7638 / RFC 8037 thumbprint of an Ed25519 JWK, base64url without padding.
pub fn jwk_thumbprint(jwk: &OkpJwk) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn decode_okp(jwk: &OkpJwk) -> anyhow::Result<VerifyingKey> {
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        anyhow::bail!("only OKP/Ed25519 keys are supported");
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk.x.trim_end_matches('='))
        .map_err(|_| anyhow::anyhow!("jwk.x is not base64url"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("jwk.x must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("jwk.x is not a valid Ed25519 key"))
}

/// Normalize a URL to `scheme://host[:port]`, lowercased.
pub fn origin_of(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    ))
}

fn combined_header(
    headers: &HeaderMap,
    name: &str,
    limit: usize,
) -> Result<Option<String>, &'static str> {
    let mut values = Vec::new();
    let mut total = 0usize;
    for value in headers.get_all(name) {
        let text = value.to_str().map_err(|_| "non_ascii_header")?.trim();
        total += text.len() + 2;
        if total > limit {
            return Err("header_too_large");
        }
        values.push(text.to_string());
    }
    Ok((!values.is_empty()).then(|| values.join(", ")))
}

fn param_str<'a>(params: &'a sfv::Parameters, key: &str) -> Option<&'a str> {
    match sfv::param(params, key) {
        Some(BareItem::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn param_int(params: &sfv::Parameters, key: &str) -> Option<i64> {
    match sfv::param(params, key) {
        Some(BareItem::Integer(n)) => Some(*n),
        _ => None,
    }
}

/// True when a Signature-Input field mentions the `web-bot-auth` tag, even
/// one that does not parse. Other uses of HTTP signatures (PSD2 and other
/// API signing schemes) are not agent claims and are left alone.
fn claims_web_bot_auth(headers: &HeaderMap) -> bool {
    const TAG: &[u8] = b"web-bot-auth";
    headers.get_all("signature-input").iter().any(|value| {
        value
            .as_bytes()
            .windows(TAG.len())
            .any(|w| w.eq_ignore_ascii_case(TAG))
    })
}

/// The agent a bare `Signature-Agent` header names, signed or not.
pub fn declared_signature_agent(headers: &HeaderMap) -> Option<String> {
    combined_header(headers, "signature-agent", SIGNATURE_AGENT_MAX_BYTES)
        .ok()
        .flatten()
        .and_then(|raw| signature_agent_values(&raw).into_iter().next())
}

/// Signature-Agent values the request names: dictionary members, or the
/// legacy single sf-string form.
fn signature_agent_values(raw: &str) -> Vec<String> {
    if let Ok(dict) = sfv::parse_dictionary(raw) {
        let values: Vec<String> = dict
            .iter()
            .filter_map(|(_, member)| match member {
                Member::Item(item) => match &item.bare {
                    BareItem::String(s) => Some(s.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        if !values.is_empty() {
            return values;
        }
    }
    match sfv::parse_item(raw) {
        Ok(item) => match item.bare {
            BareItem::String(s) => vec![s],
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

impl WebBotAuthVerifier {
    pub fn new(config: WebBotAuthConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let mut keys = HashMap::new();
        for entry in &config.trusted_keys {
            if entry.agent_id.is_empty() {
                anyhow::bail!("web_bot_auth.trusted_keys entries need an agent_id");
            }
            let key = decode_okp(&entry.jwk)
                .map_err(|e| anyhow::anyhow!("trusted key for {}: {}", entry.agent_id, e))?;
            let keyid = if entry.keyid.is_empty() {
                jwk_thumbprint(&entry.jwk)
            } else {
                entry.keyid.clone()
            };
            let signature_agent = if entry.signature_agent.is_empty() {
                None
            } else {
                Some(origin_of(&entry.signature_agent).ok_or_else(|| {
                    anyhow::anyhow!(
                        "trusted key for {}: signature_agent must be a URL",
                        entry.agent_id
                    )
                })?)
            };
            if keys
                .insert(
                    keyid.clone(),
                    PinnedKey {
                        agent_id: entry.agent_id.clone(),
                        key,
                        signature_agent,
                    },
                )
                .is_some()
            {
                anyhow::bail!("duplicate Web Bot Auth keyid {keyid}");
            }
        }
        let authorities = config
            .authorities
            .iter()
            .map(|a| a.trim().to_ascii_lowercase())
            .collect();
        Ok(Self {
            config,
            keys,
            authorities,
            nonces: Mutex::new(HashMap::new()),
        })
    }

    pub fn trusted_key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify the request's Web Bot Auth signature, if any, at `now` (Unix seconds).
    pub fn verify(&self, request: &SignedRequest<'_>, now: i64) -> WebBotAuthOutcome {
        if !self.config.enabled || !claims_web_bot_auth(request.headers) {
            return WebBotAuthOutcome::Absent;
        }
        let (input_raw, sig_raw) = match (
            combined_header(request.headers, "signature-input", sfv::MAX_FIELD_BYTES),
            combined_header(request.headers, "signature", sfv::MAX_FIELD_BYTES),
        ) {
            (Ok(Some(input)), Ok(Some(sig))) => (input, sig),
            (Err(reason), _) | (_, Err(reason)) => return unverified(reason, None, None),
            _ => return unverified("incomplete_signature_headers", None, None),
        };
        let agent_raw = match combined_header(
            request.headers,
            "signature-agent",
            SIGNATURE_AGENT_MAX_BYTES,
        ) {
            Ok(value) => value,
            Err(reason) => return unverified(reason, None, None),
        };
        let declared_agent = agent_raw
            .as_deref()
            .and_then(|raw| signature_agent_values(raw).into_iter().next());

        let inputs = match sfv::parse_dictionary(&input_raw) {
            Ok(dict) => dict,
            Err(reason) => return unverified(reason, None, declared_agent),
        };
        let signatures = match sfv::parse_dictionary(&sig_raw) {
            Ok(dict) => dict,
            Err(reason) => return unverified(reason, None, declared_agent),
        };

        let mut last: Option<WebBotAuthOutcome> = None;
        for (label, member) in inputs.iter().take(MAX_LABELS) {
            let Member::InnerList(covered) = member else {
                continue;
            };
            if param_str(&covered.params, "tag") != Some("web-bot-auth") {
                continue;
            }
            let outcome = self.verify_label(
                request,
                label,
                covered,
                &signatures,
                agent_raw.as_deref(),
                declared_agent.clone(),
                now,
            );
            if matches!(outcome, WebBotAuthOutcome::Verified { .. }) {
                return outcome;
            }
            last = Some(outcome);
        }
        last.unwrap_or(WebBotAuthOutcome::Absent)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_label(
        &self,
        request: &SignedRequest<'_>,
        label: &str,
        covered: &sfv::InnerList,
        signatures: &Dictionary,
        agent_raw: Option<&str>,
        declared_agent: Option<String>,
        now: i64,
    ) -> WebBotAuthOutcome {
        let keyid = param_str(&covered.params, "keyid").map(str::to_string);
        let fail = |reason: &'static str| unverified(reason, keyid.clone(), declared_agent.clone());

        let Some(keyid_value) = keyid.as_deref() else {
            return fail("missing_keyid");
        };
        let (Some(created), Some(expires)) = (
            param_int(&covered.params, "created"),
            param_int(&covered.params, "expires"),
        ) else {
            return fail("missing_created_or_expires");
        };
        if let Some(alg) = sfv::param(&covered.params, "alg") {
            if *alg != BareItem::String("ed25519".into()) {
                return fail("unsupported_alg");
            }
        }
        let skew = self.config.clock_skew_secs;
        if created > now.saturating_add(skew) {
            return fail("created_in_future");
        }
        if now > expires.saturating_add(skew) {
            return fail("expired");
        }
        if expires < created || expires.saturating_sub(created) > self.config.max_lifetime_secs {
            return fail("lifetime_too_long");
        }

        // Which covered component names the agent, and which value it signed.
        let mut covers_target = false;
        let mut signed_agent: Option<String> = None;
        let mut covers_agent = false;
        for component in &covered.items {
            let BareItem::String(name) = &component.bare else {
                return fail("bad_component");
            };
            if name == "@authority" || name == "@target-uri" {
                covers_target = true;
            }
            if name == "signature-agent" {
                covers_agent = true;
                if let Some(raw) = agent_raw {
                    signed_agent = match param_str(&component.params, "key") {
                        Some(key) => sfv::parse_dictionary(raw).ok().and_then(|dict| {
                            match sfv::dict_get(&dict, key) {
                                Some(Member::Item(item)) => match &item.bare {
                                    BareItem::String(s) => Some(s.clone()),
                                    _ => None,
                                },
                                _ => None,
                            }
                        }),
                        None => signature_agent_values(raw).into_iter().next(),
                    };
                }
            }
        }
        if !covers_target {
            return fail("authority_not_covered");
        }
        if agent_raw.is_some() && !covers_agent {
            return fail("signature_agent_not_covered");
        }
        let declared = signed_agent.or(declared_agent.clone());
        let fail = |reason: &'static str| unverified(reason, keyid.clone(), declared.clone());

        if !self.authorities.is_empty()
            && !self
                .authorities
                .contains(&request.authority.trim().to_ascii_lowercase())
        {
            return fail("authority_not_allowed");
        }
        let nonce = param_str(&covered.params, "nonce");
        if nonce.is_none() && self.config.require_nonce {
            return fail("missing_nonce");
        }

        let Some(pinned) = self.keys.get(keyid_value) else {
            return fail("unknown_keyid");
        };
        let Some(Member::Item(sig_item)) = sfv::dict_get(signatures, label) else {
            return fail("missing_signature");
        };
        let BareItem::ByteSeq(sig_bytes) = &sig_item.bare else {
            return fail("bad_signature_encoding");
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return fail("bad_signature_length");
        };

        let base = match signature_base(request, covered) {
            Ok(base) => base,
            Err(reason) => return fail(reason),
        };
        if pinned
            .key
            .verify_strict(base.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .is_err()
        {
            return fail("bad_signature");
        }
        if let Some(expected) = &pinned.signature_agent {
            if declared.as_deref().and_then(origin_of).as_ref() != Some(expected) {
                return fail("signature_agent_mismatch");
            }
        }
        if let Some(nonce) = nonce {
            if !self.remember_nonce(keyid_value, nonce, expires.saturating_add(skew), now) {
                return fail("replayed_nonce");
            }
        }

        WebBotAuthOutcome::Verified {
            agent_id: pinned.agent_id.clone(),
            keyid: keyid_value.to_string(),
            signature_agent: declared,
        }
    }

    /// Record a nonce; false if it was already seen and is still live.
    fn remember_nonce(&self, keyid: &str, nonce: &str, valid_until: i64, now: i64) -> bool {
        let Ok(mut nonces) = self.nonces.lock() else {
            return false;
        };
        let key = format!("{keyid}\u{0}{nonce}");
        if nonces.get(&key).is_some_and(|until| *until >= now) {
            return false;
        }
        if nonces.len() >= self.config.max_nonces {
            nonces.retain(|_, until| *until >= now);
            if nonces.len() >= self.config.max_nonces {
                // Fail closed rather than forget live nonces.
                return false;
            }
        }
        nonces.insert(key, valid_until);
        true
    }
}

fn unverified(
    reason: &'static str,
    keyid: Option<String>,
    signature_agent: Option<String>,
) -> WebBotAuthOutcome {
    WebBotAuthOutcome::Unverified {
        reason,
        keyid,
        signature_agent,
    }
}

/// Build the RFC 9421 section 2.5 signature base for the covered components.
pub fn signature_base(
    request: &SignedRequest<'_>,
    covered: &sfv::InnerList,
) -> Result<String, &'static str> {
    let mut base = String::new();
    for component in &covered.items {
        let BareItem::String(name) = &component.bare else {
            return Err("bad_component");
        };
        let value = component_value(request, name, &component.params)?;
        if value.contains('\n') || value.contains('\r') {
            return Err("bad_component_value");
        }
        sfv::serialize_item(component, &mut base);
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    sfv::serialize_inner_list(covered, &mut base);
    Ok(base)
}

fn component_value(
    request: &SignedRequest<'_>,
    name: &str,
    params: &sfv::Parameters,
) -> Result<String, &'static str> {
    let key = param_str(params, "key");
    if params.iter().any(|(k, _)| k != "key") || (key.is_some() && name.starts_with('@')) {
        return Err("unsupported_component_parameter");
    }
    let query = request.query.unwrap_or("");
    let path = if request.path.is_empty() {
        "/"
    } else {
        request.path
    };
    match name {
        "@authority" => Ok(request.authority.to_ascii_lowercase()),
        "@method" => Ok(request.method.to_string()),
        "@scheme" => Ok(request.scheme.to_ascii_lowercase()),
        "@path" => Ok(path.to_string()),
        "@query" => Ok(format!("?{query}")),
        "@request-target" => Ok(if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        }),
        "@target-uri" => Ok(format!(
            "{}://{}{}{}",
            request.scheme.to_ascii_lowercase(),
            request.authority.to_ascii_lowercase(),
            path,
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        )),
        _ if name.starts_with('@') => Err("unsupported_derived_component"),
        _ => {
            if name.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err("bad_component_name");
            }
            let raw = combined_header(request.headers, name, sfv::MAX_FIELD_BYTES)?
                .ok_or("missing_covered_header")?;
            match key {
                None => Ok(raw),
                Some(key) => {
                    let dict = sfv::parse_dictionary(&raw)?;
                    let member = sfv::dict_get(&dict, key).ok_or("missing_dictionary_member")?;
                    let mut out = String::new();
                    sfv::serialize_member(member, &mut out);
                    Ok(out)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from Cloudflare's web-bot-auth repository (Apache-2.0):
    // packages/web-bot-auth/test/test_data/web_bot_auth_architecture_v{1,2}.json
    // and examples/rust/verify.rs. Key: RFC 9421 Appendix B.1.4 test-key-ed25519.
    const TEST_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
    const TEST_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

    fn test_jwk() -> OkpJwk {
        OkpJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: TEST_X.into(),
        }
    }

    fn verifier(max_lifetime_secs: i64) -> WebBotAuthVerifier {
        WebBotAuthVerifier::new(WebBotAuthConfig {
            trusted_keys: vec![TrustedAgentKey {
                agent_id: "test_agent".into(),
                jwk: test_jwk(),
                ..Default::default()
            }],
            max_lifetime_secs,
            ..Default::default()
        })
        .unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn request(headers: &HeaderMap) -> SignedRequest<'_> {
        SignedRequest {
            method: "GET",
            scheme: "https",
            authority: "example.com",
            path: "/path/to/resource",
            query: None,
            headers,
        }
    }

    #[test]
    fn thumbprint_matches_draft_keyid() {
        assert_eq!(jwk_thumbprint(&test_jwk()), TEST_KEYID);
    }

    #[test]
    fn verifies_authority_only_vector() {
        let h = headers(&[
            ("signature-input", r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==";tag="web-bot-auth""#),
            ("signature", "sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:"),
        ]);
        let outcome = verifier(86_400).verify(&request(&h), 1_735_690_000);
        assert!(
            matches!(outcome, WebBotAuthOutcome::Verified { ref agent_id, .. } if agent_id == "test_agent"),
            "{outcome:?}"
        );
    }

    #[test]
    fn verifies_dictionary_signature_agent_vector() {
        let h = headers(&[
            ("signature-agent", r#"agent2="https://signature-agent.test""#),
            ("signature-input", r#"sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth""#),
            ("signature", "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:"),
        ]);
        // This vector's validity window is ~100 years, so allow it here only.
        let outcome = verifier(i64::MAX / 2).verify(&request(&h), 1_735_690_000);
        assert_eq!(
            outcome,
            WebBotAuthOutcome::Verified {
                agent_id: "test_agent".into(),
                keyid: TEST_KEYID.into(),
                signature_agent: Some("https://signature-agent.test".into()),
            }
        );
        // The default lifetime cap rejects it.
        assert!(matches!(
            verifier(86_400).verify(&request(&h), 1_735_690_000),
            WebBotAuthOutcome::Unverified {
                reason: "lifetime_too_long",
                ..
            }
        ));
    }

    #[test]
    fn verifies_legacy_string_signature_agent_vector() {
        let h = headers(&[
            ("signature-agent", r#""https://signature-agent.test""#),
            ("signature-input", r#"sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth""#),
            ("signature", "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:"),
        ]);
        let outcome = verifier(86_400).verify(&request(&h), 1_735_690_000);
        assert!(
            matches!(outcome, WebBotAuthOutcome::Verified { .. }),
            "{outcome:?}"
        );
    }

    /// Sign `covered` over `request` with a throwaway key and return headers.
    fn self_signed(
        signing: &ed25519_dalek::SigningKey,
        input_member: &str,
        agent: Option<&str>,
    ) -> HeaderMap {
        let mut pairs = vec![("signature-input", format!("sig1={input_member}"))];
        if let Some(agent) = agent {
            pairs.push(("signature-agent", agent.to_string()));
        }
        let owned: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let h = headers(&owned);
        let sfv::Member::InnerList(covered) =
            sfv::parse_dictionary(&format!("sig1={input_member}"))
                .unwrap()
                .remove(0)
                .1
        else {
            panic!("not an inner list");
        };
        let base = signature_base(&request(&h), &covered).unwrap();
        use ed25519_dalek::Signer;
        let sig = signing.sign(base.as_bytes());
        let mut h = h;
        h.insert(
            "signature",
            http::HeaderValue::from_str(&format!(
                "sig1=:{}:",
                base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
            ))
            .unwrap(),
        );
        h
    }

    fn self_signed_verifier(
        signing: &ed25519_dalek::SigningKey,
        signature_agent: &str,
    ) -> WebBotAuthVerifier {
        let jwk = OkpJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing.verifying_key().to_bytes()),
        };
        WebBotAuthVerifier::new(WebBotAuthConfig {
            trusted_keys: vec![TrustedAgentKey {
                agent_id: "openai_chatgpt_agent".into(),
                keyid: "k1".into(),
                jwk,
                signature_agent: signature_agent.into(),
            }],
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn self_signed_request_replay_expiry_and_agent_pinning() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let input = r#"("@authority" "@path" "signature-agent";key="a1");created=1000;expires=1300;keyid="k1";nonce="n-1";tag="web-bot-auth""#;
        let h = self_signed(&signing, input, Some(r#"a1="https://chatgpt.com""#));

        let v = self_signed_verifier(&signing, "https://chatgpt.com/");
        assert_eq!(
            v.verify(&request(&h), 1100),
            WebBotAuthOutcome::Verified {
                agent_id: "openai_chatgpt_agent".into(),
                keyid: "k1".into(),
                signature_agent: Some("https://chatgpt.com".into()),
            }
        );
        assert!(matches!(
            v.verify(&request(&h), 1101),
            WebBotAuthOutcome::Unverified {
                reason: "replayed_nonce",
                ..
            }
        ));
        assert!(matches!(
            self_signed_verifier(&signing, "").verify(&request(&h), 5000),
            WebBotAuthOutcome::Unverified {
                reason: "expired",
                ..
            }
        ));
        assert!(matches!(
            self_signed_verifier(&signing, "").verify(&request(&h), 100),
            WebBotAuthOutcome::Unverified {
                reason: "created_in_future",
                ..
            }
        ));
        // A valid signature from the pinned key that names another agent origin.
        assert!(matches!(
            self_signed_verifier(&signing, "https://other.example").verify(&request(&h), 1100),
            WebBotAuthOutcome::Unverified {
                reason: "signature_agent_mismatch",
                ..
            }
        ));
        // Changing the path breaks the covered @path component.
        let mut moved = request(&h);
        moved.path = "/transfer";
        assert!(matches!(
            self_signed_verifier(&signing, "").verify(&moved, 1100),
            WebBotAuthOutcome::Unverified {
                reason: "bad_signature",
                ..
            }
        ));
    }

    #[test]
    fn rfc_member_semantics_for_key_parameter() {
        // Cloudflare's examples/rust/verify.rs signs the whole Signature-Agent
        // dictionary under ;key="agent1". RFC 9421 section 2.1.2 signs only the
        // member value, as the draft's own test vectors do, so that example
        // does not verify here.
        let h = headers(&[
            ("signature-agent", r#"agent1="https://myexample.com""#),
            ("signature-input", r#"sig1=("@authority" "signature-agent";key="agent1");keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";nonce="ZO3/XMEZjrvSnLtAP9M7jK0WGQf3J+pbmQRUpKDhF9/jsNCWqUh2sq+TH4WTX3/GpNoSZUa8eNWMKqxWp2/c2g==";tag="web-bot-auth";created=1761143856;expires=1761143866"#),
            ("signature", "sig1=:EZZ8VJcVQ9WgiUytQWAfEvRWLLu2O+UkJ15aVI//dfLTCLnr1Vg2CDXXlrW4D+OjBB6zu/UkFtxpKzbXh2ESBg==:"),
        ]);
        assert!(matches!(
            verifier(86_400).verify(&request(&h), 1_761_143_860),
            WebBotAuthOutcome::Unverified {
                reason: "bad_signature",
                ..
            }
        ));
    }

    #[test]
    fn rejects_tampered_authority_and_unknown_keys() {
        let h = headers(&[
            ("signature-input", r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==";tag="web-bot-auth""#),
            ("signature", "sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:"),
        ]);
        let mut req = request(&h);
        req.authority = "bank.example";
        assert!(matches!(
            verifier(86_400).verify(&req, 1_735_690_000),
            WebBotAuthOutcome::Unverified {
                reason: "bad_signature",
                ..
            }
        ));
        let empty = WebBotAuthVerifier::new(WebBotAuthConfig::default()).unwrap();
        assert!(matches!(
            empty.verify(&request(&h), 1_735_690_000),
            WebBotAuthOutcome::Unverified {
                reason: "unknown_keyid",
                ..
            }
        ));
    }

    #[test]
    fn unsigned_signature_agent_is_not_trusted() {
        let h = headers(&[
            ("signature-agent", r#"agent1="https://chatgpt.com""#),
            ("signature-input", r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";expires=1735693200;tag="web-bot-auth""#),
            ("signature", "sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:"),
        ]);
        assert!(matches!(
            verifier(86_400).verify(&request(&h), 1_735_690_000),
            WebBotAuthOutcome::Unverified {
                reason: "signature_agent_not_covered",
                ref signature_agent,
                ..
            } if signature_agent.as_deref() == Some("https://chatgpt.com")
        ));
    }

    #[test]
    fn absent_without_headers_and_ignores_other_tags() {
        let none = HeaderMap::new();
        assert_eq!(
            verifier(86_400).verify(&request(&none), 0),
            WebBotAuthOutcome::Absent
        );
        let other = headers(&[
            (
                "signature-input",
                r#"s=("@method");created=1;keyid="k";tag="something-else""#,
            ),
            ("signature", "s=:AAAA:"),
        ]);
        assert_eq!(
            verifier(86_400).verify(&request(&other), 0),
            WebBotAuthOutcome::Absent
        );
    }

    #[test]
    fn nonce_required_by_default() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let input = r#"("@authority");created=1000;expires=1300;keyid="k1";tag="web-bot-auth""#;
        let h = self_signed(&signing, input, None);
        assert!(matches!(
            self_signed_verifier(&signing, "").verify(&request(&h), 1100),
            WebBotAuthOutcome::Unverified {
                reason: "missing_nonce",
                ..
            }
        ));
        let mut relaxed = self_signed_verifier(&signing, "");
        relaxed.config.require_nonce = false;
        assert!(matches!(
            relaxed.verify(&request(&h), 1100),
            WebBotAuthOutcome::Verified { .. }
        ));
    }

    #[test]
    fn authority_allowlist() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let input =
            r#"("@authority");created=1000;expires=1300;keyid="k1";nonce="a";tag="web-bot-auth""#;
        let h = self_signed(&signing, input, None);
        let mut v = self_signed_verifier(&signing, "");
        v.authorities = ["bank.example".to_string()].into_iter().collect();
        // Signed for example.com, presented to a gate that serves bank.example.
        assert!(matches!(
            v.verify(&request(&h), 1100),
            WebBotAuthOutcome::Unverified {
                reason: "authority_not_allowed",
                ..
            }
        ));
        v.authorities.insert("example.com".into());
        assert!(matches!(
            v.verify(&request(&h), 1100),
            WebBotAuthOutcome::Verified { .. }
        ));
    }

    #[test]
    fn other_signature_schemes_are_not_agent_claims() {
        // A draft-cavage / PSD2 style signature, as some banking APIs send.
        let cavage = headers(&[(
            "signature",
            r#"keyId="tpp-1",algorithm="rsa-sha256",headers="digest x-request-id",signature="AAAA""#,
        )]);
        assert_eq!(
            verifier(3_600).verify(&request(&cavage), 0),
            WebBotAuthOutcome::Absent
        );
        // RFC 9421 without the web-bot-auth tag, even malformed.
        let plain = headers(&[("signature-input", "not a dictionary ((")]);
        assert_eq!(
            verifier(3_600).verify(&request(&plain), 0),
            WebBotAuthOutcome::Absent
        );
        // A tagged but incomplete claim is still a claim.
        let tagged = headers(&[(
            "signature-input",
            r#"sig1=("@authority");tag="web-bot-auth""#,
        )]);
        assert!(matches!(
            verifier(3_600).verify(&request(&tagged), 0),
            WebBotAuthOutcome::Unverified {
                reason: "incomplete_signature_headers",
                ..
            }
        ));
    }

    #[test]
    fn rejects_out_of_range_settings() {
        for config in [
            WebBotAuthConfig {
                clock_skew_secs: i64::MAX,
                ..Default::default()
            },
            WebBotAuthConfig {
                max_lifetime_secs: 0,
                ..Default::default()
            },
            WebBotAuthConfig {
                max_nonces: 0,
                ..Default::default()
            },
            WebBotAuthConfig {
                authorities: vec!["https://bank.example/".into()],
                ..Default::default()
            },
        ] {
            assert!(WebBotAuthVerifier::new(config).is_err());
        }
    }

    #[test]
    fn rejects_bad_key_config() {
        let bad = WebBotAuthConfig {
            trusted_keys: vec![TrustedAgentKey {
                agent_id: "x".into(),
                jwk: OkpJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: TEST_X.into(),
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(WebBotAuthVerifier::new(bad).is_err());
    }
}
