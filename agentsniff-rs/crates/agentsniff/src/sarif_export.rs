use std::collections::HashSet;

use serde_json::Value;

use crate::models::{Confidence, DetectedAgent, ScanResult};

/// Convert a ScanResult to SARIF 2.1.0 format for GitHub Code Scanning integration.
pub fn to_sarif(result: &ScanResult) -> Value {
    let runs = vec![serde_json::json!({
        "tool": {
            "driver": {
                "name": "agentsniff",
                "version": "2.0.0",
                "informationUri": "https://agentsniff.org",
                "rules": build_rules(&result.agents),
            }
        },
        "results": build_results(&result.agents),
    })];

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    })
}

fn build_rules(agents: &[DetectedAgent]) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut rules = Vec::new();

    for agent in agents {
        for signal in &agent.signals {
            if seen.insert(signal.signal_type.clone()) {
                rules.push(serde_json::json!({
                    "id": signal.signal_type,
                    "shortDescription": {
                        "text": signal.description.clone(),
                    },
                }));
            }
        }
    }
    rules
}

fn build_results(agents: &[DetectedAgent]) -> Vec<Value> {
    let mut results = Vec::new();
    for agent in agents {
        for signal in &agent.signals {
            results.push(serde_json::json!({
                "ruleId": signal.signal_type,
                "level": confidence_to_sarif_level(signal.confidence),
                "message": {
                    "text": signal.description,
                },
                "locations": [{
                    "physicalLocation": {
                        "address": {
                            "absoluteAddress": 0,
                        }
                    },
                    "logicalLocations": [{
                        "name": agent.ip_address.to_string(),
                        "kind": "host",
                    }],
                }],
            }));
        }
    }
    results
}

fn confidence_to_sarif_level(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed | Confidence::High => "error",
        Confidence::Medium => "warning",
        Confidence::Low => "note",
    }
}
