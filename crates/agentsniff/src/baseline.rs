use std::collections::{HashMap, HashSet};

use crate::models::{AssetChangeStatus, RemovedAsset, ScanDiff, ScanResult};

/// Classify a completed scan against the most recent persisted scan for the
/// same target scope. This is the durable baseline used by the API, alerts,
/// and dashboard; the in-memory `BaselineTracker` below remains as a small
/// signal-level helper for callers that do not use storage.
pub fn apply_scan_diff(current: &mut ScanResult, previous: Option<&ScanResult>) {
    if current.cancelled || !current.errors.is_empty() {
        current.diff = ScanDiff {
            baseline_scan_id: previous.map(|scan| scan.scan_id.clone()),
            ..ScanDiff::default()
        };
        return;
    }
    let observed_at = current.completed_at.unwrap_or(current.started_at);
    let mut diff = ScanDiff {
        baseline_scan_id: previous.map(|scan| scan.scan_id.clone()),
        ..ScanDiff::default()
    };
    let previous_by_id: HashMap<&str, _> = previous
        .into_iter()
        .flat_map(|scan| scan.agents.iter())
        .map(|agent| (agent.id.as_str(), agent))
        .collect();

    for agent in &mut current.agents {
        agent.update_status();
        agent.last_seen = observed_at;
        if let Some(prior) = previous_by_id.get(agent.id.as_str()) {
            agent.first_seen = prior.first_seen;
            let prior_fingerprint = if prior.fingerprint.is_empty() {
                prior.compute_fingerprint()
            } else {
                prior.fingerprint.clone()
            };
            if agent.fingerprint == prior_fingerprint {
                agent.change_status = AssetChangeStatus::Unchanged;
                diff.unchanged_assets.push(agent.id.clone());
            } else {
                agent.change_status = AssetChangeStatus::Changed;
                diff.changed_assets.push(agent.id.clone());
            }
        } else {
            agent.change_status = AssetChangeStatus::New;
            diff.new_assets.push(agent.id.clone());
        }
    }

    if let Some(previous) = previous {
        let current_ids: HashSet<&str> = current
            .agents
            .iter()
            .map(|agent| agent.id.as_str())
            .collect();
        for agent in &previous.agents {
            if !current_ids.contains(agent.id.as_str()) {
                diff.removed_assets.push(RemovedAsset {
                    id: agent.id.clone(),
                    host: agent.host.clone(),
                    ip_address: agent.ip_address,
                    port: agent.port,
                    framework: agent.framework.clone(),
                });
            }
        }
    }

    diff.new_assets.sort();
    diff.changed_assets.sort();
    diff.unchanged_assets.sort();
    diff.removed_assets
        .sort_by(|left, right| left.id.cmp(&right.id));
    current.diff = diff;
}

/// A new (host, signal_type) pair detected that was not in the baseline.
#[derive(Debug, Clone)]
pub struct BaselineAnomaly {
    pub host: String,
    pub signal_type: String,
    pub description: String,
}

/// Tracks a baseline of known (host, signal_type) pairs.
///
/// The first scan establishes the baseline; subsequent scans flag new pairs
/// that were not present when the baseline was recorded.
pub struct BaselineTracker {
    known_pairs: HashSet<(String, String)>,
    initialized: bool,
}

impl BaselineTracker {
    pub fn new() -> Self {
        Self {
            known_pairs: HashSet::new(),
            initialized: false,
        }
    }

    /// Process a scan result.
    ///
    /// Returns a list of new (host, signal_type) pairs that were not in the
    /// baseline. On the first call the baseline is established and an empty
    /// Vec is returned.
    pub fn process(&mut self, result: &ScanResult) -> Vec<BaselineAnomaly> {
        let mut anomalies = Vec::new();
        let mut current_pairs: HashSet<(String, String)> = HashSet::new();

        for agent in &result.agents {
            for signal in &agent.signals {
                let pair = (agent.host.clone(), signal.signal_type.clone());
                current_pairs.insert(pair.clone());

                if self.initialized && !self.known_pairs.contains(&pair) {
                    anomalies.push(BaselineAnomaly {
                        host: agent.host.clone(),
                        signal_type: signal.signal_type.clone(),
                        description: format!(
                            "New signal '{}' from host '{}'",
                            signal.signal_type, agent.host
                        ),
                    });
                }
            }
        }

        if !self.initialized {
            self.initialized = true;
        }

        // Add all current pairs to the persistent baseline.
        self.known_pairs.extend(current_pairs);

        anomalies
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn known_pair_count(&self) -> usize {
        self.known_pairs.len()
    }
}

impl Default for BaselineTracker {
    fn default() -> Self {
        Self::new()
    }
}
