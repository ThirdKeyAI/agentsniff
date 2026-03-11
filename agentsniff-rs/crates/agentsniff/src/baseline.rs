use std::collections::HashSet;

use crate::models::ScanResult;

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
