//! Runtime monitor: tracks agent behavior for anomaly detection.
//!
//! Counts actions, tracks durations, and watches resource consumption per agent.
//! Detects "individually benign, collectively dangerous" patterns by monitoring
//! cumulative trajectories against configurable thresholds.
//!
//! ## Advanced features (AgentGuard-style)
//!
//! - **FSM state tracking**: Agents move through defined states (idle, executing,
//!   requesting_secret, etc.) with validated transitions. Invalid transitions
//!   generate alerts.
//! - **Sliding window analysis**: Action rates tracked over configurable windows
//!   (1min, 5min, 15min). Sudden spikes trigger alerts.
//! - **Pattern detection**: Specific action sequences flagged (e.g., "read secret"
//!   followed by "network request" within N seconds).

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use moat_core::MoatError;

/// Thresholds that trigger alerts when crossed.
#[derive(Debug, Clone)]
pub struct MonitorThresholds {
    /// Max total actions per agent before alert.
    pub max_actions: u64,
    /// Max actions of a single type per agent.
    pub max_actions_per_type: u64,
    /// Max unique resources accessed per agent.
    pub max_unique_resources: u64,
    /// Max cumulative "cost" score per agent. Actions have configurable weights.
    pub max_cumulative_cost: f64,
}

impl Default for MonitorThresholds {
    fn default() -> Self {
        Self {
            max_actions: 1000,
            max_actions_per_type: 100,
            max_unique_resources: 50,
            max_cumulative_cost: 100.0,
        }
    }
}

/// An alert emitted when a threshold is crossed.
#[derive(Debug, Clone)]
pub struct MonitorAlert {
    pub agent_id: Uuid,
    pub alert_type: String,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

/// FSM state for agent lifecycle tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentState {
    Idle,
    Executing,
    RequestingSecret,
    NetworkRequest,
    FileAccess,
    Terminated,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Idle => write!(f, "idle"),
            AgentState::Executing => write!(f, "executing"),
            AgentState::RequestingSecret => write!(f, "requesting_secret"),
            AgentState::NetworkRequest => write!(f, "network_request"),
            AgentState::FileAccess => write!(f, "file_access"),
            AgentState::Terminated => write!(f, "terminated"),
        }
    }
}

/// Defines valid state transitions. Any transition not listed is flagged.
fn valid_transitions() -> HashMap<AgentState, Vec<AgentState>> {
    let mut m = HashMap::new();
    m.insert(
        AgentState::Idle,
        vec![AgentState::Executing, AgentState::Terminated],
    );
    m.insert(
        AgentState::Executing,
        vec![
            AgentState::Idle,
            AgentState::RequestingSecret,
            AgentState::NetworkRequest,
            AgentState::FileAccess,
            AgentState::Terminated,
        ],
    );
    m.insert(
        AgentState::RequestingSecret,
        vec![AgentState::Executing, AgentState::Idle],
    );
    m.insert(
        AgentState::NetworkRequest,
        vec![AgentState::Executing, AgentState::Idle],
    );
    m.insert(
        AgentState::FileAccess,
        vec![AgentState::Executing, AgentState::Idle],
    );
    m.insert(AgentState::Terminated, vec![]);
    m
}

/// A suspicious action pattern to detect.
#[derive(Debug, Clone)]
pub struct ActionPattern {
    /// The sequence of action types to match.
    pub actions: Vec<String>,
    /// Maximum time between first and last action in the sequence.
    pub max_window: Duration,
    /// Alert type emitted when pattern is detected.
    pub alert_type: String,
    /// Human-readable description.
    pub description: String,
}

/// Configuration for sliding window rate analysis.
#[derive(Debug, Clone)]
pub struct WindowConfig {
    /// Window duration.
    pub window: Duration,
    /// Maximum actions within this window before alert.
    pub max_rate: u64,
    /// Name for alerting (e.g., "1min_rate").
    pub name: String,
}

/// Per-agent tracking state.
#[derive(Debug, Default)]
struct AgentMetrics {
    total_actions: u64,
    actions_by_type: HashMap<String, u64>,
    unique_resources: HashSet<String>,
    cumulative_cost: f64,
    first_action_at: Option<DateTime<Utc>>,
    last_action_at: Option<DateTime<Utc>>,
}

/// Per-agent FSM and pattern tracking.
#[derive(Debug)]
struct AgentTracking {
    state: AgentState,
    /// Recent actions for sliding window and pattern detection.
    recent_actions: VecDeque<(DateTime<Utc>, String, String)>,
    /// Which window alerts have fired (to avoid repeats within same window).
    window_alerts_fired: HashMap<String, DateTime<Utc>>,
    /// Pattern alerts fired recently (debounce).
    pattern_alerts_fired: HashMap<String, DateTime<Utc>>,
}

impl Default for AgentTracking {
    fn default() -> Self {
        Self {
            state: AgentState::Idle,
            recent_actions: VecDeque::new(),
            window_alerts_fired: HashMap::new(),
            pattern_alerts_fired: HashMap::new(),
        }
    }
}

/// Serializable monitor state snapshot for persistence.
#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub agent_states: HashMap<Uuid, AgentState>,
    pub agent_action_counts: HashMap<Uuid, u64>,
}

/// The runtime monitor. One per runtime instance.
pub struct RuntimeMonitor {
    metrics: HashMap<Uuid, AgentMetrics>,
    tracking: HashMap<Uuid, AgentTracking>,
    thresholds: MonitorThresholds,
    /// Cost weights per action type. Default is 1.0 for unknown actions.
    action_costs: HashMap<String, f64>,
    alerts: Vec<MonitorAlert>,
    /// Valid state transitions.
    transitions: HashMap<AgentState, Vec<AgentState>>,
    /// Suspicious patterns to detect.
    patterns: Vec<ActionPattern>,
    /// Sliding window configurations.
    windows: Vec<WindowConfig>,
    /// Maximum history per agent (for memory bounding).
    max_history_per_agent: usize,
}

impl RuntimeMonitor {
    pub fn new(thresholds: MonitorThresholds) -> Self {
        Self {
            metrics: HashMap::new(),
            tracking: HashMap::new(),
            thresholds,
            action_costs: HashMap::new(),
            alerts: Vec::new(),
            transitions: valid_transitions(),
            patterns: Vec::new(),
            windows: Vec::new(),
            max_history_per_agent: 10_000,
        }
    }

    /// Set the cost weight for a specific action type.
    pub fn set_action_cost(&mut self, action: impl Into<String>, cost: f64) {
        self.action_costs.insert(action.into(), cost);
    }

    /// Add a suspicious pattern to detect.
    pub fn add_pattern(&mut self, pattern: ActionPattern) {
        self.patterns.push(pattern);
    }

    /// Add a sliding window rate limit.
    pub fn add_window(&mut self, config: WindowConfig) {
        self.windows.push(config);
    }

    /// Transition an agent's FSM state. Returns alerts for invalid transitions.
    pub fn transition_state(&mut self, agent_id: Uuid, new_state: AgentState) -> Vec<MonitorAlert> {
        let now = Utc::now();
        let tracking = self.tracking.entry(agent_id).or_default();
        let old_state = tracking.state;

        let valid = self
            .transitions
            .get(&old_state)
            .map(|targets| targets.contains(&new_state))
            .unwrap_or(false);

        let mut new_alerts = Vec::new();

        if !valid {
            let alert = MonitorAlert {
                agent_id,
                alert_type: "invalid_state_transition".into(),
                details: format!("{} -> {} (not allowed)", old_state, new_state),
                timestamp: now,
            };
            new_alerts.push(alert);
        }

        tracking.state = new_state;

        self.alerts.extend(new_alerts.clone());
        new_alerts
    }

    /// Get an agent's current FSM state.
    pub fn agent_state(&self, agent_id: Uuid) -> AgentState {
        self.tracking
            .get(&agent_id)
            .map(|t| t.state)
            .unwrap_or(AgentState::Idle)
    }

    /// Update thresholds at runtime.
    pub fn update_thresholds(&mut self, thresholds: MonitorThresholds) {
        self.thresholds = thresholds;
    }

    /// Record an action by an agent. Returns any alerts triggered.
    pub fn record_action(
        &mut self,
        agent_id: Uuid,
        action: &str,
        resource: &str,
    ) -> Vec<MonitorAlert> {
        let now = Utc::now();
        let metrics = self.metrics.entry(agent_id).or_default();

        metrics.total_actions += 1;
        *metrics
            .actions_by_type
            .entry(action.to_string())
            .or_insert(0) += 1;
        let is_new_resource = metrics.unique_resources.insert(resource.to_string());

        let cost = self.action_costs.get(action).copied().unwrap_or(1.0);
        metrics.cumulative_cost += cost;

        if metrics.first_action_at.is_none() {
            metrics.first_action_at = Some(now);
        }
        metrics.last_action_at = Some(now);

        // Record in tracking history
        let tracking = self.tracking.entry(agent_id).or_default();
        tracking
            .recent_actions
            .push_back((now, action.to_string(), resource.to_string()));
        while tracking.recent_actions.len() > self.max_history_per_agent {
            tracking.recent_actions.pop_front();
        }

        let mut new_alerts = Vec::new();

        // --- Threshold checks ---
        if metrics.total_actions == self.thresholds.max_actions {
            new_alerts.push(MonitorAlert {
                agent_id,
                alert_type: "max_actions_reached".into(),
                details: format!(
                    "agent reached {} total actions",
                    self.thresholds.max_actions
                ),
                timestamp: now,
            });
        }

        if let Some(&count) = metrics.actions_by_type.get(action) {
            if count == self.thresholds.max_actions_per_type {
                new_alerts.push(MonitorAlert {
                    agent_id,
                    alert_type: "max_actions_per_type_reached".into(),
                    details: format!(
                        "agent reached {} actions of type '{}'",
                        self.thresholds.max_actions_per_type, action
                    ),
                    timestamp: now,
                });
            }
        }

        if is_new_resource
            && metrics.unique_resources.len() as u64 == self.thresholds.max_unique_resources
        {
            new_alerts.push(MonitorAlert {
                agent_id,
                alert_type: "max_unique_resources_reached".into(),
                details: format!(
                    "agent accessed {} unique resources",
                    self.thresholds.max_unique_resources
                ),
                timestamp: now,
            });
        }

        if metrics.cumulative_cost >= self.thresholds.max_cumulative_cost
            && (metrics.cumulative_cost - cost) < self.thresholds.max_cumulative_cost
        {
            new_alerts.push(MonitorAlert {
                agent_id,
                alert_type: "max_cumulative_cost_reached".into(),
                details: format!(
                    "agent cumulative cost {:.1} reached threshold {:.1}",
                    metrics.cumulative_cost, self.thresholds.max_cumulative_cost
                ),
                timestamp: now,
            });
        }

        // --- Sliding window checks ---
        let window_alerts = self.check_windows(agent_id, now);
        new_alerts.extend(window_alerts);

        // --- Pattern detection ---
        let pattern_alerts = self.check_patterns(agent_id, now);
        new_alerts.extend(pattern_alerts);

        self.alerts.extend(new_alerts.clone());
        new_alerts
    }

    /// Check sliding window rate limits.
    fn check_windows(&mut self, agent_id: Uuid, now: DateTime<Utc>) -> Vec<MonitorAlert> {
        let mut alerts = Vec::new();
        let tracking = match self.tracking.get_mut(&agent_id) {
            Some(t) => t,
            None => return alerts,
        };

        for window_config in &self.windows {
            let cutoff = now - window_config.window;
            let count = tracking
                .recent_actions
                .iter()
                .filter(|(ts, _, _)| *ts > cutoff)
                .count() as u64;

            if count > window_config.max_rate {
                // Debounce: only fire once per window
                let should_fire = tracking
                    .window_alerts_fired
                    .get(&window_config.name)
                    .map(|last_fired| now - *last_fired > window_config.window)
                    .unwrap_or(true);

                if should_fire {
                    tracking
                        .window_alerts_fired
                        .insert(window_config.name.clone(), now);
                    alerts.push(MonitorAlert {
                        agent_id,
                        alert_type: format!("rate_spike_{}", window_config.name),
                        details: format!(
                            "{} actions in {}s window (limit: {})",
                            count,
                            window_config.window.num_seconds(),
                            window_config.max_rate,
                        ),
                        timestamp: now,
                    });
                }
            }
        }

        alerts
    }

    /// Check for suspicious action patterns.
    fn check_patterns(&mut self, agent_id: Uuid, now: DateTime<Utc>) -> Vec<MonitorAlert> {
        let mut alerts = Vec::new();
        let tracking = match self.tracking.get_mut(&agent_id) {
            Some(t) => t,
            None => return alerts,
        };

        for pattern in &self.patterns {
            if pattern.actions.is_empty() {
                continue;
            }

            // Search backwards through recent actions for a matching sequence
            let actions: Vec<&(DateTime<Utc>, String, String)> =
                tracking.recent_actions.iter().collect();

            if actions.len() < pattern.actions.len() {
                continue;
            }

            // Try to match the pattern ending at the most recent action
            let last_action = &actions[actions.len() - 1].1;
            if *last_action != pattern.actions[pattern.actions.len() - 1] {
                continue;
            }

            // Walk backwards to find the full sequence
            let mut pattern_idx = pattern.actions.len() - 1;
            let mut first_ts = None;
            let mut matched = false;

            for entry in actions.iter().rev() {
                if entry.1 == pattern.actions[pattern_idx] {
                    if pattern_idx == pattern.actions.len() - 1 {
                        // Last element already matched
                    }
                    if pattern_idx == 0 {
                        first_ts = Some(entry.0);
                        matched = true;
                        break;
                    }
                    pattern_idx -= 1;
                }
            }

            if matched {
                if let Some(first) = first_ts {
                    let elapsed = now - first;
                    if elapsed <= pattern.max_window {
                        // Debounce
                        let should_fire = tracking
                            .pattern_alerts_fired
                            .get(&pattern.alert_type)
                            .map(|last| now - *last > pattern.max_window)
                            .unwrap_or(true);

                        if should_fire {
                            tracking
                                .pattern_alerts_fired
                                .insert(pattern.alert_type.clone(), now);
                            alerts.push(MonitorAlert {
                                agent_id,
                                alert_type: pattern.alert_type.clone(),
                                details: pattern.description.clone(),
                                timestamp: now,
                            });
                        }
                    }
                }
            }
        }

        alerts
    }

    /// Check if an agent has exceeded any limit (for use in enforcement decisions).
    pub fn is_over_limit(&self, agent_id: Uuid) -> Result<(), MoatError> {
        if let Some(metrics) = self.metrics.get(&agent_id) {
            if metrics.total_actions > self.thresholds.max_actions {
                return Err(MoatError::ResourceLimitExceeded {
                    resource: "total_actions".into(),
                    limit: self.thresholds.max_actions,
                    current: metrics.total_actions,
                });
            }
            if metrics.cumulative_cost > self.thresholds.max_cumulative_cost {
                return Err(MoatError::TrajectoryAlert(format!(
                    "cumulative cost {:.1} exceeds {:.1}",
                    metrics.cumulative_cost, self.thresholds.max_cumulative_cost
                )));
            }
        }
        Ok(())
    }

    /// Take a serializable snapshot of monitor state.
    pub fn snapshot(&self) -> MonitorSnapshot {
        let agent_states = self.tracking.iter().map(|(id, t)| (*id, t.state)).collect();
        let agent_action_counts = self
            .metrics
            .iter()
            .map(|(id, m)| (*id, m.total_actions))
            .collect();
        MonitorSnapshot {
            agent_states,
            agent_action_counts,
        }
    }

    pub fn alerts(&self) -> &[MonitorAlert] {
        &self.alerts
    }

    pub fn agent_action_count(&self, agent_id: Uuid) -> u64 {
        self.metrics
            .get(&agent_id)
            .map(|m| m.total_actions)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_tracking() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        monitor.record_action(agent, "execute", "tool://test");
        assert_eq!(monitor.agent_action_count(agent), 1);
        assert!(monitor.is_over_limit(agent).is_ok());
    }

    #[test]
    fn alert_on_max_actions() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds {
            max_actions: 3,
            ..Default::default()
        });
        let agent = Uuid::new_v4();

        let a1 = monitor.record_action(agent, "execute", "tool://a");
        assert!(a1.is_empty());
        let a2 = monitor.record_action(agent, "read", "tool://b");
        assert!(a2.is_empty());
        let a3 = monitor.record_action(agent, "write", "tool://c");
        assert_eq!(a3.len(), 1);
        assert_eq!(a3[0].alert_type, "max_actions_reached");
    }

    #[test]
    fn alert_on_action_type_threshold() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds {
            max_actions_per_type: 2,
            ..Default::default()
        });
        let agent = Uuid::new_v4();

        monitor.record_action(agent, "execute", "tool://a");
        let alerts = monitor.record_action(agent, "execute", "tool://b");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, "max_actions_per_type_reached");
    }

    #[test]
    fn cumulative_cost_tracking() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds {
            max_cumulative_cost: 10.0,
            ..Default::default()
        });
        let agent = Uuid::new_v4();
        monitor.set_action_cost("dangerous", 5.0);

        monitor.record_action(agent, "dangerous", "tool://a"); // cost: 5
        let alerts = monitor.record_action(agent, "dangerous", "tool://b"); // cost: 10
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, "max_cumulative_cost_reached");
    }

    #[test]
    fn is_over_limit_after_exceeding() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds {
            max_actions: 2,
            ..Default::default()
        });
        let agent = Uuid::new_v4();

        monitor.record_action(agent, "a", "r");
        monitor.record_action(agent, "b", "r");
        assert!(monitor.is_over_limit(agent).is_ok()); // at limit, not over

        monitor.record_action(agent, "c", "r");
        assert!(monitor.is_over_limit(agent).is_err()); // over limit
    }

    #[test]
    fn unique_resource_alert() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds {
            max_unique_resources: 3,
            ..Default::default()
        });
        let agent = Uuid::new_v4();

        monitor.record_action(agent, "read", "resource_1");
        monitor.record_action(agent, "read", "resource_2");
        let alerts = monitor.record_action(agent, "read", "resource_3");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, "max_unique_resources_reached");

        // Same resource again doesn't re-trigger
        let alerts = monitor.record_action(agent, "read", "resource_3");
        assert!(alerts.is_empty());
    }

    // --- FSM tests ---

    #[test]
    fn valid_state_transition() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        assert_eq!(monitor.agent_state(agent), AgentState::Idle);

        let alerts = monitor.transition_state(agent, AgentState::Executing);
        assert!(alerts.is_empty());
        assert_eq!(monitor.agent_state(agent), AgentState::Executing);

        let alerts = monitor.transition_state(agent, AgentState::RequestingSecret);
        assert!(alerts.is_empty());
        assert_eq!(monitor.agent_state(agent), AgentState::RequestingSecret);
    }

    #[test]
    fn invalid_state_transition_alerts() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        // Idle -> RequestingSecret is NOT valid
        let alerts = monitor.transition_state(agent, AgentState::RequestingSecret);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, "invalid_state_transition");
        assert!(alerts[0].details.contains("idle -> requesting_secret"));
    }

    #[test]
    fn terminated_state_blocks_all_transitions() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        monitor.transition_state(agent, AgentState::Executing);
        monitor.transition_state(agent, AgentState::Terminated);

        let alerts = monitor.transition_state(agent, AgentState::Idle);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, "invalid_state_transition");
    }

    // --- Sliding window tests ---

    #[test]
    fn sliding_window_rate_alert() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        monitor.add_window(WindowConfig {
            window: Duration::minutes(1),
            max_rate: 3,
            name: "1min".into(),
        });

        monitor.record_action(agent, "a", "r1");
        monitor.record_action(agent, "b", "r2");
        monitor.record_action(agent, "c", "r3");
        let alerts = monitor.record_action(agent, "d", "r4"); // 4 > 3
        assert!(
            alerts.iter().any(|a| a.alert_type == "rate_spike_1min"),
            "expected rate spike alert, got: {:?}",
            alerts
        );
    }

    // --- Pattern detection tests ---

    #[test]
    fn pattern_detection() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        monitor.add_pattern(ActionPattern {
            actions: vec!["read_secret".into(), "network_request".into()],
            max_window: Duration::seconds(30),
            alert_type: "secret_exfiltration".into(),
            description: "secret read followed by network request".into(),
        });

        // First action: read_secret
        let alerts = monitor.record_action(agent, "read_secret", "secret://api_key");
        assert!(alerts.is_empty());

        // Second action: network_request -- should match pattern
        let alerts = monitor.record_action(agent, "network_request", "https://evil.com");
        assert!(
            alerts.iter().any(|a| a.alert_type == "secret_exfiltration"),
            "expected secret_exfiltration alert, got: {:?}",
            alerts
        );
    }

    #[test]
    fn pattern_not_matched_outside_window() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        monitor.add_pattern(ActionPattern {
            actions: vec!["read_secret".into(), "network_request".into()],
            max_window: Duration::seconds(0), // zero-second window = impossible to match
            alert_type: "secret_exfiltration".into(),
            description: "test".into(),
        });

        monitor.record_action(agent, "read_secret", "secret://key");
        let alerts = monitor.record_action(agent, "network_request", "https://evil.com");
        // Should NOT match because window is 0 seconds
        assert!(
            !alerts.iter().any(|a| a.alert_type == "secret_exfiltration"),
            "should not match with 0s window"
        );
    }

    // --- Snapshot test ---

    #[test]
    fn monitor_snapshot() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds::default());
        let agent = Uuid::new_v4();

        monitor.transition_state(agent, AgentState::Executing);
        monitor.record_action(agent, "execute", "tool://a");
        monitor.record_action(agent, "execute", "tool://b");

        let snap = monitor.snapshot();
        assert_eq!(snap.agent_states.get(&agent), Some(&AgentState::Executing));
        assert_eq!(snap.agent_action_counts.get(&agent), Some(&2));

        // Verify serializable
        let json = serde_json::to_string(&snap).unwrap();
        let restored: MonitorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.agent_states.get(&agent),
            Some(&AgentState::Executing)
        );
    }

    // --- Runtime reconfiguration test ---

    #[test]
    fn update_thresholds_at_runtime() {
        let mut monitor = RuntimeMonitor::new(MonitorThresholds {
            max_actions: 100,
            ..Default::default()
        });
        let agent = Uuid::new_v4();

        monitor.record_action(agent, "a", "r");
        monitor.record_action(agent, "b", "r");

        // Tighten the limit
        monitor.update_thresholds(MonitorThresholds {
            max_actions: 3,
            ..Default::default()
        });

        // Third action should trigger alert with new limit
        let alerts = monitor.record_action(agent, "c", "r");
        assert!(
            alerts.iter().any(|a| a.alert_type == "max_actions_reached"),
            "expected alert after threshold tightening"
        );
    }
}
