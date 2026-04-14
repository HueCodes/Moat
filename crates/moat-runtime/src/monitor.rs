//! Runtime monitor: tracks agent behavior for anomaly detection.
//!
//! Counts actions, tracks durations, and watches resource consumption per agent.
//! Detects "individually benign, collectively dangerous" patterns by monitoring
//! cumulative trajectories against configurable thresholds.
//!
//! This is the MVP counter-based approach. Full MDP-based probabilistic
//! assurance (AgentGuard-style) is future work.

use std::collections::HashMap;
use chrono::{DateTime, Utc};
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

use std::collections::HashSet;

/// The runtime monitor. One per runtime instance.
pub struct RuntimeMonitor {
    metrics: HashMap<Uuid, AgentMetrics>,
    thresholds: MonitorThresholds,
    /// Cost weights per action type. Default is 1.0 for unknown actions.
    action_costs: HashMap<String, f64>,
    alerts: Vec<MonitorAlert>,
}

impl RuntimeMonitor {
    pub fn new(thresholds: MonitorThresholds) -> Self {
        Self {
            metrics: HashMap::new(),
            thresholds,
            action_costs: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Set the cost weight for a specific action type.
    pub fn set_action_cost(&mut self, action: impl Into<String>, cost: f64) {
        self.action_costs.insert(action.into(), cost);
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
        *metrics.actions_by_type.entry(action.to_string()).or_insert(0) += 1;
        let is_new_resource = metrics.unique_resources.insert(resource.to_string());

        let cost = self.action_costs.get(action).copied().unwrap_or(1.0);
        metrics.cumulative_cost += cost;

        if metrics.first_action_at.is_none() {
            metrics.first_action_at = Some(now);
        }
        metrics.last_action_at = Some(now);

        let mut new_alerts = Vec::new();

        // Check thresholds
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

        // Use >= for cost since it's floating point and we accumulate
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

        self.alerts.extend(new_alerts.clone());
        new_alerts
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
}
