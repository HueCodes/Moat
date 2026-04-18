//! `moat demo` — a scripted, visually satisfying multi-agent scenario that
//! exercises delegation, scope enforcement, and audit-log integrity in one run.
//!
//! Designed to be the thing you record for the asciinema clip that goes next
//! to the README and in the launch tweet.

use chrono::{Duration, Utc};
use serde::Serialize;

use moat_protocol::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, Moat, PolicyBinding, ResourceLimits,
    ScopeEntry,
};
use moat_runtime::MonitorThresholds;

use crate::style::{arrow, bold, check, cross, cyan, dim, green, magenta, red, yellow};

#[derive(Serialize)]
struct DemoReport {
    allowed: u32,
    denied: u32,
    anomalies: u32,
    audit_entries: usize,
    audit_integrity: bool,
    steps: Vec<StepReport>,
}

#[derive(Serialize)]
struct StepReport {
    agent: String,
    resource: String,
    action: String,
    allowed: bool,
    stage_failed: Option<String>,
    reason: Option<String>,
}

pub fn run(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !json {
        header();
    }

    // --- Setup ---
    let coordinator = AgentKeypair::generate("coordinator")?;
    let reviewer = AgentKeypair::generate("reviewer")?;
    let tester = AgentKeypair::generate("tester")?;
    let deployer = AgentKeypair::generate("deployer")?;

    let policy = PolicyBinding::new("demo-v1", b"moat demo policy");
    let mut moat = Moat::builder()
        .policy(policy.clone())
        .monitor_thresholds(MonitorThresholds::default())
        .agent(coordinator.identity.clone())
        .agent(reviewer.identity.clone())
        .agent(tester.identity.clone())
        .agent(deployer.identity.clone())
        .trust_root(coordinator.id())
        .build()?;

    if !json {
        section("Runtime");
        line(format!("{} policy         {}", check(), dim("demo-v1")));
        line(format!("{} agents         {}", check(), dim("coordinator, reviewer, tester, deployer")));
        line(format!("{} trusted root   {}", check(), cyan("coordinator")));
    }

    // --- Tokens ---
    let mut coord_token = CapabilityToken::root(
        coordinator.id(),
        coordinator.id(),
        Utc::now() + Duration::hours(1),
    );
    coord_token.allowed = vec![
        ScopeEntry {
            resource: "tool://code_review".into(),
            actions: vec!["read".into(), "execute".into()],
        },
        ScopeEntry {
            resource: "tool://test".into(),
            actions: vec!["execute".into()],
        },
        ScopeEntry {
            resource: "tool://deploy".into(),
            actions: vec!["execute".into()],
        },
    ];
    coord_token.resource_limits = ResourceLimits {
        max_fuel: Some(10_000_000),
        max_memory_bytes: Some(128 * 1024 * 1024),
        ..Default::default()
    };
    coord_token.sign(&coordinator);

    let mut reviewer_token = coord_token.attenuate(
        reviewer.id(),
        vec![ScopeEntry {
            resource: "tool://code_review".into(),
            actions: vec!["read".into()],
        }],
        vec![],
        ResourceLimits {
            max_fuel: Some(1_000_000),
            max_memory_bytes: Some(32 * 1024 * 1024),
            ..Default::default()
        },
        10,
    )?;
    reviewer_token.sign(&coordinator);

    let mut tester_token = coord_token.attenuate(
        tester.id(),
        vec![ScopeEntry {
            resource: "tool://test".into(),
            actions: vec!["execute".into()],
        }],
        vec![],
        ResourceLimits {
            max_fuel: Some(5_000_000),
            max_memory_bytes: Some(64 * 1024 * 1024),
            ..Default::default()
        },
        10,
    )?;
    tester_token.sign(&coordinator);

    let mut deployer_token = coord_token.attenuate(
        deployer.id(),
        vec![ScopeEntry {
            resource: "tool://deploy".into(),
            actions: vec!["execute".into()],
        }],
        vec![],
        ResourceLimits {
            max_fuel: Some(2_000_000),
            max_memory_bytes: Some(32 * 1024 * 1024),
            ..Default::default()
        },
        10,
    )?;
    deployer_token.sign(&coordinator);

    if !json {
        section("Capability tokens");
        line(format!(
            "{} {:<10} {}  {}",
            check(),
            "reviewer",
            arrow(),
            dim("read on tool://code_review")
        ));
        line(format!(
            "{} {:<10} {}  {}",
            check(),
            "tester",
            arrow(),
            dim("execute on tool://test")
        ));
        line(format!(
            "{} {:<10} {}  {}",
            check(),
            "deployer",
            arrow(),
            dim("execute on tool://deploy")
        ));
        line(format!(
            "{} {}",
            dim("monotonic attenuation: each child ⊆ parent"),
            magenta("(enforced by construction)")
        ));
    }

    // --- Happy-path pipeline ---
    let mut steps = Vec::new();
    let mut allowed = 0u32;
    let mut denied = 0u32;
    let mut anomalies = 0u32;

    if !json {
        section("Pipeline");
    }

    for (seq, (agent_name, agent, tok, resource, action)) in [
        (
            "reviewer",
            &reviewer,
            &reviewer_token,
            "tool://code_review",
            "read",
        ),
        ("tester", &tester, &tester_token, "tool://test", "execute"),
        (
            "deployer",
            &deployer,
            &deployer_token,
            "tool://deploy",
            "execute",
        ),
    ]
    .iter()
    .enumerate()
    {
        let msg = AuthenticatedMessage::create(
            agent,
            coordinator.id(),
            format!("{agent_name} payload").into_bytes(),
            (*tok).clone(),
            vec![coord_token.clone()],
            policy.clone(),
            (seq + 1) as u64,
        )?;
        let result = moat.route(&msg, resource, action)?;
        anomalies += result.alerts.len() as u32;
        if result.allowed {
            allowed += 1;
            if !json {
                line(format!(
                    "{} {:<10} {} {:<6} on {:<22} {}",
                    check(),
                    agent_name,
                    arrow(),
                    action,
                    resource,
                    green("ALLOWED")
                ));
            }
        } else {
            denied += 1;
            if !json {
                line(format!(
                    "{} {:<10} {} {:<6} on {:<22} {}",
                    cross(),
                    agent_name,
                    arrow(),
                    action,
                    resource,
                    red("DENIED")
                ));
            }
        }
        steps.push(StepReport {
            agent: (*agent_name).to_string(),
            resource: (*resource).to_string(),
            action: (*action).to_string(),
            allowed: result.allowed,
            stage_failed: None,
            reason: None,
        });
    }

    // --- Expected denials: scope enforcement ---
    if !json {
        section("Scope enforcement (expected denials)");
    }

    let denial_cases = [
        (
            "reviewer",
            &reviewer,
            &reviewer_token,
            "tool://code_review",
            "execute",
            "action outside attenuated scope",
        ),
        (
            "tester",
            &tester,
            &tester_token,
            "tool://deploy",
            "execute",
            "resource not in token",
        ),
        (
            "deployer",
            &deployer,
            &deployer_token,
            "tool://code_review",
            "read",
            "resource not in token",
        ),
    ];

    for (seq, (agent_name, agent, tok, resource, action, why)) in denial_cases.iter().enumerate() {
        let msg = AuthenticatedMessage::create(
            agent,
            coordinator.id(),
            b"escape attempt".to_vec(),
            (*tok).clone(),
            vec![coord_token.clone()],
            policy.clone(),
            (seq + 10) as u64, // fresh seq space so we don't collide with happy path
        )?;
        let result = moat.route(&msg, resource, action)?;
        if result.allowed {
            allowed += 1;
            if !json {
                line(format!(
                    "{} {:<10} {} {} — {}",
                    cross(),
                    agent_name,
                    arrow(),
                    red("UNEXPECTEDLY ALLOWED"),
                    yellow(why)
                ));
            }
        } else {
            denied += 1;
            if !json {
                line(format!(
                    "{} {:<10} {} {:<6} on {:<22} {}  {}",
                    check(),
                    agent_name,
                    arrow(),
                    action,
                    resource,
                    red("DENIED"),
                    dim(why)
                ));
            }
        }
        steps.push(StepReport {
            agent: (*agent_name).to_string(),
            resource: (*resource).to_string(),
            action: (*action).to_string(),
            allowed: result.allowed,
            stage_failed: None,
            reason: Some((*why).to_string()),
        });
    }

    // --- Audit integrity ---
    let audit = moat.audit_log();
    let integrity_ok = audit.verify_integrity().is_ok();
    if !json {
        section("Audit log");
        if integrity_ok {
            line(format!(
                "{} {} entries, SHA-256 hash chain verified",
                check(),
                audit.len()
            ));
        } else {
            line(format!("{} hash chain BROKEN", cross()));
        }
    }

    if json {
        let report = DemoReport {
            allowed,
            denied,
            anomalies,
            audit_entries: audit.len(),
            audit_integrity: integrity_ok,
            steps,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!();
        println!(
            "{}  {} allowed   {} denied   {} anomalies   {} audit entries",
            bold("Summary"),
            green(&format!("{allowed}")),
            red(&format!("{denied}")),
            yellow(&format!("{anomalies}")),
            cyan(&format!("{}", audit.len())),
        );
        if integrity_ok && allowed == 3 && denied == 3 && anomalies == 0 {
            println!("{}", green("All security invariants held."));
        } else {
            println!("{}", red("Security invariants NOT fully held — inspect audit log."));
        }
    }
    Ok(())
}

fn header() {
    println!();
    println!("{}", bold("Moat Demo — multi-agent delegation with capability attenuation"));
    println!("{}", dim("coordinator → reviewer / tester / deployer, plus three escape attempts"));
    println!();
}

fn section(title: &str) {
    println!();
    println!("{} {}", cyan("▸"), bold(title));
}

fn line(s: String) {
    println!("  {s}");
}
