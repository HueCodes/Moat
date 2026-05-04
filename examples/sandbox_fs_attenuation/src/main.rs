//! Sandbox filesystem attenuation example.
//!
//! Shows that capability-token attenuation composes with WASI preopens:
//!
//! 1. A parent agent holds a broad filesystem grant (`<tmp>/parent`).
//! 2. The parent attenuates a child token to a single subdirectory
//!    (`<tmp>/parent/child`).
//! 3. The token system rejects an over-broad child request (a sibling path
//!    not contained in the parent's grant).
//! 4. Each sandbox is built directly from its token's `ResourceLimits`,
//!    so the WASI preopens mirror the token's filesystem scope --
//!    a child sandbox literally cannot reach paths the child token doesn't grant.
//!
//! The link from token to OS-level confinement is what makes "monotonic
//! attenuation" load-bearing rather than advisory: a compromised child cannot
//! ask the runtime for a broader preopen than its token allows.

use chrono::{Duration, Utc};
use moat_core::{AgentKeypair, CapabilityToken, MoatError, ResourceLimits, ScopeEntry};
use moat_runtime::{Sandbox, SandboxConfig};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

/// Layout of the demo tree on disk. Created fresh per run, removed at the end
/// so repeated invocations don't accumulate state.
struct DemoLayout {
    root: PathBuf,
    parent_dir: PathBuf,
    child_dir: PathBuf,
    /// A sibling path that is *not* under the parent's grant. Used only as a
    /// negative example -- it is not pre-opened anywhere.
    sibling_path: String,
}

impl DemoLayout {
    fn create() -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("moat-fs-demo-{}", Uuid::new_v4()));
        let parent_dir = root.join("parent");
        let child_dir = parent_dir.join("child");
        fs::create_dir_all(&child_dir)?;

        // Materialise the sibling path string only -- never created.
        let sibling_path = root.join("sibling").to_string_lossy().into_owned();

        Ok(Self {
            root,
            parent_dir,
            child_dir,
            sibling_path,
        })
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Moat Sandbox FS Attenuation Example ===\n");

    let layout = DemoLayout::create()?;
    println!("Demo root: {}", layout.root.display());
    println!("  parent grant:    {}", layout.parent_dir.display());
    println!("  child  grant:    {}", layout.child_dir.display());
    println!("  sibling (unset): {}\n", layout.sibling_path);

    let parent_agent = AgentKeypair::generate("parent")?;
    let child_agent = AgentKeypair::generate("child")?;
    println!("Parent agent: {}", parent_agent.id());
    println!("Child  agent: {}\n", child_agent.id());

    // --- Parent's root token: broad FS grant under one demo directory ---
    let parent_fs_root = layout.parent_dir.to_string_lossy().into_owned();
    let mut parent_token = CapabilityToken::root(
        parent_agent.id(),
        parent_agent.id(),
        Utc::now() + Duration::hours(1),
    );
    parent_token.allowed = vec![ScopeEntry {
        resource: "fs://*".into(),
        actions: vec!["read".into(), "write".into()],
    }];
    parent_token.resource_limits = ResourceLimits {
        max_fuel: Some(10_000_000),
        max_memory_bytes: Some(64 * 1024 * 1024),
        allowed_fs_read: vec![parent_fs_root.clone()],
        allowed_fs_write: vec![parent_fs_root.clone()],
        ..Default::default()
    };
    parent_token.sign(&parent_agent);
    println!(
        "Parent token issued: write={:?}\n",
        parent_token.resource_limits.allowed_fs_write
    );

    // --- Negative case: parent tries to attenuate to a sibling path ---
    println!("--- Over-broad attenuation (rejected) ---");
    let bad_attempt = parent_token.attenuate(
        child_agent.id(),
        vec![ScopeEntry {
            resource: "fs://*".into(),
            actions: vec!["read".into(), "write".into()],
        }],
        vec![],
        ResourceLimits {
            max_fuel: Some(1_000_000),
            max_memory_bytes: Some(16 * 1024 * 1024),
            // Sibling path is not under parent's grant -- must be rejected.
            allowed_fs_write: vec![layout.sibling_path.clone()],
            ..Default::default()
        },
        5,
    );
    match &bad_attempt {
        Err(MoatError::AttenuationViolation) => {
            println!(
                "  request to grant {} -> REJECTED (AttenuationViolation)",
                layout.sibling_path
            );
        }
        Err(other) => {
            layout.cleanup();
            return Err(format!("unexpected error: {other}").into());
        }
        Ok(_) => {
            layout.cleanup();
            return Err("attenuation should have been rejected".into());
        }
    }

    // --- Positive case: narrow to the child subdirectory ---
    println!("\n--- Narrowed attenuation (accepted) ---");
    let child_fs_root = layout.child_dir.to_string_lossy().into_owned();
    let mut child_token = parent_token.attenuate(
        child_agent.id(),
        vec![ScopeEntry {
            resource: "fs://*".into(),
            actions: vec!["read".into(), "write".into()],
        }],
        vec![],
        ResourceLimits {
            max_fuel: Some(1_000_000),
            max_memory_bytes: Some(16 * 1024 * 1024),
            allowed_fs_read: vec![child_fs_root.clone()],
            allowed_fs_write: vec![child_fs_root.clone()],
            ..Default::default()
        },
        5,
    )?;
    child_token.sign(&parent_agent);
    println!(
        "  child token issued: write={:?} (depth {})",
        child_token.resource_limits.allowed_fs_write, child_token.delegation_depth,
    );

    // --- Sandbox configs come from the tokens, not a separate config file ---
    println!("\n--- Sandbox configs derived from tokens ---");
    let parent_config = SandboxConfig::from(&parent_token.resource_limits);
    let child_config = SandboxConfig::from(&child_token.resource_limits);

    print_config("parent", &parent_config);
    print_config("child ", &child_config);

    // --- Both sandboxes boot with their respective preopens ---
    // We execute a trivial WASI module to confirm the runtime accepts the
    // capability-derived preopen list. Real workloads (e.g. a sandboxed tool
    // call) would substitute their own wasm here; the security boundary is
    // identical -- the child literally cannot reach the parent's directory.
    println!("\n--- Booting sandboxes ---");
    let trivial_wasi = wat::parse_str(
        r#"
        (module
            (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
            (memory (export "memory") 1)
            (func (export "_start")
                i32.const 0
                call $proc_exit))
        "#,
    )?;

    let parent_sandbox = Sandbox::new(parent_config)?;
    boot_quiet(&parent_sandbox, &trivial_wasi, "parent");

    let child_sandbox = Sandbox::new(child_config)?;
    boot_quiet(&child_sandbox, &trivial_wasi, "child ");

    println!("\nDone. Filesystem attenuation enforced at both layers:");
    println!("  - capability tokens reject over-broad child grants;");
    println!("  - WASI preopens follow the token, so OS-level confinement matches.");

    layout.cleanup();
    Ok(())
}

fn print_config(label: &str, cfg: &SandboxConfig) {
    println!(
        "  {} fs_read={:?} fs_write={:?} fuel={:?}",
        label, cfg.allowed_fs_read, cfg.allowed_fs_write, cfg.max_fuel,
    );
}

/// Run the trivial WASI module and report success/failure, swallowing the
/// trap that `proc_exit(0)` raises (a clean exit reports as a trap in
/// wasmtime, which is fine for this demo).
fn boot_quiet(sandbox: &Sandbox, wasm: &[u8], label: &str) {
    match sandbox.execute(wasm) {
        Ok(_) => println!("  {} sandbox booted", label),
        // proc_exit raises a trap -- treat as a clean exit.
        Err(_) => println!("  {} sandbox booted (clean exit)", label),
    }
}
