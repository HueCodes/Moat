//! Moat CLI.
//!
//! Subcommands:
//! - `moat identity generate|show` — manage agent keypairs
//! - `moat token create|attenuate|verify` — issue and verify capability tokens
//! - `moat audit verify` — verify the SHA-256 hash chain of an audit log
//! - `moat demo` — run a scripted multi-agent delegation scenario

mod demo;
mod style;

use std::path::{Path, PathBuf};

use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use moat_core::{AgentIdentity, AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry};
use moat_runtime::AuditLog;
use serde::Serialize;

use crate::style::{bold, check, cross, cyan, dim, red};

#[derive(Parser)]
#[command(
    name = "moat",
    about = "Moat — the missing security layer for AI agents.",
    long_about = "Moat CLI. Generate identities, issue and attenuate capability tokens, \
                  verify audit logs, and run a scripted multi-agent demo.",
    version
)]
struct Cli {
    /// Emit structured JSON output instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage agent identities (Ed25519 keypairs).
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Manage capability tokens (create, attenuate, verify).
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Audit log operations.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Run a scripted multi-agent demo scenario (good for asciinema).
    Demo,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new agent keypair.
    Generate {
        /// Human-readable name for the agent.
        #[arg(long)]
        name: String,
        /// Output path for the keypair file (JSON).
        #[arg(long, default_value = "agent.key")]
        output: PathBuf,
    },
    /// Display the public identity from a keypair file.
    Show {
        /// Path to the keypair file.
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Create and sign a root capability token.
    Create {
        /// Path to the issuer's keypair file.
        #[arg(long)]
        issuer: PathBuf,
        /// Subject agent ID (UUID).
        #[arg(long)]
        subject: uuid::Uuid,
        /// Scope entries as `resource=action,action` (repeatable, semicolon-separated).
        #[arg(long, value_delimiter = ';')]
        scope: Vec<String>,
        /// Token lifetime (e.g. `1h`, `30m`, `7d`).
        #[arg(long, default_value = "1h")]
        expires: String,
        /// Maximum fuel (wasmtime units).
        #[arg(long)]
        max_fuel: Option<u64>,
        /// Maximum memory in bytes.
        #[arg(long)]
        max_memory: Option<u64>,
        /// Output path for the token file (JSON).
        #[arg(long, default_value = "token.json")]
        output: PathBuf,
    },
    /// Attenuate (restrict) an existing token.
    Attenuate {
        /// Path to the parent token file.
        #[arg(long)]
        parent: PathBuf,
        /// Path to the delegator's keypair file (must match parent's subject).
        #[arg(long)]
        signer: PathBuf,
        /// New subject agent ID (UUID).
        #[arg(long)]
        subject: uuid::Uuid,
        /// Narrowed scope entries as `resource=action,action` (repeatable).
        #[arg(long, value_delimiter = ';')]
        scope: Vec<String>,
        /// Maximum delegation depth.
        #[arg(long, default_value_t = 10)]
        max_depth: u32,
        /// Output path.
        #[arg(long, default_value = "attenuated_token.json")]
        output: PathBuf,
    },
    /// Verify a token's signature.
    Verify {
        /// Path to the token file.
        #[arg(long)]
        token: PathBuf,
        /// Path to the issuer's identity (public) or keypair file.
        #[arg(long)]
        identity: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Verify the integrity of an audit log file.
    Verify {
        /// Path to the audit log file (JSONL).
        path: PathBuf,
    },
}

#[derive(Serialize)]
struct KeypairFile {
    id: uuid::Uuid,
    name: String,
    public_key: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct KeypairFileIn {
    id: uuid::Uuid,
    name: String,
    public_key: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityFile {
    id: uuid::Uuid,
    name: String,
    public_key: Vec<u8>,
}

fn save_keypair(kp: &AgentKeypair, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key_bytes = kp.signing_key_bytes();
    let file = KeypairFile {
        id: kp.id(),
        name: kp.identity.name.clone(),
        public_key: kp.identity.public_key.clone(),
        signing_key: signing_key_bytes.to_vec(),
    };
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn load_keypair(path: &PathBuf) -> Result<AgentKeypair, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let file: KeypairFileIn = serde_json::from_str(&data)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        file.signing_key
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signing key length")?,
    );
    let identity = AgentIdentity {
        id: file.id,
        name: file.name,
        public_key: file.public_key,
        attestations: Vec::new(),
        created_at: Utc::now(),
    };
    Ok(AgentKeypair::from_parts(identity, signing_key))
}

/// Parse scope entries in the format `resource=action1,action2`.
fn parse_scope(scope_strs: &[String]) -> Vec<ScopeEntry> {
    scope_strs
        .iter()
        .filter_map(|s| {
            if let Some((resource, actions_str)) = s.rsplit_once('=') {
                let actions: Vec<String> = actions_str
                    .split(',')
                    .map(|a| a.trim().to_string())
                    .collect();
                Some(ScopeEntry {
                    resource: resource.to_string(),
                    actions,
                })
            } else {
                eprintln!(
                    "{} malformed scope entry (expected `resource=action,...`): {}",
                    cross(),
                    s
                );
                None
            }
        })
        .collect()
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h') {
        h.parse::<i64>()
            .map(Duration::hours)
            .map_err(|e| e.to_string())
    } else if let Some(m) = s.strip_suffix('m') {
        m.parse::<i64>()
            .map(Duration::minutes)
            .map_err(|e| e.to_string())
    } else if let Some(d) = s.strip_suffix('d') {
        d.parse::<i64>()
            .map(Duration::days)
            .map_err(|e| e.to_string())
    } else {
        s.parse::<i64>()
            .map(Duration::hours)
            .map_err(|e| e.to_string())
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.json {
        style::disable_colors();
    }

    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Commands::Identity { action } => match action {
            IdentityAction::Generate { name, output } => {
                cmd_identity_generate(&name, &output, cli.json)
            }
            IdentityAction::Show { path } => cmd_identity_show(&path, cli.json),
        },
        Commands::Token { action } => match action {
            TokenAction::Create {
                issuer,
                subject,
                scope,
                expires,
                max_fuel,
                max_memory,
                output,
            } => cmd_token_create(
                &issuer, subject, &scope, &expires, max_fuel, max_memory, &output, cli.json,
            ),
            TokenAction::Attenuate {
                parent,
                signer,
                subject,
                scope,
                max_depth,
                output,
            } => cmd_token_attenuate(
                &parent, &signer, subject, &scope, max_depth, &output, cli.json,
            ),
            TokenAction::Verify { token, identity } => {
                cmd_token_verify(&token, &identity, cli.json)
            }
        },
        Commands::Audit { action } => match action {
            AuditAction::Verify { path } => cmd_audit_verify(&path, cli.json),
        },
        Commands::Demo => demo::run(cli.json),
    };

    if let Err(e) = result {
        if cli.json {
            let err = serde_json::json!({ "error": e.to_string() });
            eprintln!("{err}");
        } else {
            eprintln!("{} {}", cross(), red(&e.to_string()));
        }
        std::process::exit(1);
    }
}

fn cmd_identity_generate(
    name: &str,
    output: &PathBuf,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let kp = AgentKeypair::generate(name)?;
    save_keypair(&kp, output)?;
    if json {
        let v = serde_json::json!({
            "id": kp.id().to_string(),
            "name": name,
            "output": output.display().to_string(),
            "public_key": hex_encode(&kp.identity.public_key),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{} identity generated", check());
        println!("  {}  {}", dim("id    "), kp.id());
        println!("  {}  {}", dim("name  "), name);
        println!("  {}  {}", dim("saved "), output.display());
    }
    Ok(())
}

fn cmd_identity_show(path: &PathBuf, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let kp = load_keypair(path)?;
    if json {
        let v = serde_json::json!({
            "id": kp.id().to_string(),
            "name": kp.identity.name,
            "public_key": hex_encode(&kp.identity.public_key),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{} identity", bold(""));
        println!("  {}  {}", dim("id        "), kp.id());
        println!("  {}  {}", dim("name      "), kp.identity.name);
        println!(
            "  {}  {}",
            dim("public_key"),
            cyan(&hex_encode(&kp.identity.public_key))
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_token_create(
    issuer_path: &PathBuf,
    subject: uuid::Uuid,
    scope: &[String],
    expires: &str,
    max_fuel: Option<u64>,
    max_memory: Option<u64>,
    output: &PathBuf,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = load_keypair(issuer_path)?;
    let duration = parse_duration(expires)?;
    let expires_at = Utc::now() + duration;

    let mut token = CapabilityToken::root(issuer.id(), subject, expires_at);
    token.allowed = parse_scope(scope);
    token.resource_limits = ResourceLimits {
        max_fuel,
        max_memory_bytes: max_memory,
        ..Default::default()
    };
    token.sign(&issuer);

    let token_json = serde_json::to_string_pretty(&token)?;
    std::fs::write(output, token_json)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "token_id": token.token_id.to_string(),
                "issuer": issuer.id().to_string(),
                "subject": subject.to_string(),
                "expires_at": expires_at.to_rfc3339(),
                "output": output.display().to_string(),
            }))?
        );
    } else {
        println!("{} token created", check());
        println!("  {}  {}", dim("token_id"), token.token_id);
        println!("  {}  {}", dim("issuer  "), issuer.id());
        println!("  {}  {}", dim("subject "), subject);
        println!("  {}  {}", dim("expires "), expires_at);
        println!("  {}  {}", dim("saved   "), output.display());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_token_attenuate(
    parent_path: &PathBuf,
    signer_path: &PathBuf,
    subject: uuid::Uuid,
    scope: &[String],
    max_depth: u32,
    output: &PathBuf,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent_json = std::fs::read_to_string(parent_path)?;
    let parent: CapabilityToken = serde_json::from_str(&parent_json)?;
    let signer = load_keypair(signer_path)?;

    let allowed = parse_scope(scope);
    let mut child = parent.attenuate(
        subject,
        allowed,
        vec![],
        parent.resource_limits.clone(),
        max_depth,
    )?;
    child.sign(&signer);

    let child_json = serde_json::to_string_pretty(&child)?;
    std::fs::write(output, child_json)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "token_id": child.token_id.to_string(),
                "parent_id": parent.token_id.to_string(),
                "subject": subject.to_string(),
                "delegation_depth": child.delegation_depth,
                "output": output.display().to_string(),
            }))?
        );
    } else {
        println!("{} attenuated token created", check());
        println!("  {}  {}", dim("token_id "), child.token_id);
        println!("  {}  {}", dim("parent   "), parent.token_id);
        println!("  {}  {}", dim("subject  "), subject);
        println!("  {}  {}", dim("depth    "), child.delegation_depth);
        println!("  {}  {}", dim("saved    "), output.display());
    }
    Ok(())
}

fn cmd_token_verify(
    token_path: &PathBuf,
    identity_path: &PathBuf,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_json = std::fs::read_to_string(token_path)?;
    let token: CapabilityToken = serde_json::from_str(&token_json)?;

    let identity = if let Ok(kp) = load_keypair(identity_path) {
        kp.identity
    } else {
        let data = std::fs::read_to_string(identity_path)?;
        let id_file: IdentityFile = serde_json::from_str(&data)?;
        AgentIdentity {
            id: id_file.id,
            name: id_file.name,
            public_key: id_file.public_key,
            attestations: Vec::new(),
            created_at: Utc::now(),
        }
    };

    match token.verify_signature(&identity) {
        Ok(()) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "token_id": token.token_id.to_string(),
                        "issuer": token.issuer_id.to_string(),
                        "subject": token.subject_id.to_string(),
                        "expires_at": token.expires_at.to_rfc3339(),
                    }))?
                );
            } else {
                println!("{} signature valid", check());
                println!("  {}  {}", dim("token_id"), token.token_id);
                println!("  {}  {}", dim("issuer  "), token.issuer_id);
                println!("  {}  {}", dim("subject "), token.subject_id);
                println!("  {}  {}", dim("expires "), token.expires_at);
            }
            Ok(())
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": false,
                        "error": e.to_string(),
                    }))?
                );
            } else {
                println!("{} signature INVALID — {}", cross(), red(&e.to_string()));
            }
            std::process::exit(1);
        }
    }
}

fn cmd_audit_verify(path: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let log = AuditLog::with_persistence(path.to_path_buf())?;
    match log.verify_integrity() {
        Ok(()) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "entries": log.len(),
                    }))?
                );
            } else {
                println!("{} audit log integrity verified", check());
                println!("  {}  {}", dim("entries"), log.len());
            }
            Ok(())
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": false,
                        "error": e.to_string(),
                    }))?
                );
            } else {
                println!("{} audit log INVALID — {}", cross(), red(&e.to_string()));
            }
            std::process::exit(1);
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
