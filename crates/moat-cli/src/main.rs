use std::path::PathBuf;

use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use moat_core::{AgentIdentity, AgentKeypair, CapabilityToken, ResourceLimits, ScopeEntry};
use moat_runtime::AuditLog;

#[derive(Parser)]
#[command(name = "moat", about = "Moat protocol CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage agent identities
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Manage capability tokens
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Audit log operations
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new agent keypair
    Generate {
        /// Human-readable name for the agent
        #[arg(long)]
        name: String,
        /// Output path for the keypair file (JSON)
        #[arg(long, default_value = "agent.key")]
        output: PathBuf,
    },
    /// Display the public identity from a keypair file
    Show {
        /// Path to the keypair file
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Create and sign a root capability token
    Create {
        /// Path to the issuer's keypair file
        #[arg(long)]
        issuer: PathBuf,
        /// Subject agent ID (UUID)
        #[arg(long)]
        subject: uuid::Uuid,
        /// Scope entries as "resource=action,action" (repeatable)
        #[arg(long, value_delimiter = ';')]
        scope: Vec<String>,
        /// Token lifetime (e.g. "1h", "30m", "7d")
        #[arg(long, default_value = "1h")]
        expires: String,
        /// Maximum fuel
        #[arg(long)]
        max_fuel: Option<u64>,
        /// Maximum memory in bytes
        #[arg(long)]
        max_memory: Option<u64>,
        /// Output path for the token file (JSON)
        #[arg(long, default_value = "token.json")]
        output: PathBuf,
    },
    /// Attenuate (restrict) an existing token
    Attenuate {
        /// Path to the parent token file
        #[arg(long)]
        parent: PathBuf,
        /// Path to the delegator's keypair file (must match parent's subject)
        #[arg(long)]
        signer: PathBuf,
        /// New subject agent ID (UUID)
        #[arg(long)]
        subject: uuid::Uuid,
        /// Narrowed scope entries as "resource=action,action" (repeatable)
        #[arg(long, value_delimiter = ';')]
        scope: Vec<String>,
        /// Maximum delegation depth
        #[arg(long, default_value_t = 10)]
        max_depth: u32,
        /// Output path
        #[arg(long, default_value = "attenuated_token.json")]
        output: PathBuf,
    },
    /// Verify a token's signature
    Verify {
        /// Path to the token file
        #[arg(long)]
        token: PathBuf,
        /// Path to the issuer's identity (public) or keypair file
        #[arg(long)]
        identity: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Verify the integrity of an audit log file
    Verify {
        /// Path to the audit log file (JSONL)
        path: PathBuf,
    },
}

/// Serializable keypair for file storage. The signing key is secret.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeypairFile {
    id: uuid::Uuid,
    name: String,
    public_key: Vec<u8>,
    signing_key: Vec<u8>,
}

/// Identity-only file (no private key).
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
    let file: KeypairFile = serde_json::from_str(&data)?;
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

/// Parse scope entries in the format "resource=action1,action2".
/// Example: "tool://*=execute,read" or "tool://review=read"
fn parse_scope(scope_strs: &[String]) -> Vec<ScopeEntry> {
    scope_strs
        .iter()
        .filter_map(|s| {
            if let Some((resource, actions_str)) = s.rsplit_once('=') {
                let actions: Vec<String> =
                    actions_str.split(',').map(|a| a.trim().to_string()).collect();
                Some(ScopeEntry {
                    resource: resource.to_string(),
                    actions,
                })
            } else {
                eprintln!("warning: ignoring malformed scope entry (expected resource=action,...): {}", s);
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

    let result = match cli.command {
        Commands::Identity { action } => match action {
            IdentityAction::Generate { name, output } => cmd_identity_generate(&name, &output),
            IdentityAction::Show { path } => cmd_identity_show(&path),
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
                &issuer, subject, &scope, &expires, max_fuel, max_memory, &output,
            ),
            TokenAction::Attenuate {
                parent,
                signer,
                subject,
                scope,
                max_depth,
                output,
            } => cmd_token_attenuate(&parent, &signer, subject, &scope, max_depth, &output),
            TokenAction::Verify { token, identity } => cmd_token_verify(&token, &identity),
        },
        Commands::Audit { action } => match action {
            AuditAction::Verify { path } => cmd_audit_verify(&path),
        },
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_identity_generate(
    name: &str,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let kp = AgentKeypair::generate(name)?;
    println!("generated identity: {}", kp.id());
    println!("name: {}", name);
    save_keypair(&kp, output)?;
    println!("keypair saved to: {}", output.display());
    Ok(())
}

fn cmd_identity_show(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let kp = load_keypair(path)?;
    println!("id: {}", kp.id());
    println!("name: {}", kp.identity.name);
    println!("public_key: {}", hex_encode(&kp.identity.public_key));
    Ok(())
}

fn cmd_token_create(
    issuer_path: &PathBuf,
    subject: uuid::Uuid,
    scope: &[String],
    expires: &str,
    max_fuel: Option<u64>,
    max_memory: Option<u64>,
    output: &PathBuf,
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

    let json = serde_json::to_string_pretty(&token)?;
    std::fs::write(output, json)?;
    println!("token created: {}", token.token_id);
    println!("issuer: {}", issuer.id());
    println!("subject: {}", subject);
    println!("expires: {}", expires_at);
    println!("saved to: {}", output.display());
    Ok(())
}

fn cmd_token_attenuate(
    parent_path: &PathBuf,
    signer_path: &PathBuf,
    subject: uuid::Uuid,
    scope: &[String],
    max_depth: u32,
    output: &PathBuf,
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

    let json = serde_json::to_string_pretty(&child)?;
    std::fs::write(output, json)?;
    println!("attenuated token created: {}", child.token_id);
    println!("parent: {}", parent.token_id);
    println!("subject: {}", subject);
    println!("depth: {}", child.delegation_depth);
    println!("saved to: {}", output.display());
    Ok(())
}

fn cmd_token_verify(
    token_path: &PathBuf,
    identity_path: &PathBuf,
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
            println!("signature valid");
            println!("token: {}", token.token_id);
            println!("issuer: {}", token.issuer_id);
            println!("subject: {}", token.subject_id);
            println!("expires: {}", token.expires_at);
            Ok(())
        }
        Err(e) => {
            println!("signature INVALID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_audit_verify(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let log = AuditLog::with_persistence(path.clone())?;
    match log.verify_integrity() {
        Ok(()) => {
            println!("audit log integrity verified");
            println!("entries: {}", log.len());
            Ok(())
        }
        Err(e) => {
            println!("audit log INVALID: {}", e);
            std::process::exit(1);
        }
    }
}

/// Simple hex encoding without pulling in the hex crate.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
