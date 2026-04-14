//! Append-only, tamper-evident audit log with SHA-256 hash chain.
//!
//! Every PEP decision, sandbox action, and secret resolution is recorded.
//! Each entry includes a hash of the previous entry, forming a chain where
//! modifying any entry invalidates all subsequent entries.
//!
//! The log can optionally be backed by a file (one JSON line per entry).
//! On load, the hash chain is verified. On append, the new entry is
//! written and fsynced.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use moat_core::MoatError;

/// The type of event being logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventKind {
    PepDecision {
        message_id: Uuid,
        sender_id: Uuid,
        resource: String,
        action: String,
        allowed: bool,
        stage_failed: Option<String>,
        reason: Option<String>,
    },
    SandboxAction {
        agent_id: Uuid,
        action: String,
        resource: String,
    },
    SecretResolution {
        agent_id: Uuid,
        handle: String,
        /// Whether the resolution succeeded (never logs the secret value).
        success: bool,
    },
    MonitorAlert {
        agent_id: Uuid,
        alert_type: String,
        details: String,
    },
}

/// A single entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub event: AuditEventKind,
    /// SHA-256 hash of the previous entry's canonical bytes. Genesis entry uses all zeros.
    pub previous_hash: Vec<u8>,
    /// SHA-256 hash of this entry (computed over index + timestamp + event + previous_hash).
    pub entry_hash: Vec<u8>,
}

impl AuditEntry {
    fn compute_hash(
        index: u64,
        timestamp: &DateTime<Utc>,
        event: &AuditEventKind,
        previous_hash: &[u8],
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(index.to_le_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        // Canonical JSON of event for deterministic hashing
        let event_bytes = serde_json::to_vec(event).expect("audit event must serialize");
        hasher.update(&event_bytes);
        hasher.update(previous_hash);
        hasher.finalize().to_vec()
    }
}

/// The append-only audit log.
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    /// Optional file path for persistence.
    file_path: Option<PathBuf>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            file_path: None,
        }
    }

    /// Create a persistent audit log. Loads existing entries from the file
    /// (verifying the hash chain), and appends new entries to it.
    pub fn with_persistence(path: PathBuf) -> Result<Self, MoatError> {
        let entries = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            Vec::new()
        };
        Ok(Self {
            entries,
            file_path: Some(path),
        })
    }

    /// Load entries from a JSONL file and verify the hash chain.
    fn load_from_file(path: &Path) -> Result<Vec<AuditEntry>, MoatError> {
        let file = File::open(path)
            .map_err(|e| MoatError::Sandbox(format!("failed to open audit log: {}", e)))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line
                .map_err(|e| MoatError::Sandbox(format!("failed to read audit log line: {}", e)))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line).map_err(|e| {
                MoatError::Sandbox(format!(
                    "failed to parse audit log line {}: {}",
                    line_num + 1,
                    e
                ))
            })?;
            entries.push(entry);
        }

        // Verify integrity after loading
        let log = AuditLog {
            entries,
            file_path: None,
        };
        log.verify_integrity()?;
        Ok(log.entries)
    }

    /// Append a single entry to the file.
    fn persist_entry(&self, entry: &AuditEntry) -> Result<(), MoatError> {
        if let Some(ref path) = self.file_path {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    MoatError::Sandbox(format!("failed to open audit log for append: {}", e))
                })?;
            let json = serde_json::to_string(entry)?;
            writeln!(file, "{}", json).map_err(|e| {
                MoatError::Sandbox(format!("failed to write audit entry: {}", e))
            })?;
            file.sync_all().map_err(|e| {
                MoatError::Sandbox(format!("failed to fsync audit log: {}", e))
            })?;
        }
        Ok(())
    }

    /// Append an event to the log, extending the hash chain.
    pub fn append(&mut self, event: AuditEventKind) -> &AuditEntry {
        let index = self.entries.len() as u64;
        let previous_hash = if let Some(last) = self.entries.last() {
            last.entry_hash.clone()
        } else {
            vec![0u8; 32] // genesis
        };
        let timestamp = Utc::now();
        let entry_hash = AuditEntry::compute_hash(index, &timestamp, &event, &previous_hash);

        let entry = AuditEntry {
            index,
            timestamp,
            event,
            previous_hash,
            entry_hash,
        };

        // Persist before adding to in-memory log
        if let Err(e) = self.persist_entry(&entry) {
            tracing::error!(error = %e, "failed to persist audit entry");
        }

        self.entries.push(entry);
        self.entries.last().expect("just pushed")
    }

    /// Verify the integrity of the entire hash chain.
    /// Returns Ok(()) if every entry's hash is valid, or an error at the first broken link.
    pub fn verify_integrity(&self) -> Result<(), MoatError> {
        let mut expected_prev = vec![0u8; 32];

        for entry in &self.entries {
            if entry.previous_hash != expected_prev {
                return Err(MoatError::AuditChainBroken { index: entry.index });
            }

            let recomputed = AuditEntry::compute_hash(
                entry.index,
                &entry.timestamp,
                &entry.event,
                &entry.previous_hash,
            );

            if entry.entry_hash != recomputed {
                return Err(MoatError::AuditChainBroken { index: entry.index });
            }

            expected_prev = entry.entry_hash.clone();
        }

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get entries filtered by agent ID (searches PEP decisions and sandbox actions).
    pub fn entries_for_agent(&self, agent_id: Uuid) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| match &e.event {
                AuditEventKind::PepDecision { sender_id, .. } => *sender_id == agent_id,
                AuditEventKind::SandboxAction {
                    agent_id: aid, ..
                } => *aid == agent_id,
                AuditEventKind::SecretResolution {
                    agent_id: aid, ..
                } => *aid == agent_id,
                AuditEventKind::MonitorAlert {
                    agent_id: aid, ..
                } => *aid == agent_id,
            })
            .collect()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_verify() {
        let mut log = AuditLog::new();
        log.append(AuditEventKind::PepDecision {
            message_id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            resource: "tool://test".into(),
            action: "execute".into(),
            allowed: true,
            stage_failed: None,
            reason: None,
        });
        log.append(AuditEventKind::SandboxAction {
            agent_id: Uuid::new_v4(),
            action: "read".into(),
            resource: "file:///tmp/test".into(),
        });

        assert_eq!(log.len(), 2);
        assert!(log.verify_integrity().is_ok());
    }

    #[test]
    fn tampered_entry_detected() {
        let mut log = AuditLog::new();
        log.append(AuditEventKind::PepDecision {
            message_id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            resource: "tool://test".into(),
            action: "execute".into(),
            allowed: true,
            stage_failed: None,
            reason: None,
        });
        log.append(AuditEventKind::SandboxAction {
            agent_id: Uuid::new_v4(),
            action: "read".into(),
            resource: "file:///tmp/test".into(),
        });

        // Tamper with first entry
        log.entries[0].entry_hash[0] ^= 0xff;

        assert!(matches!(
            log.verify_integrity(),
            Err(MoatError::AuditChainBroken { .. })
        ));
    }

    #[test]
    fn tampered_middle_entry_breaks_chain() {
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(AuditEventKind::SandboxAction {
                agent_id: Uuid::new_v4(),
                action: format!("action_{}", i),
                resource: "test".into(),
            });
        }
        assert!(log.verify_integrity().is_ok());

        // Tamper with entry 2's previous_hash
        log.entries[2].previous_hash[0] ^= 0xff;
        let err = log.verify_integrity().unwrap_err();
        match err {
            MoatError::AuditChainBroken { index } => assert_eq!(index, 2),
            _ => panic!("expected AuditChainBroken"),
        }
    }

    #[test]
    fn empty_log_verifies() {
        let log = AuditLog::new();
        assert!(log.verify_integrity().is_ok());
        assert!(log.is_empty());
    }

    #[test]
    fn filter_by_agent() {
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let mut log = AuditLog::new();

        log.append(AuditEventKind::SandboxAction {
            agent_id: agent_a,
            action: "read".into(),
            resource: "file_a".into(),
        });
        log.append(AuditEventKind::SandboxAction {
            agent_id: agent_b,
            action: "write".into(),
            resource: "file_b".into(),
        });
        log.append(AuditEventKind::SandboxAction {
            agent_id: agent_a,
            action: "execute".into(),
            resource: "tool_a".into(),
        });

        assert_eq!(log.entries_for_agent(agent_a).len(), 2);
        assert_eq!(log.entries_for_agent(agent_b).len(), 1);
    }

    #[test]
    fn persistent_audit_log_survives_reload() {
        let dir = std::env::temp_dir().join(format!("moat-audit-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");

        let agent = Uuid::new_v4();

        // Write some entries
        {
            let mut log = AuditLog::with_persistence(log_path.clone()).unwrap();
            log.append(AuditEventKind::SandboxAction {
                agent_id: agent,
                action: "read".into(),
                resource: "file_a".into(),
            });
            log.append(AuditEventKind::SandboxAction {
                agent_id: agent,
                action: "write".into(),
                resource: "file_b".into(),
            });
            assert_eq!(log.len(), 2);
        }

        // Reload and verify
        {
            let mut log = AuditLog::with_persistence(log_path.clone()).unwrap();
            assert_eq!(log.len(), 2);
            assert!(log.verify_integrity().is_ok());

            // Append more
            log.append(AuditEventKind::SandboxAction {
                agent_id: agent,
                action: "execute".into(),
                resource: "tool_c".into(),
            });
            assert_eq!(log.len(), 3);
        }

        // Reload again and verify the full chain
        {
            let log = AuditLog::with_persistence(log_path.clone()).unwrap();
            assert_eq!(log.len(), 3);
            assert!(log.verify_integrity().is_ok());
            assert_eq!(log.entries_for_agent(agent).len(), 3);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_file_detected_on_load() {
        let dir = std::env::temp_dir().join(format!("moat-audit-tamper-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");

        // Write entries
        {
            let mut log = AuditLog::with_persistence(log_path.clone()).unwrap();
            log.append(AuditEventKind::SandboxAction {
                agent_id: Uuid::new_v4(),
                action: "read".into(),
                resource: "file_a".into(),
            });
            log.append(AuditEventKind::SandboxAction {
                agent_id: Uuid::new_v4(),
                action: "write".into(),
                resource: "file_b".into(),
            });
        }

        // Tamper with the file: modify the first line
        {
            let content = std::fs::read_to_string(&log_path).unwrap();
            let mut lines: Vec<&str> = content.lines().collect();
            // Replace the first character of the first line's hash
            let first = lines[0].to_string();
            let tampered = first.replacen("\"entry_hash\":[", "\"entry_hash\":[0,", 1);
            lines[0] = &tampered;
            std::fs::write(&log_path, lines.join("\n") + "\n").unwrap();
        }

        // Loading should detect tampering
        let result = AuditLog::with_persistence(log_path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
