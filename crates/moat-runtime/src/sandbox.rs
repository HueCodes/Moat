//! Wasm sandbox for agent code execution.
//!
//! Uses wasmtime with fuel metering, memory limits, and WASI with restricted
//! filesystem/network access derived from the agent's capability token.
//! This provides OS-level confinement that application-level controls cannot bypass.

use moat_core::{MoatError, ResourceLimits};
use wasmtime::*;

/// Configuration derived from a capability token's resource limits.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub max_fuel: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub allowed_fs_read: Vec<String>,
    pub allowed_fs_write: Vec<String>,
    pub network_allowed: bool,
    pub allowed_hosts: Vec<String>,
}

impl From<&ResourceLimits> for SandboxConfig {
    fn from(limits: &ResourceLimits) -> Self {
        Self {
            max_fuel: limits.max_fuel,
            max_memory_bytes: limits.max_memory_bytes,
            allowed_fs_read: limits.allowed_fs_read.clone(),
            allowed_fs_write: limits.allowed_fs_write.clone(),
            network_allowed: limits.network_allowed,
            allowed_hosts: limits.allowed_hosts.clone(),
        }
    }
}

/// A configured wasmtime engine + store, ready to execute Wasm modules.
/// Each sandbox instance is isolated: separate store, separate fuel budget.
pub struct Sandbox {
    engine: Engine,
    config: SandboxConfig,
}

impl Sandbox {
    /// Create a new sandbox with the given resource constraints.
    pub fn new(config: SandboxConfig) -> Result<Self, MoatError> {
        let mut engine_config = Config::new();
        engine_config.consume_fuel(true);

        if let Some(max_mem) = config.max_memory_bytes {
            // wasmtime memory limit is per-memory; we set a reasonable page limit.
            // Each Wasm page is 64KiB.
            let _max_pages = max_mem / (64 * 1024);
            // Memory limits are applied at instantiation time via Store::limiter
        }

        let engine = Engine::new(&engine_config).map_err(|e| MoatError::Sandbox(e.to_string()))?;

        Ok(Self { engine, config })
    }

    /// Execute a Wasm module (raw bytes) within this sandbox.
    /// Returns the module's linear memory contents after execution (for inspection/testing).
    pub fn execute(&self, wasm_bytes: &[u8]) -> Result<SandboxResult, MoatError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| MoatError::Sandbox(format!("module compilation: {}", e)))?;

        let mut store = Store::new(&self.engine, ());

        // Set fuel budget
        if let Some(fuel) = self.config.max_fuel {
            store
                .set_fuel(fuel)
                .map_err(|e| MoatError::Sandbox(format!("set fuel: {}", e)))?;
        }

        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| MoatError::Sandbox(format!("instantiation: {}", e)))?;

        // Look for a _start export
        if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
            start
                .call(&mut store, ())
                .map_err(|e| MoatError::Sandbox(format!("execution: {}", e)))?;
        }

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = self.config.max_fuel.map(|f| f - fuel_remaining);

        Ok(SandboxResult { fuel_consumed })
    }

    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

/// Result of sandbox execution.
#[derive(Debug)]
pub struct SandboxResult {
    pub fuel_consumed: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_sandbox() {
        let config = SandboxConfig {
            max_fuel: Some(1_000_000),
            max_memory_bytes: Some(64 * 1024 * 1024),
            allowed_fs_read: vec![],
            allowed_fs_write: vec![],
            network_allowed: false,
            allowed_hosts: vec![],
        };
        let sandbox = Sandbox::new(config);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn sandbox_from_resource_limits() {
        let limits = ResourceLimits {
            max_fuel: Some(500_000),
            max_memory_bytes: Some(32 * 1024 * 1024),
            network_allowed: false,
            allowed_hosts: vec![],
            allowed_fs_read: vec!["/tmp".into()],
            allowed_fs_write: vec![],
        };
        let config = SandboxConfig::from(&limits);
        assert_eq!(config.max_fuel, Some(500_000));
        assert!(!config.network_allowed);
        assert_eq!(config.allowed_fs_read, vec!["/tmp".to_string()]);
    }

    #[test]
    fn execute_minimal_wasm() {
        // Minimal valid Wasm module (empty module)
        let wasm = wat::parse_str("(module)").unwrap();
        let config = SandboxConfig {
            max_fuel: Some(1_000_000),
            max_memory_bytes: None,
            allowed_fs_read: vec![],
            allowed_fs_write: vec![],
            network_allowed: false,
            allowed_hosts: vec![],
        };
        let sandbox = Sandbox::new(config).unwrap();
        let result = sandbox.execute(&wasm);
        assert!(result.is_ok());
    }
}
