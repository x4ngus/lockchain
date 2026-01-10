//! Provider context management for UI.
//!
//! This module provides a unified interface for working with different
//! encryption providers (ZFS, LUKS) in the UI layer.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use lockchain_core::config::LockchainConfig;
use lockchain_core::provider::ProviderKind;
use lockchain_zfs::SystemZfsProvider;
use lockchain_luks::SystemLuksProvider;

pub mod zfs_adapter;
pub mod luks_adapter;

/// Wrapper for provider state and configuration.
///
/// Manages the active provider, config persistence, and provider switching.
pub struct ProviderContext {
    /// Current active provider kind.
    current_kind: ProviderKind,

    /// Path to config file for persistence.
    #[allow(dead_code)]
    config_path: PathBuf,

    /// Shared config state (thread-safe for async workflows).
    config: Arc<Mutex<LockchainConfig>>,

    /// ZFS provider instance.
    zfs_provider: SystemZfsProvider,

    /// LUKS provider instance.
    luks_provider: SystemLuksProvider,
}

impl ProviderContext {
    /// Creates a new provider context from config file.
    pub fn new(config_path: PathBuf) -> Result<Self, String> {
        let config = LockchainConfig::load(&config_path)
            .map_err(|e| format!("Failed to load config: {}", e))?;

        let current_kind = config.resolve_provider_kind()
            .map_err(|e| format!("Failed to resolve provider: {}", e))?;

        // Create providers from config
        let zfs_provider = SystemZfsProvider::from_config(&config)
            .map_err(|e| format!("Failed to create ZFS provider: {}", e))?;
        let luks_provider = SystemLuksProvider::from_config(&config)
            .map_err(|e| format!("Failed to create LUKS provider: {}", e))?;

        Ok(Self {
            current_kind,
            config_path,
            config: Arc::new(Mutex::new(config)),
            zfs_provider,
            luks_provider,
        })
    }

    /// Returns the current active provider kind.
    pub fn current_provider(&self) -> ProviderKind {
        self.current_kind
    }

    /// Switches to a different provider and persists the change.
    pub fn switch_provider(&mut self, kind: ProviderKind) -> Result<(), String> {
        if kind == ProviderKind::Auto {
            return Err("Cannot switch to Auto provider kind".to_string());
        }

        // Update config
        {
            let mut config = self.config.lock()
                .map_err(|e| format!("Failed to lock config: {}", e))?;
            config.provider.r#type = kind;
            config.save()
                .map_err(|e| format!("Failed to save config: {}", e))?;
        }

        // Update current kind
        self.current_kind = kind;

        Ok(())
    }

    /// Returns a reference to the ZFS provider.
    pub fn zfs_provider(&self) -> &SystemZfsProvider {
        &self.zfs_provider
    }

    /// Returns a reference to the LUKS provider.
    pub fn luks_provider(&self) -> &SystemLuksProvider {
        &self.luks_provider
    }

    /// Returns a cloned Arc to the config for async workflows.
    pub fn config_arc(&self) -> Arc<Mutex<LockchainConfig>> {
        Arc::clone(&self.config)
    }

    /// Returns a snapshot of the current config.
    #[allow(dead_code)]
    pub fn config_snapshot(&self) -> Result<LockchainConfig, String> {
        self.config.lock()
            .map(|guard| guard.clone())
            .map_err(|e| format!("Failed to lock config: {}", e))
    }

    /// Updates the config and persists changes.
    #[allow(dead_code)]
    pub fn update_config<F>(&mut self, f: F) -> Result<(), String>
    where
        F: FnOnce(&mut LockchainConfig) -> Result<(), String>,
    {
        let mut config = self.config.lock()
            .map_err(|e| format!("Failed to lock config: {}", e))?;

        f(&mut config)?;

        config.save()
            .map_err(|e| format!("Failed to save config: {}", e))?;

        Ok(())
    }
}
