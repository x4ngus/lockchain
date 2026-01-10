//! Workflow execution helpers.
//!
//! Async functions for executing workflows against providers.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use lockchain_core::config::LockchainConfig;
use lockchain_core::provider::ProviderKind;
use lockchain_core::workflow::{self, ForgeMode, ProvisionOptions, RecoveryInput, WorkflowReport};
use lockchain_luks::SystemLuksProvider;
use lockchain_zfs::SystemZfsProvider;

use super::WorkflowCommand;

/// Executes a workflow command against the appropriate provider.
pub async fn execute_workflow(
    command: WorkflowCommand,
    provider_kind: ProviderKind,
    config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
    luks_provider: &SystemLuksProvider,
) -> Result<WorkflowReport, String> {
    match command {
        WorkflowCommand::ForgeKey {
            dataset,
            mode,
            options,
        } => execute_forge_key(provider_kind, config, zfs_provider, &dataset, mode, options).await,
        WorkflowCommand::SelfTest { dataset } => {
            execute_self_test(provider_kind, config, zfs_provider, luks_provider, &dataset).await
        }
        WorkflowCommand::RecoverKey { key_material } => {
            execute_recover_key(provider_kind, config, zfs_provider, &key_material).await
        }
        WorkflowCommand::RecoverUsb => execute_recover_usb().await,
        WorkflowCommand::Diagnostics => execute_diagnostics(config, zfs_provider).await,
        WorkflowCommand::Status { target } => {
            execute_status(provider_kind, config, zfs_provider, luks_provider, &target).await
        }
        WorkflowCommand::Unlock { target } => {
            execute_unlock(provider_kind, config, zfs_provider, luks_provider, &target).await
        }
    }
}

/// Executes a key forging workflow.
async fn execute_forge_key(
    provider_kind: ProviderKind,
    config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
    dataset: &str,
    mode: ForgeMode,
    options: ProvisionOptions,
) -> Result<WorkflowReport, String> {
    match provider_kind {
        ProviderKind::Zfs => {
            let mut config_guard = config
                .lock()
                .map_err(|e| format!("Failed to lock config: {}", e))?;

            workflow::forge_key(&mut config_guard, zfs_provider, dataset, mode, options)
                .map_err(|e| format!("Forge key failed: {}", e))
        }
        ProviderKind::Luks => {
            Err("Key forging not supported for LUKS in UI. Use lockchain-cli init.".to_string())
        }
        ProviderKind::Auto => Err("Provider kind must be resolved before forging".to_string()),
    }
}

/// Executes a self-test workflow.
async fn execute_self_test(
    provider_kind: ProviderKind,
    config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
    _luks_provider: &SystemLuksProvider,
    dataset: &str,
) -> Result<WorkflowReport, String> {
    let config_guard = config
        .lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;

    match provider_kind {
        ProviderKind::Zfs => {
            // self_test requires: config, provider (cloned), dataset, skip_unlock (bool)
            workflow::self_test(&config_guard, zfs_provider.clone(), dataset, false)
                .map_err(|e| format!("Self-test failed: {}", e))
        }
        ProviderKind::Luks => {
            // self_test_luks requires: config, provider_builder, target, skip_unlock
            // For now, return placeholder error - full implementation needed
            Err("LUKS self-test not yet implemented in new architecture".to_string())
        }
        ProviderKind::Auto => Err("Provider kind must be resolved before self-test".to_string()),
    }
}

/// Executes a key recovery workflow.
async fn execute_recover_key(
    provider_kind: ProviderKind,
    config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
    key_material: &[u8],
) -> Result<WorkflowReport, String> {
    let config_guard = config
        .lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;

    // Get first dataset from config
    let dataset = config_guard
        .policy
        .targets
        .first()
        .ok_or_else(|| "No targets configured".to_string())?;

    // Determine recovery input type (hex vs passphrase)
    let recovery_input = if key_material.len() == 64 {
        // Assume hex-encoded key (as string)
        let hex_str = std::str::from_utf8(key_material)
            .map_err(|e| format!("Invalid UTF-8 in hex key: {}", e))?;
        RecoveryInput::Hex(hex_str)
    } else {
        // Passphrase as raw bytes
        RecoveryInput::Passphrase(key_material)
    };

    // Use a temp output path for recovery
    let output_path = PathBuf::from("/tmp/lockchain_recovery_key");

    match provider_kind {
        ProviderKind::Zfs | ProviderKind::Luks => workflow::recover_key(
            &config_guard,
            zfs_provider.clone(),
            dataset,
            recovery_input,
            &output_path,
        )
        .map_err(|e| format!("Recovery failed: {}", e)),
        ProviderKind::Auto => Err("Provider kind must be resolved before recovery".to_string()),
    }
}

/// Executes system diagnostics.
async fn execute_diagnostics(
    config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
) -> Result<WorkflowReport, String> {
    let config_guard = config
        .lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;

    workflow::doctor(&config_guard, zfs_provider.clone())
        .map_err(|e| format!("Diagnostics failed: {}", e))
}

/// Executes status check for a target (ZFS dataset or LUKS volume).
async fn execute_status(
    provider_kind: ProviderKind,
    _config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
    _luks_provider: &SystemLuksProvider,
    target: &str,
) -> Result<WorkflowReport, String> {
    use lockchain_core::workflow::{WorkflowEvent, WorkflowLevel};
    use lockchain_provider::zfs::ZfsProvider;

    match provider_kind {
        ProviderKind::Zfs => {
            let mut events = Vec::new();

            // Get encryption status using describe_datasets
            match zfs_provider.describe_datasets(&[target.to_string()]) {
                Ok(descriptors) => {
                    if let Some(desc) = descriptors.first() {
                        events.push(WorkflowEvent {
                            level: WorkflowLevel::Info,
                            message: format!("Dataset: {}", desc.dataset),
                        });
                        events.push(WorkflowEvent {
                            level: WorkflowLevel::Info,
                            message: format!("Encryption root: {}", desc.encryption_root),
                        });
                        events.push(WorkflowEvent {
                            level: WorkflowLevel::Info,
                            message: format!("Key state: {:?}", desc.state),
                        });
                        events.push(WorkflowEvent {
                            level: WorkflowLevel::Success,
                            message: "Status check completed".to_string(),
                        });
                    } else {
                        events.push(WorkflowEvent {
                            level: WorkflowLevel::Error,
                            message: "Dataset not found".to_string(),
                        });
                    }
                }
                Err(e) => {
                    events.push(WorkflowEvent {
                        level: WorkflowLevel::Error,
                        message: format!("Failed to get status: {}", e),
                    });
                }
            }

            Ok(WorkflowReport {
                title: format!("Status Check: {}", target),
                events,
                recovery_key: None,
            })
        }
        ProviderKind::Luks => Ok(WorkflowReport {
            title: format!("LUKS Status: {}", target),
            events: vec![
                WorkflowEvent {
                    level: WorkflowLevel::Info,
                    message: format!("Target: {}", target),
                },
                WorkflowEvent {
                    level: WorkflowLevel::Warn,
                    message: "LUKS status check not yet fully implemented".to_string(),
                },
            ],
            recovery_key: None,
        }),
        ProviderKind::Auto => Err("Provider kind must be resolved before status check".to_string()),
    }
}

/// Executes unlock workflow for a target (ZFS dataset or LUKS volume).
async fn execute_unlock(
    provider_kind: ProviderKind,
    config: Arc<Mutex<LockchainConfig>>,
    zfs_provider: &SystemZfsProvider,
    _luks_provider: &SystemLuksProvider,
    target: &str,
) -> Result<WorkflowReport, String> {
    let config_guard = config
        .lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;

    match provider_kind {
        ProviderKind::Zfs => {
            // For ZFS, unlock means loading the key and mounting
            // Use drill_key workflow which exercises the full unlock path
            workflow::drill_key(&config_guard, zfs_provider.clone(), target, false)
                .map_err(|e| format!("Unlock failed: {}", e))
        }
        ProviderKind::Luks => {
            // LUKS unlock - placeholder implementation
            use lockchain_core::workflow::{WorkflowEvent, WorkflowLevel};

            Ok(WorkflowReport {
                title: format!("LUKS Unlock: {}", target),
                events: vec![
                    WorkflowEvent {
                        level: WorkflowLevel::Info,
                        message: format!("Target: {}", target),
                    },
                    WorkflowEvent {
                        level: WorkflowLevel::Warn,
                        message: "LUKS unlock not yet fully implemented in UI".to_string(),
                    },
                    WorkflowEvent {
                        level: WorkflowLevel::Info,
                        message: "Use 'lockchain unlock' CLI command for LUKS volumes".to_string(),
                    },
                ],
                recovery_key: None,
            })
        }
        ProviderKind::Auto => Err("Provider kind must be resolved before unlock".to_string()),
    }
}

/// Executes USB key recovery workflow using recovery code.
///
/// This workflow guides the user through recovering a lost USB key using the
/// recovery code that was generated during the initial key forging process.
async fn execute_recover_usb() -> Result<WorkflowReport, String> {
    use lockchain_core::workflow::{WorkflowEvent, WorkflowLevel};

    // This is a placeholder implementation that provides instructions.
    // The actual recovery requires user input (recovery hex code) which should
    // be collected via UI and passed to the RecoverKey workflow.

    Ok(WorkflowReport {
        title: "USB Key Recovery".to_string(),
        events: vec![
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "USB Key Recovery Process".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "To recover your USB key, you will need:".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "1. The 64-character recovery hex code from your initial key forge"
                    .to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "2. A USB device formatted and ready to receive the key".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Warn,
                message: "Recovery code should have been securely stored during initial setup!"
                    .to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "Navigate to the Key panel → Recovery tab to enter your recovery code"
                    .to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "The recovery workflow will:".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "  - Decode your recovery hex code".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "  - Write the key to the USB device".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Info,
                message: "  - Stage the key in /run/lockchain for unlock".to_string(),
            },
            WorkflowEvent {
                level: WorkflowLevel::Success,
                message: "Use the Key panel's Recovery mode to proceed with recovery".to_string(),
            },
        ],
        recovery_key: None,
    })
}
