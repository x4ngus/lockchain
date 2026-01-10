//! Key panel for key operations.
//!
//! Handles:
//! - Key forging (standard and safe mode)
//! - Target unlocking
//! - Key recovery from passphrase

use iced::{
    widget::{button, column, container, row, text, text_input, Space},
    Alignment, Element, Length, Task,
};
use lockchain_core::provider::ProviderKind;
use lockchain_core::workflow::{ForgeMode, ProvisionOptions};

use super::ProviderPanel;
use crate::dispatcher::WorkflowCommand;

/// Per-provider state snapshot.
#[derive(Debug, Clone)]
struct ProviderState {
    dataset_input: String,
    recovery_input: String,
    active_mode: KeyMode,
}

impl Default for ProviderState {
    fn default() -> Self {
        Self {
            dataset_input: String::new(),
            recovery_input: String::new(),
            active_mode: KeyMode::Forge,
        }
    }
}

/// State for the Key panel.
pub struct KeyPanel {
    current_provider: ProviderKind,

    // Per-provider state snapshots
    zfs_state: ProviderState,
    luks_state: ProviderState,

    // Forge inputs (active state)
    dataset_input: String,

    // Recovery inputs (active state)
    recovery_input: String,

    // UI state (active state)
    active_mode: KeyMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyMode {
    Forge,
    Recovery,
}

/// Messages for the Key panel.
#[derive(Debug, Clone)]
pub enum KeyMessage {
    /// Switch active mode (forge/recovery).
    SwitchMode(KeyMode),

    /// Dataset input changed.
    DatasetChanged(String),

    /// Recovery input changed.
    RecoveryInputChanged(String),

    /// User clicked "Forge Key" button.
    ExecuteForge { safe_mode: bool },

    /// User clicked "Recover Key" button.
    ExecuteRecovery,

    /// Request workflow execution (bubbled up to AppShell).
    RequestWorkflow(WorkflowCommand),
}

impl KeyPanel {
    /// Creates a new key panel.
    pub fn new(provider: ProviderKind) -> Self {
        Self {
            current_provider: provider,
            zfs_state: ProviderState::default(),
            luks_state: ProviderState::default(),
            dataset_input: String::new(),
            recovery_input: String::new(),
            active_mode: KeyMode::Forge,
        }
    }

    /// Saves current state to provider snapshot.
    fn save_current_state(&mut self) {
        let state = ProviderState {
            dataset_input: self.dataset_input.clone(),
            recovery_input: self.recovery_input.clone(),
            active_mode: self.active_mode,
        };

        match self.current_provider {
            ProviderKind::Zfs => self.zfs_state = state,
            ProviderKind::Luks => self.luks_state = state,
            ProviderKind::Auto => {} // Don't save for Auto
        }
    }

    /// Restores state from provider snapshot.
    fn restore_provider_state(&mut self, provider: ProviderKind) {
        let state = match provider {
            ProviderKind::Zfs => &self.zfs_state,
            ProviderKind::Luks => &self.luks_state,
            ProviderKind::Auto => return, // Don't restore for Auto
        };

        self.dataset_input = state.dataset_input.clone();
        self.recovery_input = state.recovery_input.clone();
        self.active_mode = state.active_mode;
    }
}

impl ProviderPanel for KeyPanel {
    type Message = KeyMessage;

    fn title(&self) -> &str {
        "KEY"
    }

    fn view(&self) -> Element<'_, Self::Message> {
        // Mode selector tabs
        let forge_btn = button(text(if self.active_mode == KeyMode::Forge {
            "[FORGE]"
        } else {
            "FORGE"
        }))
        .on_press(KeyMessage::SwitchMode(KeyMode::Forge))
        .padding([8, 16]);

        let recovery_btn = button(text(if self.active_mode == KeyMode::Recovery {
            "[RECOVERY]"
        } else {
            "RECOVERY"
        }))
        .on_press(KeyMessage::SwitchMode(KeyMode::Recovery))
        .padding([8, 16]);

        let mode_tabs = row![forge_btn, recovery_btn]
            .spacing(10)
            .align_y(Alignment::Center);

        // Provider indicator
        let provider_label = text(format!(
            "Provider: {}",
            match self.current_provider {
                ProviderKind::Zfs => "ZFS",
                ProviderKind::Luks => "LUKS",
                ProviderKind::Auto => "Auto",
            }
        ))
        .size(14);

        // Main content area (different based on active mode)
        let main_content = match self.active_mode {
            KeyMode::Forge => self.render_forge_ui(),
            KeyMode::Recovery => self.render_recovery_ui(),
        };

        let content = column![
            text("KEY").size(32),
            Space::with_height(10),
            mode_tabs,
            Space::with_height(10),
            provider_label,
            Space::with_height(20),
            main_content,
        ]
        .spacing(5)
        .padding(20);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        match message {
            KeyMessage::SwitchMode(mode) => {
                self.active_mode = mode;
                Task::none()
            }
            KeyMessage::DatasetChanged(value) => {
                self.dataset_input = value;
                Task::none()
            }
            KeyMessage::RecoveryInputChanged(value) => {
                self.recovery_input = value;
                Task::none()
            }
            KeyMessage::ExecuteForge { safe_mode } => {
                // Build forge workflow command
                let mode = if safe_mode {
                    ForgeMode::Safe
                } else {
                    ForgeMode::Standard
                };

                let options = ProvisionOptions::default();

                let command = WorkflowCommand::ForgeKey {
                    dataset: self.dataset_input.clone(),
                    mode,
                    options,
                };

                // Bubble up to AppShell for execution
                Task::done(KeyMessage::RequestWorkflow(command))
            }
            KeyMessage::ExecuteRecovery => {
                // Build recovery workflow command
                let key_material = self.recovery_input.as_bytes().to_vec();

                let command = WorkflowCommand::RecoverKey { key_material };

                // Bubble up to AppShell for execution
                Task::done(KeyMessage::RequestWorkflow(command))
            }
            KeyMessage::RequestWorkflow(_) => {
                // This message is handled by AppShell, do nothing here
                Task::none()
            }
        }
    }

    fn supports_provider(&self, kind: ProviderKind) -> bool {
        match kind {
            ProviderKind::Zfs => true,
            ProviderKind::Luks => true, // Recovery and unlock supported
            ProviderKind::Auto => false,
        }
    }

    fn on_provider_changed(&mut self, kind: ProviderKind) {
        // Save current provider state before switching
        self.save_current_state();

        // Switch provider
        self.current_provider = kind;

        // Restore saved state for new provider
        self.restore_provider_state(kind);
    }
}

impl KeyPanel {
    /// Renders the key forging UI.
    fn render_forge_ui(&self) -> Element<'_, KeyMessage> {
        let dataset_label = text("Dataset:").size(16);
        let dataset_input = text_input("e.g. rpool", &self.dataset_input)
            .on_input(KeyMessage::DatasetChanged)
            .padding(10);

        let forge_standard = button(text("Forge Key (Standard)").size(16))
            .on_press(KeyMessage::ExecuteForge { safe_mode: false })
            .padding([10, 20]);

        let forge_safe = button(text("Forge Key (Safe Mode)").size(16))
            .on_press(KeyMessage::ExecuteForge { safe_mode: true })
            .padding([10, 20]);

        let note = if self.current_provider == ProviderKind::Luks {
            text("Note: Key forging for LUKS is not supported in the UI. Use lockchain-cli init.")
                .size(12)
        } else {
            text("Standard forge uses existing keyfile. Safe mode creates new keyfile on USB.")
                .size(12)
        };

        let buttons = if self.current_provider == ProviderKind::Luks {
            row![].spacing(10)
        } else {
            row![forge_standard, forge_safe].spacing(10)
        };

        column![
            dataset_label,
            dataset_input,
            Space::with_height(15),
            buttons,
            Space::with_height(10),
            note,
        ]
        .spacing(5)
        .into()
    }

    /// Renders the key recovery UI.
    fn render_recovery_ui(&self) -> Element<'_, KeyMessage> {
        let input_label = text("Recovery passphrase or hex key:").size(16);
        let input_box = text_input("Enter passphrase or 64-char hex key", &self.recovery_input)
            .on_input(KeyMessage::RecoveryInputChanged)
            .padding(10)
            .secure(true);

        let recover_btn = button(text("Recover Key").size(16))
            .on_press(KeyMessage::ExecuteRecovery)
            .padding([10, 20]);

        let note = text("Recovered key will be written to /tmp/lockchain_recovery_key").size(12);

        column![
            input_label,
            input_box,
            Space::with_height(15),
            recover_btn,
            Space::with_height(10),
            note,
        ]
        .spacing(5)
        .into()
    }
}
