//! Health panel for diagnostics.
//!
//! Handles:
//! - Self-test execution
//! - System diagnostics (doctor)
//! - Status monitoring
//! - Key/USB status visibility

use iced::{
    widget::{button, column, container, text, text_input, Space},
    Element, Length, Task,
};
use lockchain_core::config::LockchainConfig;
use lockchain_core::provider::ProviderKind;

use super::ProviderPanel;
use crate::components::{KeyStatus, KeyStatusMessage, KeyStatusState};
use crate::dispatcher::WorkflowCommand;

/// Per-provider state snapshot.
#[derive(Debug, Clone, Default)]
struct ProviderState {
    dataset_input: String,
}

/// State for the Health panel.
pub struct HealthPanel {
    current_provider: ProviderKind,

    // Per-provider state snapshots
    zfs_state: ProviderState,
    luks_state: ProviderState,

    // Dataset for self-test (active state)
    dataset_input: String,

    // Key/USB status component
    key_status: KeyStatusState,
}

/// Messages for the Health panel.
#[derive(Debug, Clone)]
pub enum HealthMessage {
    /// Dataset input changed.
    DatasetChanged(String),

    /// User clicked "Run Self-Test" button.
    ExecuteSelfTest,

    /// User clicked "Run Diagnostics" button.
    ExecuteDiagnostics,

    /// Key status message (from component).
    KeyStatus(KeyStatusMessage),

    /// Request workflow execution (bubbled up to AppShell).
    RequestWorkflow(WorkflowCommand),

    /// Refresh key status from config.
    RefreshKeyStatus(LockchainConfig),

    /// Jump to terminal to view logs.
    ShowTerminal,
}

impl HealthPanel {
    /// Creates a new health panel.
    pub fn new(provider: ProviderKind) -> Self {
        Self {
            current_provider: provider,
            zfs_state: ProviderState::default(),
            luks_state: ProviderState::default(),
            dataset_input: String::new(),
            key_status: KeyStatusState::new(),
        }
    }

    /// Initialize panel with config data.
    pub fn init_with_config(&mut self, config: &LockchainConfig) {
        let status = KeyStatus::check(config, self.current_provider);
        self.key_status.update(status);
    }

    /// Saves current state to provider snapshot.
    fn save_current_state(&mut self) {
        let state = ProviderState {
            dataset_input: self.dataset_input.clone(),
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
    }
}

impl ProviderPanel for HealthPanel {
    type Message = HealthMessage;

    fn title(&self) -> &str {
        "HEALTH"
    }

    fn view(&self) -> Element<'_, Self::Message> {
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

        // Key/USB status section (map messages)
        let key_status_view = self
            .key_status
            .view()
            .map(HealthMessage::KeyStatus);

        // Self-test section
        let selftest_title = text("Self-Test").size(20);
        let dataset_label = text("Dataset:").size(16);
        let dataset_input = text_input("e.g. rpool", &self.dataset_input)
            .on_input(HealthMessage::DatasetChanged)
            .padding(10);
        let selftest_btn = button(text("Run Self-Test").size(16))
            .on_press(HealthMessage::ExecuteSelfTest)
            .padding([10, 20]);
        let selftest_note = text("Runs end-to-end unlock test on the dataset").size(12);

        // Diagnostics section
        let diagnostics_title = text("System Diagnostics").size(20);
        let diagnostics_btn = button(text("Run Diagnostics").size(16))
            .on_press(HealthMessage::ExecuteDiagnostics)
            .padding([10, 20]);
        let diagnostics_note = text("Checks system configuration and dependencies").size(12);

        let content = column![
            text("HEALTH").size(32),
            Space::with_height(10),
            provider_label,
            Space::with_height(20),
            // Key/USB Status section
            key_status_view,
            Space::with_height(30),
            // Self-test section
            selftest_title,
            Space::with_height(10),
            dataset_label,
            dataset_input,
            Space::with_height(10),
            selftest_btn,
            selftest_note,
            Space::with_height(30),
            // Diagnostics section
            diagnostics_title,
            Space::with_height(10),
            diagnostics_btn,
            diagnostics_note,
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
            HealthMessage::DatasetChanged(value) => {
                self.dataset_input = value;
                Task::none()
            }
            HealthMessage::ExecuteSelfTest => {
                let command = WorkflowCommand::SelfTest {
                    dataset: self.dataset_input.clone(),
                };
                Task::done(HealthMessage::RequestWorkflow(command))
            }
            HealthMessage::ExecuteDiagnostics => {
                let command = WorkflowCommand::Diagnostics;
                Task::done(HealthMessage::RequestWorkflow(command))
            }
            HealthMessage::KeyStatus(msg) => {
                match msg {
                    KeyStatusMessage::Refresh | KeyStatusMessage::AutoRefresh => {
                        // Trigger refresh - request config from AppShell
                        // For now, do nothing - AppShell should periodically refresh
                        Task::none()
                    }
                    KeyStatusMessage::ShowLogs => {
                        // Signal to switch to terminal view (handled by AppShell)
                        Task::done(HealthMessage::ShowTerminal)
                    }
                    KeyStatusMessage::RecoverUsb => {
                        // Launch USB recovery workflow
                        let command = WorkflowCommand::RecoverUsb;
                        Task::done(HealthMessage::RequestWorkflow(command))
                    }
                    KeyStatusMessage::InspectPath(path) => {
                        // Open file for inspection - use system command
                        #[cfg(target_os = "macos")]
                        let _ = std::process::Command::new("open")
                            .arg("-t") // Text editor
                            .arg(&path)
                            .spawn();

                        #[cfg(target_os = "linux")]
                        let _ = std::process::Command::new("xdg-open")
                            .arg(&path)
                            .spawn();

                        #[cfg(target_os = "windows")]
                        let _ = std::process::Command::new("notepad")
                            .arg(&path)
                            .spawn();

                        Task::none()
                    }
                }
            }
            HealthMessage::RefreshKeyStatus(config) => {
                let status = KeyStatus::check(&config, self.current_provider);
                self.key_status.update(status);
                Task::none()
            }
            HealthMessage::ShowTerminal => {
                // Handled by AppShell, do nothing here
                Task::none()
            }
            HealthMessage::RequestWorkflow(_) => {
                // This message is handled by AppShell, do nothing here
                Task::none()
            }
        }
    }

    fn supports_provider(&self, kind: ProviderKind) -> bool {
        matches!(kind, ProviderKind::Zfs | ProviderKind::Luks)
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
