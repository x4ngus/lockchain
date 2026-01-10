//! Targets panel for managing encryption targets.
//!
//! Handles:
//! - ZFS dataset selection and management
//! - LUKS mapping discovery and selection
//! - Target status display
//! - Common actions: Status / Unlock / Self-Test

use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Alignment, Element, Length, Task,
};
use lockchain_core::provider::ProviderKind;

use super::ProviderPanel;
use crate::dispatcher::WorkflowCommand;

/// State for the Targets panel.
pub struct TargetsPanel {
    current_provider: ProviderKind,

    // Target list and selection
    configured_targets: Vec<String>,
    selected_target: Option<String>,

    // UI state
    loading: bool,
}

/// Messages for the Targets panel.
#[derive(Debug, Clone)]
pub enum TargetsMessage {
    /// User selected a target.
    TargetSelected(String),

    /// User requested to refresh target list.
    RefreshTargets,

    /// Target list loaded from config.
    TargetsLoaded(Vec<String>),

    /// User requested status check for a target.
    RequestStatus(String),

    /// User requested to unlock a target.
    RequestUnlock(String),

    /// User requested self-test for a target.
    RequestSelfTest(String),

    /// Bubble workflow command to AppShell.
    RequestWorkflow(WorkflowCommand),
}

impl TargetsPanel {
    /// Creates a new targets panel.
    pub fn new(provider: ProviderKind) -> Self {
        Self {
            current_provider: provider,
            configured_targets: Vec::new(),
            selected_target: None,
            loading: false,
        }
    }

    /// Loads targets from the configuration.
    pub fn load_targets_from_config(&mut self, targets: Vec<String>) {
        self.configured_targets = targets;
        self.loading = false;
        // Auto-select first target if available
        if self.selected_target.is_none() && !self.configured_targets.is_empty() {
            self.selected_target = Some(self.configured_targets[0].clone());
        }
    }

    /// Returns provider-specific noun for targets.
    fn target_noun(&self) -> &str {
        match self.current_provider {
            ProviderKind::Zfs => "Dataset",
            ProviderKind::Luks => "Volume",
            ProviderKind::Auto => "Target",
        }
    }

    /// Returns provider-specific plural noun for targets.
    fn target_noun_plural(&self) -> &str {
        match self.current_provider {
            ProviderKind::Zfs => "Datasets",
            ProviderKind::Luks => "Volumes",
            ProviderKind::Auto => "Targets",
        }
    }

    /// Returns provider-specific description.
    fn provider_description(&self) -> &str {
        match self.current_provider {
            ProviderKind::Zfs => "ZFS (Datasets)",
            ProviderKind::Luks => "LUKS (Crypttab/Mapper)",
            ProviderKind::Auto => "Auto",
        }
    }
}

impl ProviderPanel for TargetsPanel {
    type Message = TargetsMessage;

    fn title(&self) -> &str {
        "TARGETS"
    }

    fn view(&self) -> Element<'_, Self::Message> {
        // Provider indicator
        let provider_label = text(format!(
            "Provider: {}",
            self.provider_description()
        ))
        .size(14);

        // Header with refresh button
        let header = row![
            text(format!("Configured {}", self.target_noun_plural())).size(20),
            Space::with_width(Length::Fill),
            button(text("Refresh").size(14))
                .on_press(TargetsMessage::RefreshTargets)
                .padding([6, 12]),
        ]
        .align_y(Alignment::Center)
        .spacing(10);

        // Target list
        let target_list = if self.loading {
            column![text("Loading targets...").size(16)].spacing(10)
        } else if self.configured_targets.is_empty() {
            let noun_lower = self.target_noun_plural().to_lowercase();
            column![
                text(format!("No {} configured", noun_lower)).size(16),
                Space::with_height(10),
                text("Targets are defined in the Lockchain configuration file.").size(12),
                text(match self.current_provider {
                    ProviderKind::Zfs => "For ZFS: dataset names (e.g., rpool/encrypted)",
                    ProviderKind::Luks => "For LUKS: device paths or mapping names (e.g., /dev/nvme0n1p3, vault)",
                    ProviderKind::Auto => "Target format depends on provider (ZFS datasets or LUKS volumes)",
                }).size(12),
            ]
            .spacing(5)
        } else {
            let mut items = column![].spacing(8);
            for target in &self.configured_targets {
                let is_selected = self.selected_target.as_ref() == Some(target);
                let label = if is_selected {
                    format!("▶ {}", target)
                } else {
                    format!("  {}", target)
                };

                let btn = button(text(label).size(16))
                    .on_press(TargetsMessage::TargetSelected(target.clone()))
                    .padding([8, 12])
                    .width(Length::Fill);

                items = items.push(btn);
            }
            items
        };

        // Action buttons section (only show if target selected)
        let actions_section = if let Some(selected) = &self.selected_target {
            column![
                text(format!("Selected {}", self.target_noun())).size(16),
                Space::with_height(5),
                text(selected).size(20),
                Space::with_height(15),
                text("Actions").size(18),
                Space::with_height(10),
                // Action buttons row
                row![
                    button(text("Status").size(14))
                        .on_press(TargetsMessage::RequestStatus(selected.clone()))
                        .padding([8, 16]),
                    Space::with_width(10),
                    button(text("Unlock").size(14))
                        .on_press(TargetsMessage::RequestUnlock(selected.clone()))
                        .padding([8, 16]),
                    Space::with_width(10),
                    button(text("Self-Test").size(14))
                        .on_press(TargetsMessage::RequestSelfTest(selected.clone()))
                        .padding([8, 16]),
                ]
                .align_y(Alignment::Center)
                .spacing(0),
                Space::with_height(15),
                text(match self.current_provider {
                    ProviderKind::Zfs => "• Status: Check ZFS encryption properties\n• Unlock: Load key and mount dataset\n• Self-Test: Verify encryption integrity",
                    ProviderKind::Luks => "• Status: Check LUKS volume status\n• Unlock: Open encrypted volume\n• Self-Test: Verify volume integrity",
                    ProviderKind::Auto => "• Status: Check target status\n• Unlock: Unlock target\n• Self-Test: Run integrity test",
                })
                .size(12),
            ]
            .spacing(5)
        } else {
            column![
                text(format!("No {} selected", self.target_noun().to_lowercase())).size(16),
                Space::with_height(5),
                text(format!("Select a {} from the list above to view actions.", self.target_noun().to_lowercase())).size(12),
            ]
            .spacing(5)
        };

        let content = column![
            text("TARGETS").size(32),
            Space::with_height(10),
            provider_label,
            Space::with_height(20),
            header,
            Space::with_height(15),
            scrollable(target_list).height(Length::Fixed(200.0)),
            Space::with_height(20),
            actions_section,
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
            TargetsMessage::TargetSelected(target) => {
                self.selected_target = Some(target);
                Task::none()
            }
            TargetsMessage::RefreshTargets => {
                self.loading = true;
                // In a real implementation, this would trigger a config reload
                // For now, just keep existing targets
                Task::done(TargetsMessage::TargetsLoaded(
                    self.configured_targets.clone(),
                ))
            }
            TargetsMessage::TargetsLoaded(targets) => {
                self.load_targets_from_config(targets);
                Task::none()
            }
            TargetsMessage::RequestStatus(target) => {
                // Bubble up workflow command
                Task::done(TargetsMessage::RequestWorkflow(
                    WorkflowCommand::Status { target },
                ))
            }
            TargetsMessage::RequestUnlock(target) => {
                // Bubble up workflow command
                Task::done(TargetsMessage::RequestWorkflow(
                    WorkflowCommand::Unlock { target },
                ))
            }
            TargetsMessage::RequestSelfTest(target) => {
                // Bubble up workflow command
                Task::done(TargetsMessage::RequestWorkflow(
                    WorkflowCommand::SelfTest { dataset: target },
                ))
            }
            TargetsMessage::RequestWorkflow(_) => {
                // This message bubbles up to AppShell, no local handling needed
                Task::none()
            }
        }
    }

    fn supports_provider(&self, kind: ProviderKind) -> bool {
        matches!(kind, ProviderKind::Zfs | ProviderKind::Luks)
    }

    fn on_provider_changed(&mut self, kind: ProviderKind) {
        self.current_provider = kind;
        // Clear selection when provider changes
        self.selected_target = None;
    }
}
