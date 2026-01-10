//! Targets panel for managing encryption targets.
//!
//! Handles:
//! - ZFS dataset selection and management
//! - LUKS mapping discovery and selection
//! - Target status display

use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Alignment, Element, Length, Task,
};
use lockchain_core::provider::ProviderKind;

use super::ProviderPanel;

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
            match self.current_provider {
                ProviderKind::Zfs => "ZFS (Datasets)",
                ProviderKind::Luks => "LUKS (Mappings)",
                ProviderKind::Auto => "Auto",
            }
        ))
        .size(14);

        // Header with refresh button
        let header = row![
            text("Configured Targets").size(20),
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
            column![
                text("No targets configured").size(16),
                Space::with_height(10),
                text("Targets are defined in the Lockchain configuration file.").size(12),
                text("For ZFS, these are dataset names (e.g., rpool/encrypted).").size(12),
                text("For LUKS, these are device paths or mapping names.").size(12),
            ]
            .spacing(5)
        } else {
            let mut items = column![].spacing(8);
            for target in &self.configured_targets {
                let is_selected = self.selected_target.as_ref() == Some(target);
                let label = if is_selected {
                    format!("▶ {} [SELECTED]", target)
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

        // Target info section
        let info_section = if let Some(selected) = &self.selected_target {
            column![
                text("Selected Target").size(16),
                Space::with_height(5),
                text(selected).size(20),
                Space::with_height(10),
                text("Use the Key panel to forge keys or perform recovery on this target.")
                    .size(12),
            ]
            .spacing(5)
        } else {
            column![text("No target selected").size(16)].spacing(5)
        };

        let content = column![
            text("TARGETS").size(32),
            Space::with_height(10),
            provider_label,
            Space::with_height(20),
            header,
            Space::with_height(15),
            scrollable(target_list).height(Length::Fixed(250.0)),
            Space::with_height(20),
            info_section,
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
