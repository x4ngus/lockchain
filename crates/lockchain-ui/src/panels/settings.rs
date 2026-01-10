//! Settings panel for configuration.
//!
//! Handles:
//! - Provider information display
//! - Configuration file location
//! - System status

use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Alignment, Element, Length, Task,
};
use lockchain_core::provider::ProviderKind;

use super::ProviderPanel;

/// State for the Settings panel.
pub struct SettingsPanel {
    current_provider: ProviderKind,

    // Configuration info (loaded from AppShell)
    config_path: String,
    targets_count: usize,
}

/// Messages for the Settings panel.
#[derive(Debug, Clone)]
pub enum SettingsMessage {
    /// Reload configuration from disk.
    ReloadConfig,

    /// Open config file in editor (placeholder).
    OpenConfigFile,
}

impl SettingsPanel {
    /// Creates a new settings panel.
    pub fn new(provider: ProviderKind) -> Self {
        Self {
            current_provider: provider,
            config_path: String::from("/etc/lockchain/config.toml"),
            targets_count: 0,
        }
    }

    /// Updates configuration metadata.
    pub fn set_config_info(&mut self, config_path: String, targets_count: usize) {
        self.config_path = config_path;
        self.targets_count = targets_count;
    }
}

impl ProviderPanel for SettingsPanel {
    type Message = SettingsMessage;

    fn title(&self) -> &str {
        "SETTINGS"
    }

    fn view(&self) -> Element<'_, Self::Message> {
        // Provider section
        let provider_section = column![
            text("Provider Configuration").size(20),
            Space::with_height(10),
            row![
                text("Active Provider:").size(16),
                Space::with_width(10),
                text(match self.current_provider {
                    ProviderKind::Zfs => "ZFS",
                    ProviderKind::Luks => "LUKS",
                    ProviderKind::Auto => "Auto-detect",
                })
                .size(16),
            ]
            .align_y(Alignment::Center),
            Space::with_height(5),
            text("Use the header selector to switch providers.").size(12),
        ]
        .spacing(5);

        // Configuration file section
        let config_section = column![
            text("Configuration File").size(20),
            Space::with_height(10),
            row![
                text("Location:").size(16),
                Space::with_width(10),
                text(&self.config_path).size(14),
            ]
            .align_y(Alignment::Center),
            Space::with_height(5),
            row![
                text("Configured Targets:").size(16),
                Space::with_width(10),
                text(format!("{}", self.targets_count)).size(14),
            ]
            .align_y(Alignment::Center),
            Space::with_height(15),
            row![
                button(text("Reload Config").size(14))
                    .on_press(SettingsMessage::ReloadConfig)
                    .padding([8, 16]),
                Space::with_width(10),
                button(text("Open Config File").size(14))
                    .on_press(SettingsMessage::OpenConfigFile)
                    .padding([8, 16]),
            ]
            .align_y(Alignment::Center),
        ]
        .spacing(5);

        // System info section
        let system_section = column![
            text("System Information").size(20),
            Space::with_height(10),
            text("Lockchain UI - Provider Panel Architecture").size(14),
            Space::with_height(5),
            text("For advanced configuration, edit the config file directly.").size(12),
            text("Changes to the config file require a reload.").size(12),
        ]
        .spacing(5);

        // Instructions section
        let instructions = column![
            text("Configuration Notes").size(16),
            Space::with_height(10),
            text("• Targets are defined in the [policy.targets] section").size(12),
            text("• Provider type is set in [provider.type]").size(12),
            text("• USB device settings (if applicable) are in [usb_device]").size(12),
            Space::with_height(10),
            text("Use the Health panel to run diagnostics and verify configuration.").size(12),
        ]
        .spacing(5);

        let content = column![
            text("SETTINGS").size(32),
            Space::with_height(20),
            scrollable(
                column![
                    provider_section,
                    Space::with_height(30),
                    config_section,
                    Space::with_height(30),
                    system_section,
                    Space::with_height(30),
                    instructions,
                ]
                .spacing(5)
            )
            .height(Length::Fill),
        ]
        .spacing(10)
        .padding(20);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        match message {
            SettingsMessage::ReloadConfig => {
                // In a real implementation, this would trigger AppShell to reload config
                // For now, just a placeholder
                eprintln!("Config reload requested");
                Task::none()
            }
            SettingsMessage::OpenConfigFile => {
                // Placeholder - could open system editor
                eprintln!("Opening config file: {}", self.config_path);
                Task::none()
            }
        }
    }

    fn supports_provider(&self, kind: ProviderKind) -> bool {
        // Settings panel supports all providers
        matches!(kind, ProviderKind::Zfs | ProviderKind::Luks)
    }

    fn on_provider_changed(&mut self, kind: ProviderKind) {
        self.current_provider = kind;
    }
}
