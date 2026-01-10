//! Provider-agnostic panel system for the Lockchain UI.
//!
//! This module defines the core `ProviderPanel` trait that all UI panels
//! must implement, enabling a provider-driven architecture where panels
//! adapt to ZFS, LUKS, or other backend providers.

use iced::{Element, Task};
use lockchain_core::provider::ProviderKind;

pub mod targets;
pub mod key;
pub mod settings;
pub mod health;

/// Core trait for provider-aware UI panels.
///
/// Each panel implements this trait to provide:
/// - Title and metadata
/// - View rendering (Iced widgets)
/// - Message handling and state updates
/// - Provider compatibility checks
pub trait ProviderPanel {
    /// Message type for this panel's internal events.
    type Message: Clone + Send + 'static;

    /// Returns the display title for this panel.
    #[allow(dead_code)]
    fn title(&self) -> &str;

    /// Renders the panel's UI as an Iced element tree.
    fn view(&self) -> Element<'_, Self::Message>;

    /// Handles a message and returns any resulting tasks.
    fn update(&mut self, message: Self::Message) -> Task<Self::Message>;

    /// Checks if this panel supports the given provider kind.
    ///
    /// Panels can adapt their UI or disable features based on provider.
    #[allow(dead_code)]
    fn supports_provider(&self, kind: ProviderKind) -> bool;

    /// Optional: Called when the active provider changes.
    ///
    /// Allows panels to reset state or adapt to the new provider.
    fn on_provider_changed(&mut self, _kind: ProviderKind) {}
}

/// Enumeration of all available panel types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PanelKind {
    /// Target management (datasets, LUKS mappings).
    Targets,
    /// Key operations (forging, recovery).
    Key,
    /// Configuration settings (USB device, passphrase).
    Settings,
    /// Health checks (self-test, diagnostics).
    Health,
}

impl PanelKind {
    /// Returns all panel kinds in display order.
    pub fn all() -> &'static [PanelKind] {
        &[
            PanelKind::Targets,
            PanelKind::Key,
            PanelKind::Settings,
            PanelKind::Health,
        ]
    }

    /// Returns the display label for this panel.
    pub fn label(&self) -> &'static str {
        match self {
            PanelKind::Targets => "TARGETS",
            PanelKind::Key => "KEY",
            PanelKind::Settings => "SETTINGS",
            PanelKind::Health => "HEALTH",
        }
    }

    /// Returns a brief description of this panel's purpose.
    #[allow(dead_code)]
    pub fn description(&self) -> &'static str {
        match self {
            PanelKind::Targets => "Manage encryption targets (datasets or LUKS mappings)",
            PanelKind::Key => "Forge keys, unlock targets, or recover from backup",
            PanelKind::Settings => "Configure USB device, passphrase, and global options",
            PanelKind::Health => "Run diagnostics, self-tests, and view system status",
        }
    }
}
