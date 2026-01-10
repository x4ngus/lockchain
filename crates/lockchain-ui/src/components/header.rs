//! Header component with navigation and provider selector.

use iced::{
    widget::{button, container, row, text},
    Alignment, Element, Length,
};
use lockchain_core::provider::ProviderKind;

use crate::panels::PanelKind;

/// State for the header component.
pub struct HeaderState {
    /// Currently selected provider.
    current_provider: ProviderKind,
}

/// Messages from the header component.
#[derive(Debug, Clone)]
pub enum HeaderMessage {
    /// Panel selection changed.
    PanelSelected(PanelKind),
    /// Provider selection changed.
    ProviderSelected(ProviderKind),
}

impl HeaderState {
    /// Creates a new header state.
    pub fn new(provider: ProviderKind) -> Self {
        Self {
            current_provider: provider,
        }
    }

    /// Updates the current provider.
    pub fn set_provider(&mut self, provider: ProviderKind) {
        self.current_provider = provider;
    }

    /// Gets the current provider.
    #[allow(dead_code)]
    pub fn current_provider(&self) -> ProviderKind {
        self.current_provider
    }

    /// Renders the header with navigation tabs and provider selector.
    pub fn view(&self, _active_panel: PanelKind) -> Element<'_, HeaderMessage> {
        // Navigation tabs
        let mut tabs = row![].spacing(8).align_y(Alignment::Center);

        for panel in PanelKind::all() {
            let label = panel.label();

            let btn = button(text(label).size(14))
                .padding([8, 16])
                .on_press(HeaderMessage::PanelSelected(*panel));

            tabs = tabs.push(btn);
        }

        // Provider selector using buttons for now (pick_list requires Display trait)
        let zfs_btn = button(
            text(if self.current_provider == ProviderKind::Zfs {
                "[ZFS]"
            } else {
                "ZFS"
            })
            .size(14),
        )
        .padding([6, 12])
        .on_press(HeaderMessage::ProviderSelected(ProviderKind::Zfs));

        let luks_btn = button(
            text(if self.current_provider == ProviderKind::Luks {
                "[LUKS]"
            } else {
                "LUKS"
            })
            .size(14),
        )
        .padding([6, 12])
        .on_press(HeaderMessage::ProviderSelected(ProviderKind::Luks));

        let provider_selector = row![zfs_btn, luks_btn].spacing(8);

        // Combine tabs and selector
        let content = row![
            tabs,
            container(text("Provider:").size(14)).padding([0, 10]),
            provider_selector,
        ]
        .spacing(20)
        .padding(12)
        .align_y(Alignment::Center);

        container(content).width(Length::Fill).into()
    }
}
