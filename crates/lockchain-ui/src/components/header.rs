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
    /// Whether workflow is executing (disables provider switching).
    workflow_executing: bool,
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
            workflow_executing: false,
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

    /// Sets workflow execution state.
    pub fn set_workflow_executing(&mut self, executing: bool) {
        self.workflow_executing = executing;
    }

    /// Renders the header with navigation tabs and provider selector.
    pub fn view(&self, active_panel: PanelKind) -> Element<'_, HeaderMessage> {
        // Mode indicator - prominent badge showing active provider
        let mode_text = match self.current_provider {
            ProviderKind::Zfs => "MODE: ZFS",
            ProviderKind::Luks => "MODE: LUKS",
            ProviderKind::Auto => "MODE: AUTO",
        };

        let mode_indicator = container(
            text(mode_text).size(16).color(iced::color!(0x00ff00)), // Bright green
        )
        .padding([8, 16])
        .style(|_theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(iced::color!(0x1a1a1a))),
            border: iced::Border {
                color: match self.current_provider {
                    ProviderKind::Zfs => iced::color!(0x00aaff), // Blue for ZFS
                    ProviderKind::Luks => iced::color!(0xff6600), // Orange for LUKS
                    ProviderKind::Auto => iced::color!(0x888888), // Gray for Auto
                },
                width: 2.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        });

        // Navigation tabs
        let mut tabs = row![].spacing(8).align_y(Alignment::Center);

        for panel in PanelKind::all() {
            let label = panel.label();
            let is_active = *panel == active_panel;

            let btn = button(text(label).size(14).color(if is_active {
                iced::color!(0xffffff) // White for active
            } else {
                iced::color!(0xaaaaaa) // Gray for inactive
            }))
            .padding([8, 16])
            .style(move |_theme: &iced::Theme, status: button::Status| {
                let base_color = if is_active {
                    iced::color!(0x2a2a2a) // Dark gray for active
                } else {
                    iced::color!(0x1a1a1a) // Darker for inactive
                };

                button::Style {
                    background: Some(iced::Background::Color(match status {
                        button::Status::Hovered => iced::color!(0x3a3a3a),
                        _ => base_color,
                    })),
                    border: iced::Border {
                        color: if is_active {
                            iced::color!(0x00aaff)
                        } else {
                            iced::color!(0x333333)
                        },
                        width: if is_active { 2.0 } else { 1.0 },
                        radius: 4.0.into(),
                    },
                    text_color: if is_active {
                        iced::color!(0xffffff)
                    } else {
                        iced::color!(0xaaaaaa)
                    },
                    ..Default::default()
                }
            })
            .on_press(HeaderMessage::PanelSelected(*panel));

            tabs = tabs.push(btn);
        }

        // Provider selector using styled buttons
        let zfs_active = self.current_provider == ProviderKind::Zfs;
        let luks_active = self.current_provider == ProviderKind::Luks;
        let can_switch = !self.workflow_executing;

        let mut zfs_btn = button(text("ZFS").size(14).color(if !can_switch {
            iced::color!(0x555555) // Grayed out when disabled
        } else if zfs_active {
            iced::color!(0xffffff)
        } else {
            iced::color!(0xaaaaaa)
        }))
        .padding([6, 12])
        .style(
            move |_theme: &iced::Theme, status: button::Status| button::Style {
                background: Some(iced::Background::Color(if !can_switch {
                    iced::color!(0x0a0a0a) // Darker when disabled
                } else {
                    match status {
                        button::Status::Hovered => iced::color!(0x3a3a3a),
                        _ if zfs_active => iced::color!(0x005588),
                        _ => iced::color!(0x1a1a1a),
                    }
                })),
                border: iced::Border {
                    color: if !can_switch {
                        iced::color!(0x222222)
                    } else if zfs_active {
                        iced::color!(0x00aaff)
                    } else {
                        iced::color!(0x333333)
                    },
                    width: if zfs_active { 2.0 } else { 1.0 },
                    radius: 4.0.into(),
                },
                ..Default::default()
            },
        );

        if can_switch {
            zfs_btn = zfs_btn.on_press(HeaderMessage::ProviderSelected(ProviderKind::Zfs));
        }

        let mut luks_btn = button(text("LUKS").size(14).color(if !can_switch {
            iced::color!(0x555555) // Grayed out when disabled
        } else if luks_active {
            iced::color!(0xffffff)
        } else {
            iced::color!(0xaaaaaa)
        }))
        .padding([6, 12])
        .style(
            move |_theme: &iced::Theme, status: button::Status| button::Style {
                background: Some(iced::Background::Color(if !can_switch {
                    iced::color!(0x0a0a0a) // Darker when disabled
                } else {
                    match status {
                        button::Status::Hovered => iced::color!(0x3a3a3a),
                        _ if luks_active => iced::color!(0x884400),
                        _ => iced::color!(0x1a1a1a),
                    }
                })),
                border: iced::Border {
                    color: if !can_switch {
                        iced::color!(0x222222)
                    } else if luks_active {
                        iced::color!(0xff6600)
                    } else {
                        iced::color!(0x333333)
                    },
                    width: if luks_active { 2.0 } else { 1.0 },
                    radius: 4.0.into(),
                },
                ..Default::default()
            },
        );

        if can_switch {
            luks_btn = luks_btn.on_press(HeaderMessage::ProviderSelected(ProviderKind::Luks));
        }

        let mut provider_selector_items = vec![
            container(text("Switch Provider:").size(14))
                .padding([0, 10])
                .into(),
            zfs_btn.into(),
            luks_btn.into(),
        ];

        // Add disabled warning message if workflow is executing
        if !can_switch {
            provider_selector_items.push(
                container(
                    text("(disabled during workflow)")
                        .size(12)
                        .color(iced::color!(0xff8800)),
                )
                .padding([0, 8])
                .into(),
            );
        }

        let provider_selector = row(provider_selector_items)
            .spacing(8)
            .align_y(Alignment::Center);

        // Combine all elements: mode indicator, tabs, provider selector
        let content = row![mode_indicator, tabs, provider_selector,]
            .spacing(20)
            .padding(12)
            .align_y(Alignment::Center);

        container(content).width(Length::Fill).into()
    }
}
