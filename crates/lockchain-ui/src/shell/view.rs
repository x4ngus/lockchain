//! AppShell view rendering.

use iced::{
    widget::{column, container},
    Element, Length,
};

use super::{AppShell, AppShellMessage};
use crate::panels::PanelKind;

// Import ProviderPanel trait for calling view() on panels
use crate::panels::ProviderPanel as _;

/// Renders the complete AppShell UI.
pub fn render(shell: &AppShell) -> Element<'_, AppShellMessage> {
    let content = column![
        // Header with navigation and provider selector
        render_header(shell),
        // Active panel content
        render_active_panel(shell),
        // Terminal (shared across all panels)
        render_terminal(shell),
        // Mission report / status bar
        render_mission_report(shell),
    ]
    .spacing(0);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(12)
        .into()
}

/// Renders the header with navigation tabs and provider selector.
fn render_header(shell: &AppShell) -> Element<'_, AppShellMessage> {
    shell.header.view(shell.active_panel).map(|msg| match msg {
        crate::components::HeaderMessage::PanelSelected(panel) => {
            AppShellMessage::PanelSelected(panel)
        }
        crate::components::HeaderMessage::ProviderSelected(kind) => {
            AppShellMessage::ProviderSwitched(kind)
        }
    })
}

/// Renders the currently active panel.
fn render_active_panel(shell: &AppShell) -> Element<'_, AppShellMessage> {
    match shell.active_panel {
        PanelKind::Targets => shell
            .targets_panel
            .view()
            .map(AppShellMessage::TargetsMessage),
        PanelKind::Key => shell.key_panel.view().map(AppShellMessage::KeyMessage),
        PanelKind::Settings => shell
            .settings_panel
            .view()
            .map(AppShellMessage::SettingsMessage),
        PanelKind::Health => shell
            .health_panel
            .view()
            .map(AppShellMessage::HealthMessage),
    }
}

/// Renders the terminal component.
fn render_terminal(shell: &AppShell) -> Element<'_, AppShellMessage> {
    shell.terminal.view().map(|msg| match msg {
        crate::components::TerminalMessage::InputChanged(input) => {
            AppShellMessage::TerminalInputChanged(input)
        }
        crate::components::TerminalMessage::Submit => AppShellMessage::TerminalSubmit,
        crate::components::TerminalMessage::Clear => AppShellMessage::TerminalClear,
        crate::components::TerminalMessage::DownloadLogs => AppShellMessage::TerminalDownloadLogs,
    })
}

/// Renders the mission report component.
fn render_mission_report(shell: &AppShell) -> Element<'_, AppShellMessage> {
    shell.mission_report.view().map(|_msg| {
        // Mission report currently has no interactive messages
        // If it did, we'd map them here
        AppShellMessage::TerminalClear // Placeholder, never used
    })
}
