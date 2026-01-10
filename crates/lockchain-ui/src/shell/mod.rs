//! AppShell: Main application orchestrator.
//!
//! Coordinates panels, shared components, provider context, and navigation.

use std::path::PathBuf;

use iced::{Element, Task, Theme};
use lockchain_core::config::DEFAULT_CONFIG_PATH;
use lockchain_core::provider::ProviderKind;

use crate::components::{HeaderState, MissionReportState, TerminalState};
use crate::dispatcher::{CommandDispatcher, WorkflowCommand, WorkflowResult};
use crate::panels::{
    health::HealthPanel, key::KeyPanel, settings::SettingsPanel, targets::TargetsPanel, PanelKind,
    ProviderPanel,
};
use crate::provider::ProviderContext;

pub mod view;

/// Main application shell state.
pub struct AppShell {
    /// Currently active panel.
    active_panel: PanelKind,

    /// Provider context (manages active provider and config).
    provider_ctx: ProviderContext,

    /// Panel instances.
    targets_panel: TargetsPanel,
    key_panel: KeyPanel,
    settings_panel: SettingsPanel,
    health_panel: HealthPanel,

    /// Shared components.
    terminal: TerminalState,
    header: HeaderState,
    mission_report: MissionReportState,

    /// Command dispatcher.
    dispatcher: CommandDispatcher,
}

/// Messages for the AppShell.
#[derive(Debug, Clone)]
pub enum AppShellMessage {
    /// Panel selection changed.
    PanelSelected(PanelKind),

    /// Provider changed via header selector.
    ProviderSwitched(ProviderKind),

    /// Messages from panels (wrapped).
    TargetsMessage(crate::panels::targets::TargetsMessage),
    KeyMessage(crate::panels::key::KeyMessage),
    SettingsMessage(crate::panels::settings::SettingsMessage),
    HealthMessage(Box<crate::panels::health::HealthMessage>),

    /// Terminal messages.
    TerminalInputChanged(String),
    TerminalSubmit,
    TerminalClear,
    TerminalDownloadLogs,

    /// Workflow execution.
    ExecuteWorkflow(WorkflowCommand),
    WorkflowFinished(WorkflowResult),

    /// Periodic key status refresh timer.
    RefreshKeyStatus,
}

impl AppShell {
    /// Creates a new AppShell from config path.
    pub fn new(config_path: PathBuf) -> Result<Self, String> {
        let config_path_str = config_path.to_string_lossy().to_string();
        let provider_ctx = ProviderContext::new(config_path)?;
        let current_provider = provider_ctx.current_provider();

        // Load targets from config
        let targets = provider_ctx
            .config_arc()
            .lock()
            .map(|cfg| cfg.policy.targets.clone())
            .unwrap_or_default();

        let mut targets_panel = TargetsPanel::new(current_provider);
        targets_panel.load_targets_from_config(targets.clone());

        // Set up settings panel with config info
        let mut settings_panel = SettingsPanel::new(current_provider);
        settings_panel.set_config_info(config_path_str, targets.len());

        // Set up health panel with initial key status
        let mut health_panel = HealthPanel::new(current_provider);
        if let Ok(cfg) = provider_ctx.config_arc().lock() {
            health_panel.init_with_config(&cfg);
        }

        Ok(Self {
            active_panel: PanelKind::Targets,
            targets_panel,
            key_panel: KeyPanel::new(current_provider),
            settings_panel,
            health_panel,
            terminal: TerminalState::new(),
            header: HeaderState::new(current_provider),
            mission_report: MissionReportState::new(),
            dispatcher: CommandDispatcher::new(),
            provider_ctx,
        })
    }

    /// Returns the application title.
    #[allow(dead_code)]
    pub fn title(&self) -> String {
        format!("Lockchain Control Deck - {}", self.active_panel.label())
    }

    /// Handles AppShell messages and returns tasks.
    pub fn update(&mut self, message: AppShellMessage) -> Task<AppShellMessage> {
        match message {
            AppShellMessage::PanelSelected(panel) => {
                self.active_panel = panel;
                self.terminal.push_line(
                    crate::components::TerminalLevel::Info,
                    format!("Switched to {} panel", panel.label()),
                );
                Task::none()
            }

            AppShellMessage::ProviderSwitched(kind) => {
                match self.provider_ctx.switch_provider(kind) {
                    Ok(()) => {
                        self.header.set_provider(kind);

                        // Notify all panels of provider change
                        self.targets_panel.on_provider_changed(kind);
                        self.key_panel.on_provider_changed(kind);
                        self.settings_panel.on_provider_changed(kind);
                        self.health_panel.on_provider_changed(kind);

                        self.terminal.push_line(
                            crate::components::TerminalLevel::Success,
                            format!("Switched to {:?} provider", kind),
                        );
                    }
                    Err(e) => {
                        self.terminal.push_line(
                            crate::components::TerminalLevel::Error,
                            format!("Failed to switch provider: {}", e),
                        );
                    }
                }
                Task::none()
            }

            // Panel messages (delegate to panels)
            AppShellMessage::TargetsMessage(msg) => {
                // Check if this is a workflow request that needs to bubble up
                if let crate::panels::targets::TargetsMessage::RequestWorkflow(command) = msg {
                    return Task::done(AppShellMessage::ExecuteWorkflow(command));
                }
                self.targets_panel
                    .update(msg)
                    .map(AppShellMessage::TargetsMessage)
            }
            AppShellMessage::KeyMessage(msg) => {
                // Check if this is a workflow request that needs to bubble up
                if let crate::panels::key::KeyMessage::RequestWorkflow(command) = msg {
                    return Task::done(AppShellMessage::ExecuteWorkflow(command));
                }
                self.key_panel.update(msg).map(AppShellMessage::KeyMessage)
            }
            AppShellMessage::SettingsMessage(msg) => self
                .settings_panel
                .update(msg)
                .map(AppShellMessage::SettingsMessage),
            AppShellMessage::HealthMessage(msg) => {
                // Check if this is a workflow request that needs to bubble up
                if let crate::panels::health::HealthMessage::RequestWorkflow(command) = *msg {
                    return Task::done(AppShellMessage::ExecuteWorkflow(command));
                }
                // Check if this is a ShowTerminal request
                if let crate::panels::health::HealthMessage::ShowTerminal = *msg {
                    // Switch to terminal view (if we had panel tabs, we'd switch to Terminal)
                    // For now, just log to terminal
                    self.terminal.push_line(
                        crate::components::TerminalLevel::Info,
                        "View logs above for key status diagnostics".to_string(),
                    );
                    return Task::none();
                }
                self.health_panel
                    .update(*msg)
                    .map(|m| AppShellMessage::HealthMessage(Box::new(m)))
            }

            // Terminal messages
            AppShellMessage::TerminalInputChanged(input) => {
                self.terminal.set_input(input);
                Task::none()
            }
            AppShellMessage::TerminalSubmit => {
                let input = self.terminal.input().to_string();
                if !input.is_empty() {
                    self.terminal.push_line(
                        crate::components::TerminalLevel::Input,
                        format!("> {}", input),
                    );
                    self.terminal.set_input(String::new());
                    // TODO: Parse and execute command
                }
                Task::none()
            }
            AppShellMessage::TerminalClear => {
                self.terminal.clear();
                Task::none()
            }
            AppShellMessage::TerminalDownloadLogs => {
                let log_content = self.terminal.export_log();
                // TODO: Save log to file
                eprintln!("Log export requested ({} bytes)", log_content.len());
                Task::none()
            }

            // Workflow execution
            AppShellMessage::ExecuteWorkflow(command) => {
                if self.dispatcher.is_executing() {
                    self.terminal.push_line(
                        crate::components::TerminalLevel::Warning,
                        "Another workflow is already executing".to_string(),
                    );
                    return Task::none();
                }

                self.dispatcher.start_execution();
                self.header.set_workflow_executing(true); // Disable provider switching
                self.mission_report
                    .start_mission("Executing workflow...".to_string());

                // Spawn async workflow
                let provider_kind = self.provider_ctx.current_provider();
                let config = self.provider_ctx.config_arc();
                let zfs_provider = self.provider_ctx.zfs_provider().clone();
                let luks_provider = self.provider_ctx.luks_provider().clone();

                Task::perform(
                    async move {
                        crate::dispatcher::workflow::execute_workflow(
                            command,
                            provider_kind,
                            config,
                            &zfs_provider,
                            &luks_provider,
                        )
                        .await
                    },
                    AppShellMessage::WorkflowFinished,
                )
            }

            AppShellMessage::WorkflowFinished(result) => {
                self.dispatcher.finish_execution();
                self.header.set_workflow_executing(false); // Re-enable provider switching

                match result {
                    Ok(report) => {
                        self.mission_report.complete_mission();
                        self.terminal.push_line(
                            crate::components::TerminalLevel::Success,
                            format!("Workflow completed: {}", report.title),
                        );

                        // Push workflow events to terminal
                        for event in report.events {
                            let level = match event.level {
                                lockchain_core::workflow::WorkflowLevel::Info => {
                                    crate::components::TerminalLevel::Info
                                }
                                lockchain_core::workflow::WorkflowLevel::Success => {
                                    crate::components::TerminalLevel::Success
                                }
                                lockchain_core::workflow::WorkflowLevel::Warn => {
                                    crate::components::TerminalLevel::Warning
                                }
                                lockchain_core::workflow::WorkflowLevel::Error => {
                                    crate::components::TerminalLevel::Error
                                }
                                lockchain_core::workflow::WorkflowLevel::Security => {
                                    crate::components::TerminalLevel::Security
                                }
                            };
                            self.terminal.push_line(level, event.message);
                            self.mission_report.increment_events(1);
                        }
                    }
                    Err(e) => {
                        self.mission_report.fail_mission(e.clone());
                        self.terminal.push_line(
                            crate::components::TerminalLevel::Error,
                            format!("Workflow failed: {}", e),
                        );
                    }
                }

                Task::none()
            }

            AppShellMessage::RefreshKeyStatus => {
                // Refresh key status in HealthPanel
                if let Ok(config) = self.provider_ctx.config_arc().lock() {
                    self.health_panel
                        .update(crate::panels::health::HealthMessage::RefreshKeyStatus(
                            Box::new((*config).clone()),
                        ))
                        .map(|m| AppShellMessage::HealthMessage(Box::new(m)))
                } else {
                    Task::none()
                }
            }
        }
    }

    /// Renders the AppShell view (delegated to view module).
    pub fn view(&self) -> Element<'_, AppShellMessage> {
        view::render(self)
    }

    /// Subscription for periodic events (auto-refresh).
    pub fn subscription(&self) -> iced::Subscription<AppShellMessage> {
        use iced::time;
        use std::time::Duration;

        // Auto-refresh key status every 5 seconds
        time::every(Duration::from_secs(5)).map(|_| AppShellMessage::RefreshKeyStatus)
    }

    /// Initializes the AppShell (called by Iced on startup).
    pub fn init() -> (Self, Task<AppShellMessage>) {
        let config_path = PathBuf::from(DEFAULT_CONFIG_PATH);

        match Self::new(config_path) {
            Ok(shell) => (shell, Task::none()),
            Err(e) => {
                eprintln!("Failed to initialize AppShell: {}", e);
                // Create a minimal shell with default state
                // This is a fallback - in production you might want to show an error screen
                std::process::exit(1);
            }
        }
    }

    /// Returns the application theme (dark theme for now).
    pub fn theme(&self) -> Theme {
        Theme::Dark
    }
}

/// Launch the AppShell application with the Iced framework.
pub fn run() -> iced::Result {
    iced::application("Lockchain Control Deck", AppShell::update, AppShell::view)
        .theme(AppShell::theme)
        .subscription(AppShell::subscription)
        .run_with(AppShell::init)
}
