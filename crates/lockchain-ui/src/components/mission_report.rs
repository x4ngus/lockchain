//! Mission report component for displaying progress and status.

use iced::{widget::{row, text, container, progress_bar}, Element, Length};

/// Mission phase state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissionPhase {
    Hidden,
    Active,
    Completed,
    Failed,
}

/// State for the mission report component.
pub struct MissionReportState {
    /// Current mission phase.
    phase: MissionPhase,

    /// Progress value (0.0 to 1.0).
    progress: f32,

    /// Progress message.
    message: Option<String>,

    /// Event counter.
    event_count: usize,
}

/// Messages for mission report interaction.
#[derive(Debug, Clone)]
pub enum MissionReportMessage {
    // No interactive messages for now
}

impl MissionReportState {
    /// Creates a new mission report state.
    pub fn new() -> Self {
        Self {
            phase: MissionPhase::Hidden,
            progress: 0.0,
            message: None,
            event_count: 0,
        }
    }

    /// Starts a new mission.
    pub fn start_mission(&mut self, message: String) {
        self.phase = MissionPhase::Active;
        self.progress = 0.0;
        self.message = Some(message);
        self.event_count = 0;
    }

    /// Updates mission progress.
    #[allow(dead_code)]
    pub fn update_progress(&mut self, progress: f32, message: Option<String>) {
        if self.phase == MissionPhase::Active {
            self.progress = progress.clamp(0.0, 1.0);
            if let Some(msg) = message {
                self.message = Some(msg);
            }
        }
    }

    /// Increments the event counter.
    pub fn increment_events(&mut self, count: usize) {
        self.event_count += count;
    }

    /// Marks mission as completed.
    pub fn complete_mission(&mut self) {
        self.phase = MissionPhase::Completed;
        self.progress = 1.0;
    }

    /// Marks mission as failed.
    pub fn fail_mission(&mut self, error: String) {
        self.phase = MissionPhase::Failed;
        self.message = Some(error);
    }

    /// Hides the mission report.
    #[allow(dead_code)]
    pub fn hide(&mut self) {
        self.phase = MissionPhase::Hidden;
        self.progress = 0.0;
        self.message = None;
        self.event_count = 0;
    }

    /// Gets the current phase.
    #[allow(dead_code)]
    pub fn phase(&self) -> MissionPhase {
        self.phase
    }

    /// Renders the mission report view.
    pub fn view(&self) -> Element<'_, MissionReportMessage> {
        if self.phase == MissionPhase::Hidden {
            return container(text("")).into();
        }

        let phase_text = match self.phase {
            MissionPhase::Hidden => "",
            MissionPhase::Active => "ACTIVE",
            MissionPhase::Completed => "COMPLETED",
            MissionPhase::Failed => "FAILED",
        };

        let phase_color = match self.phase {
            MissionPhase::Hidden => iced::Color::WHITE,
            MissionPhase::Active => iced::Color::from_rgb(0.0, 0.83, 0.97),
            MissionPhase::Completed => iced::Color::from_rgb(0.0, 1.0, 0.53),
            MissionPhase::Failed => iced::Color::from_rgb(0.89, 0.13, 0.23),
        };

        let message_text = self.message.as_deref().unwrap_or("Processing...");

        let content = row![
            text(phase_text)
                .size(16)
                .color(phase_color),
            container(progress_bar(0.0..=1.0, self.progress))
                .width(Length::Fill),
            text(format!("Events: {}", self.event_count))
                .size(14),
            text(message_text)
                .size(14),
        ]
        .spacing(16)
        .padding(12);

        container(content)
            .width(Length::Fill)
            .into()
    }
}

impl Default for MissionReportState {
    fn default() -> Self {
        Self::new()
    }
}
