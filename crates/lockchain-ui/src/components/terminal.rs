//! Terminal component for displaying command output and logs.

use chrono::Utc;
use iced::{
    widget::{column, container, scrollable, text},
    Element, Length,
};
use std::collections::VecDeque;

/// Terminal line level (maps to colors/styles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalLevel {
    Input,
    #[allow(dead_code)]
    Prompt,
    Info,
    Success,
    Warning,
    Error,
    Security,
}

/// A single line in the terminal.
#[derive(Debug, Clone)]
pub struct TerminalLine {
    pub level: TerminalLevel,
    pub message: String,
    pub timestamp: chrono::DateTime<Utc>,
}

impl TerminalLine {
    /// Creates a new terminal line.
    pub fn new(level: TerminalLevel, message: String) -> Self {
        Self {
            level,
            message,
            timestamp: Utc::now(),
        }
    }
}

/// State for the terminal component.
pub struct TerminalState {
    /// Persistent history (limited to max_lines).
    lines: VecDeque<TerminalLine>,

    /// Maximum number of lines to keep.
    max_lines: usize,

    /// Current input text.
    input: String,
}

/// Messages for terminal interaction.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TerminalMessage {
    /// Input text changed.
    InputChanged(String),
    /// User pressed enter to submit.
    Submit,
    /// Clear terminal history.
    Clear,
    /// Download logs to file.
    DownloadLogs,
}

impl TerminalState {
    /// Creates a new terminal state.
    pub fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            max_lines: 200,
            input: String::new(),
        }
    }

    /// Adds a line to the terminal.
    pub fn push_line(&mut self, level: TerminalLevel, message: String) {
        self.lines.push_back(TerminalLine::new(level, message));

        // Trim to max lines
        while self.lines.len() > self.max_lines {
            self.lines.pop_front();
        }
    }

    /// Adds multiple lines to the terminal.
    #[allow(dead_code)]
    pub fn push_lines(&mut self, lines: impl IntoIterator<Item = (TerminalLevel, String)>) {
        for (level, message) in lines {
            self.push_line(level, message);
        }
    }

    /// Clears all terminal lines.
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Gets the current input.
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Sets the input text.
    pub fn set_input(&mut self, input: String) {
        self.input = input;
    }

    /// Gets all terminal lines.
    #[allow(dead_code)]
    pub fn lines(&self) -> &VecDeque<TerminalLine> {
        &self.lines
    }

    /// Renders the terminal view.
    pub fn view(&self) -> Element<'_, TerminalMessage> {
        let lines_view = self.lines.iter().map(|line| {
            let color = match line.level {
                TerminalLevel::Input => iced::Color::from_rgb(0.8, 0.8, 0.8),
                TerminalLevel::Prompt => iced::Color::from_rgb(0.0, 0.83, 0.97),
                TerminalLevel::Info => iced::Color::from_rgb(0.4, 0.6, 1.0),
                TerminalLevel::Success => iced::Color::from_rgb(0.0, 1.0, 0.53),
                TerminalLevel::Warning => iced::Color::from_rgb(1.0, 0.65, 0.0),
                TerminalLevel::Error => iced::Color::from_rgb(0.89, 0.13, 0.23),
                TerminalLevel::Security => iced::Color::from_rgb(1.0, 0.0, 1.0),
            };

            text(&line.message).color(color).size(14).into()
        });

        let content = column(lines_view).spacing(4).padding(10);

        container(scrollable(content))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// Exports terminal log as markdown.
    pub fn export_log(&self) -> String {
        let mut output = String::from("# Lockchain Terminal Log\n\n");

        for line in &self.lines {
            let level_str = match line.level {
                TerminalLevel::Input => "INPUT",
                TerminalLevel::Prompt => "PROMPT",
                TerminalLevel::Info => "INFO",
                TerminalLevel::Success => "SUCCESS",
                TerminalLevel::Warning => "WARNING",
                TerminalLevel::Error => "ERROR",
                TerminalLevel::Security => "SECURITY",
            };

            output.push_str(&format!(
                "[{}] {}: {}\n",
                line.timestamp.format("%Y-%m-%d %H:%M:%S"),
                level_str,
                line.message
            ));
        }

        output
    }
}

impl Default for TerminalState {
    fn default() -> Self {
        Self::new()
    }
}
