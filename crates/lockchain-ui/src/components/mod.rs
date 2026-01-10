//! Shared UI components used across panels.
//!
//! These components provide consistent UI elements like terminal output,
//! status displays, and navigation headers.

pub mod terminal;
pub mod header;
pub mod mission_report;

pub use terminal::{TerminalState, TerminalMessage, TerminalLevel};
pub use header::{HeaderState, HeaderMessage};
pub use mission_report::MissionReportState;
