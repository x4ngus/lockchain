//! Shared UI components used across panels.
//!
//! These components provide consistent UI elements like terminal output,
//! status displays, and navigation headers.

pub mod header;
pub mod key_status;
pub mod mission_report;
pub mod terminal;

pub use header::{HeaderMessage, HeaderState};
pub use key_status::{KeyStatus, KeyStatusMessage, KeyStatusState};
pub use mission_report::MissionReportState;
pub use terminal::{TerminalLevel, TerminalMessage, TerminalState};
