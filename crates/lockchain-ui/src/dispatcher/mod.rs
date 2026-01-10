//! Command dispatcher for executing workflows.
//!
//! Coordinates async workflow execution, progress tracking, and result handling.

use lockchain_core::workflow::{ForgeMode, ProvisionOptions, WorkflowReport};

pub mod workflow;

/// Commands that can be dispatched to the workflow engine.
#[derive(Debug, Clone)]
pub enum WorkflowCommand {
    /// Forge a new key for a target.
    ForgeKey {
        dataset: String,
        mode: ForgeMode,
        options: ProvisionOptions,
    },

    /// Run self-test on a target.
    SelfTest { dataset: String },

    /// Recover key from passphrase or hex.
    RecoverKey { key_material: Vec<u8> },

    /// Recover USB key using recovery code.
    RecoverUsb,

    /// Run system diagnostics.
    Diagnostics,

    /// Check status of a target (ZFS dataset or LUKS volume).
    Status { target: String },

    /// Unlock a target (ZFS dataset or LUKS volume).
    Unlock { target: String },
}

/// State for tracking command execution.
pub struct CommandDispatcher {
    /// Whether a command is currently executing.
    executing: bool,

    /// Current progress (0.0 to 1.0).
    progress: f32,

    /// Progress message.
    progress_message: Option<String>,
}

impl CommandDispatcher {
    /// Creates a new command dispatcher.
    pub fn new() -> Self {
        Self {
            executing: false,
            progress: 0.0,
            progress_message: None,
        }
    }

    /// Checks if a command is currently executing.
    pub fn is_executing(&self) -> bool {
        self.executing
    }

    /// Gets current progress (0.0 to 1.0).
    #[allow(dead_code)]
    pub fn progress(&self) -> f32 {
        self.progress
    }

    /// Gets the current progress message.
    #[allow(dead_code)]
    pub fn progress_message(&self) -> Option<&str> {
        self.progress_message.as_deref()
    }

    /// Marks execution as started.
    pub fn start_execution(&mut self) {
        self.executing = true;
        self.progress = 0.0;
        self.progress_message = Some("Initializing...".to_string());
    }

    /// Updates progress.
    #[allow(dead_code)]
    pub fn update_progress(&mut self, progress: f32, message: Option<String>) {
        self.progress = progress.clamp(0.0, 1.0);
        if let Some(msg) = message {
            self.progress_message = Some(msg);
        }
    }

    /// Marks execution as finished.
    pub fn finish_execution(&mut self) {
        self.executing = false;
        self.progress = 1.0;
        self.progress_message = None;
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a workflow execution.
pub type WorkflowResult = Result<WorkflowReport, String>;
