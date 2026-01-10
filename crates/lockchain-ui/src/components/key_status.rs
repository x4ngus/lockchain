//! Key/USB status display component.
//!
//! Shows:
//! - USB device presence and checksum validation
//! - Key staging locations (/run/lockchain, /run/cryptsetup-keys.d)
//! - Whether keys are properly staged for unlock
//! - Quick diagnostics for why unlock might fail

use iced::{
    widget::{button, column, container, row, text, Column, Space},
    Alignment, Element, Length,
};
use lockchain_core::config::LockchainConfig;
use lockchain_core::provider::ProviderKind;
use std::path::Path;

/// Status of a key staging location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingStatus {
    /// Key file present and valid.
    Present,
    /// Key file missing or inaccessible.
    Missing,
    /// Status unknown (cannot check).
    Unknown,
}

/// USB device detection status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbStatus {
    /// USB device present with valid checksum.
    PresentValid,
    /// USB device present but checksum mismatch.
    PresentInvalid { expected: String, actual: String },
    /// USB device not detected.
    NotPresent,
    /// USB checksum not configured.
    NotConfigured,
}

/// Detailed LUKS mapping status.
#[derive(Debug, Clone)]
pub struct LuksMappingStatus {
    pub mapping_name: String,
    pub key_file_path: String,
    pub status: StagingStatus,
}

/// Current key status snapshot.
#[derive(Debug, Clone)]
pub struct KeyStatus {
    /// USB device status.
    pub usb: UsbStatus,

    /// Status of /run/lockchain staging.
    pub run_lockchain_status: StagingStatus,

    /// Status of /run/cryptsetup-keys.d staging (LUKS only).
    pub cryptsetup_keys_status: StagingStatus,

    /// Detailed per-mapping status for LUKS.
    pub luks_mappings: Vec<LuksMappingStatus>,

    /// Configured key path.
    pub key_path: String,

    /// Whether the provider is currently active.
    pub provider: ProviderKind,
}

impl KeyStatus {
    /// Create a new key status by checking filesystem state.
    pub fn check(config: &LockchainConfig, provider: ProviderKind) -> Self {
        let usb = check_usb_status(config);
        let key_path = config.key_hex_path();
        let run_lockchain_status = check_staging_location(&key_path);

        let (cryptsetup_keys_status, luks_mappings) = if provider == ProviderKind::Luks {
            let mappings = get_luks_mapping_status(config);
            let overall_status = if mappings.iter().any(|m| m.status == StagingStatus::Present) {
                StagingStatus::Present
            } else if mappings.is_empty() {
                StagingStatus::Unknown
            } else {
                StagingStatus::Missing
            };
            (overall_status, mappings)
        } else {
            (StagingStatus::Unknown, Vec::new())
        };

        Self {
            usb,
            run_lockchain_status,
            cryptsetup_keys_status,
            luks_mappings,
            key_path: key_path.display().to_string(),
            provider,
        }
    }

    /// Returns true if all required keys are staged for unlock.
    pub fn ready_for_unlock(&self) -> bool {
        match self.provider {
            ProviderKind::Zfs => {
                matches!(self.usb, UsbStatus::PresentValid | UsbStatus::NotConfigured)
                    && self.run_lockchain_status == StagingStatus::Present
            }
            ProviderKind::Luks => {
                matches!(self.usb, UsbStatus::PresentValid | UsbStatus::NotConfigured)
                    && self.run_lockchain_status == StagingStatus::Present
                    && self.cryptsetup_keys_status == StagingStatus::Present
            }
            ProviderKind::Auto => false,
        }
    }

    /// Returns a human-readable summary of why unlock might fail.
    pub fn diagnostic_message(&self) -> Option<String> {
        if self.ready_for_unlock() {
            return None;
        }

        let mut issues = Vec::new();

        match &self.usb {
            UsbStatus::PresentInvalid { expected, actual } => {
                issues.push(format!(
                    "USB checksum mismatch (expected {}, got {})",
                    &expected[..8],
                    &actual[..8]
                ));
            }
            UsbStatus::NotPresent => {
                issues.push("USB device not detected".to_string());
            }
            _ => {}
        }

        if self.run_lockchain_status != StagingStatus::Present {
            issues.push("Key not staged in /run/lockchain".to_string());
        }

        if self.provider == ProviderKind::Luks
            && self.cryptsetup_keys_status != StagingStatus::Present
        {
            issues.push("LUKS keys not staged in /run/cryptsetup-keys.d".to_string());
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues.join("; "))
        }
    }
}

/// Component state for key status display.
#[derive(Debug, Clone)]
pub struct KeyStatusState {
    status: Option<KeyStatus>,
}

/// Messages for key status component.
#[derive(Debug, Clone)]
pub enum KeyStatusMessage {
    /// Refresh key status by checking filesystem.
    Refresh,

    /// Show terminal/logs for debugging.
    ShowLogs,

    /// Initiate USB recovery workflow.
    RecoverUsb,

    /// Inspect a file path (open in editor/viewer).
    InspectPath(String),

    /// Periodic auto-refresh timer tick.
    AutoRefresh,
}

impl KeyStatusState {
    /// Create a new key status component.
    pub fn new() -> Self {
        Self { status: None }
    }

    /// Update the status with fresh data.
    pub fn update(&mut self, status: KeyStatus) {
        self.status = Some(status);
    }

    /// Get the current status.
    pub fn status(&self) -> Option<&KeyStatus> {
        self.status.as_ref()
    }

    /// Render the key status UI.
    pub fn view(&self) -> Element<'_, KeyStatusMessage> {
        let Some(status) = &self.status else {
            return container(text("Loading key status...")).padding(20).into();
        };

        let mut content = Column::new().spacing(15).padding(20).width(Length::Fill);

        // USB Status Section
        content = content.push(text("USB Device Status").size(18));
        content = content.push(render_usb_status(&status.usb));

        content = content.push(Space::new(0, 10));

        // Staging Locations Section
        content = content.push(text("Key Staging Locations").size(18));

        // Main key path with clickable link
        let key_path_button = button(text(&status.key_path).size(12))
            .on_press(KeyStatusMessage::InspectPath(status.key_path.clone()))
            .style(|_theme, _status| button::Style {
                background: None,
                text_color: iced::Color::from_rgb(0.3, 0.5, 0.8),
                border: iced::Border::default(),
                shadow: iced::Shadow::default(),
            });

        content = content.push(
            row![
                render_staging_icon(status.run_lockchain_status),
                text("/run/lockchain: "),
                key_path_button,
            ]
            .spacing(5)
            .align_y(Alignment::Center),
        );

        // LUKS-specific detailed mappings
        if status.provider == ProviderKind::Luks {
            content = content.push(Space::new(0, 5));
            content = content.push(text("/run/cryptsetup-keys.d mappings:").size(14));

            if status.luks_mappings.is_empty() {
                content = content.push(text("  No LUKS mappings configured").size(12));
            } else {
                for mapping in &status.luks_mappings {
                    let mapping_path_btn = button(text(&mapping.key_file_path).size(11))
                        .on_press(KeyStatusMessage::InspectPath(mapping.key_file_path.clone()))
                        .style(|_theme, _status| button::Style {
                            background: None,
                            text_color: iced::Color::from_rgb(0.3, 0.5, 0.8),
                            border: iced::Border::default(),
                            shadow: iced::Shadow::default(),
                        });

                    content = content.push(
                        row![
                            Space::with_width(20),
                            render_staging_icon(mapping.status),
                            text(format!("{}: ", mapping.mapping_name)).size(12),
                            mapping_path_btn,
                        ]
                        .spacing(5)
                        .align_y(Alignment::Center),
                    );
                }
            }
        }

        content = content.push(Space::new(0, 10));

        // Overall Status
        if status.ready_for_unlock() {
            content = content.push(
                container(text("✓ Ready for unlock").style(|_theme| text::Style {
                    color: Some(iced::Color::from_rgb(0.0, 0.8, 0.0)),
                }))
                .padding(10)
                .style(|_theme| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgb(
                        0.0, 0.2, 0.0,
                    ))),
                    border: iced::Border {
                        color: iced::Color::from_rgb(0.0, 0.8, 0.0),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }),
            );
        } else if let Some(msg) = status.diagnostic_message() {
            content = content.push(
                container(
                    column![
                        text("⚠ Not ready for unlock").style(|_theme| {
                            text::Style {
                                color: Some(iced::Color::from_rgb(1.0, 0.6, 0.0)),
                            }
                        }),
                        text(msg).size(14)
                    ]
                    .spacing(5),
                )
                .padding(10)
                .style(|_theme| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgb(
                        0.3, 0.2, 0.0,
                    ))),
                    border: iced::Border {
                        color: iced::Color::from_rgb(1.0, 0.6, 0.0),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }),
            );
        }

        content = content.push(Space::new(0, 10));

        // Action Buttons
        let actions = row![
            button(text("Refresh Status")).on_press(KeyStatusMessage::Refresh),
            button(text("View Logs")).on_press(KeyStatusMessage::ShowLogs),
            button(text("Recover USB Key")).on_press(KeyStatusMessage::RecoverUsb),
        ]
        .spacing(10);

        content = content.push(actions);

        container(content).into()
    }
}

impl Default for KeyStatusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Render USB status indicator.
fn render_usb_status(status: &UsbStatus) -> Element<'static, KeyStatusMessage> {
    let (icon, message, color) = match status {
        UsbStatus::PresentValid => (
            "✓",
            "USB device present with valid checksum".to_string(),
            iced::Color::from_rgb(0.0, 0.8, 0.0),
        ),
        UsbStatus::PresentInvalid { expected, actual } => (
            "✗",
            format!(
                "USB checksum mismatch\nExpected: {}\nActual: {}",
                expected, actual
            ),
            iced::Color::from_rgb(1.0, 0.2, 0.0),
        ),
        UsbStatus::NotPresent => (
            "○",
            "USB device not detected".to_string(),
            iced::Color::from_rgb(0.6, 0.6, 0.6),
        ),
        UsbStatus::NotConfigured => (
            "−",
            "USB checksum verification not configured".to_string(),
            iced::Color::from_rgb(0.6, 0.6, 0.6),
        ),
    };

    row![
        text(icon)
            .size(20)
            .style(move |_theme| text::Style { color: Some(color) }),
        text(message)
    ]
    .spacing(10)
    .align_y(Alignment::Center)
    .into()
}

/// Render staging icon only (for use in detailed views).
fn render_staging_icon(status: StagingStatus) -> Element<'static, KeyStatusMessage> {
    let (icon, color) = match status {
        StagingStatus::Present => ("✓", iced::Color::from_rgb(0.0, 0.8, 0.0)),
        StagingStatus::Missing => ("✗", iced::Color::from_rgb(1.0, 0.2, 0.0)),
        StagingStatus::Unknown => ("?", iced::Color::from_rgb(0.6, 0.6, 0.6)),
    };

    text(icon)
        .size(16)
        .style(move |_theme| text::Style { color: Some(color) })
        .into()
}

/// Check USB device status against configured checksum.
fn check_usb_status(config: &LockchainConfig) -> UsbStatus {
    let Some(expected_sha256) = config.usb.expected_sha256.as_deref() else {
        return UsbStatus::NotConfigured;
    };

    if expected_sha256.trim().is_empty() {
        return UsbStatus::NotConfigured;
    }

    let key_path = config.key_hex_path();
    let Ok((key_bytes, _)) = lockchain_core::keyfile::read_key_file(&key_path) else {
        return UsbStatus::NotPresent;
    };

    use sha2::{Digest, Sha256};
    let actual = hex::encode(Sha256::digest(&key_bytes));

    if expected_sha256.eq_ignore_ascii_case(&actual) {
        UsbStatus::PresentValid
    } else {
        UsbStatus::PresentInvalid {
            expected: expected_sha256.to_string(),
            actual,
        }
    }
}

/// Check if a key file exists at the given staging location.
fn check_staging_location(path: &Path) -> StagingStatus {
    if path.exists() && path.is_file() {
        // Verify it's readable and has content
        if lockchain_core::keyfile::read_key_file(path).is_ok() {
            StagingStatus::Present
        } else {
            StagingStatus::Missing
        }
    } else {
        StagingStatus::Missing
    }
}

/// Get detailed LUKS mapping status for each configured mapping.
fn get_luks_mapping_status(config: &LockchainConfig) -> Vec<LuksMappingStatus> {
    use lockchain_core::config::looks_like_mapping_name;

    let mappings: Vec<&str> = config
        .policy
        .targets
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| looks_like_mapping_name(entry))
        .collect();

    if mappings.is_empty() {
        return Vec::new();
    }

    let cryptsetup_dir = Path::new("/run/cryptsetup-keys.d");

    mappings
        .into_iter()
        .map(|mapping| {
            let key_file_path = cryptsetup_dir.join(format!("{}.key", mapping));
            let status = if key_file_path.exists() && key_file_path.is_file() {
                StagingStatus::Present
            } else {
                StagingStatus::Missing
            };

            LuksMappingStatus {
                mapping_name: mapping.to_string(),
                key_file_path: key_file_path.display().to_string(),
                status,
            }
        })
        .collect()
}
