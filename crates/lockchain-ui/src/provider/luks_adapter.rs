//! LUKS provider adapter for UI workflows.
//!
//! Provides UI-friendly wrappers around LUKS provider operations.

use lockchain_luks::SystemLuksProvider;

/// UI adapter for LUKS operations.
#[allow(dead_code)]
pub struct LuksAdapter;

#[allow(dead_code)]
impl LuksAdapter {
    /// Lists all available LUKS mappings.
    pub async fn list_mappings(provider: &SystemLuksProvider) -> Result<Vec<String>, String> {
        // TODO: Implement mapping listing using list_mappings()
        let _ = provider;
        Ok(vec![])
    }

    /// Gets status for a LUKS mapping.
    pub async fn get_mapping_status(
        provider: &SystemLuksProvider,
        name: &str,
    ) -> Result<MappingStatus, String> {
        let _ = (provider, name);
        // TODO: Implement status check using mapping_state()
        Ok(MappingStatus::Unknown)
    }
}

/// LUKS mapping status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MappingStatus {
    /// Mapping is active (unlocked).
    Active,
    /// Mapping exists but is inactive.
    Inactive,
    /// Mapping status is unknown.
    Unknown,
}
