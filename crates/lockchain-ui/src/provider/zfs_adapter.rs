//! ZFS provider adapter for UI workflows.
//!
//! Provides UI-friendly wrappers around ZFS provider operations.

use lockchain_zfs::SystemZfsProvider;

/// UI adapter for ZFS operations.
#[allow(dead_code)]
pub struct ZfsAdapter;

#[allow(dead_code)]
impl ZfsAdapter {
    /// Lists all available ZFS datasets.
    pub async fn list_datasets(provider: &SystemZfsProvider) -> Result<Vec<String>, String> {
        // TODO: Implement dataset listing
        // This would use `zfs list -H -o name` or similar
        let _ = provider;
        Ok(vec![])
    }

    /// Gets encryption status for a dataset.
    pub async fn get_dataset_status(
        provider: &SystemZfsProvider,
        dataset: &str,
    ) -> Result<DatasetStatus, String> {
        let _ = (provider, dataset);
        // TODO: Implement status check using describe_datasets
        Ok(DatasetStatus::Unknown)
    }
}

/// Dataset encryption status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DatasetStatus {
    /// Dataset is unlocked and accessible.
    Unlocked,
    /// Dataset is locked (key not loaded).
    Locked,
    /// Dataset encryption status is unknown.
    Unknown,
}
