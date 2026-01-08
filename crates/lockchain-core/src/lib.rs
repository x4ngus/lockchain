//! Core building blocks shared by LockChain binaries.
//!
//! Configuration, workflows, and services live here so downstream crates can focus on
//! operator surfaces instead of reimplementing orchestration.

pub mod config;
pub mod error;
pub mod fallback;
pub mod keyfile;
pub mod logging;
pub mod perf;
pub mod provider;
pub mod service;
pub mod workflow;

pub use config::{ConfigFormat, CryptoCfg, Fallback, LockchainConfig, Policy, Usb};
pub use error::{LockchainError, LockchainResult};
pub use fallback::derive_fallback_key;
pub use provider::{
    DatasetKeyDescriptor, KeyProvider, KeyState, KeyStatusSnapshot, LuksKeyProvider, ProviderKind,
    ZfsProvider,
};
pub use service::{LockchainService, UnlockOptions, UnlockReport};

// Re-export zeroize for consumers that need to create UnlockOptions with sensitive data
pub use zeroize::Zeroizing;
