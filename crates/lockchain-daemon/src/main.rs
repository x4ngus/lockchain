//! Background daemon that watches for key material and keeps configured targets unlocked.

use anyhow::{Context, Result};
use lockchain_core::{
    config::{LockchainConfig, DEFAULT_CONFIG_PATH},
    logging,
    provider::{KeyProvider, KeyStatusSnapshot, LuksKeyProvider, ProviderKind},
    service::{LockchainService, UnlockOptions},
    workflow, LockchainError,
};
use lockchain_luks::SystemLuksProvider;
use lockchain_zfs::SystemZfsProvider;
use log::{error, info, warn};
use std::sync::{Arc, Mutex};
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::TcpListener,
    select, signal,
    sync::watch,
    time::{interval, Duration, Instant},
};

mod usb;

#[derive(Clone)]
enum RuntimeProvider {
    Zfs(SystemZfsProvider),
    Luks(LuksKeyProvider<SystemLuksProvider>),
}

impl KeyProvider for RuntimeProvider {
    type Error = LockchainError;

    fn kind(&self) -> ProviderKind {
        match self {
            RuntimeProvider::Zfs(_) => ProviderKind::Zfs,
            RuntimeProvider::Luks(_) => ProviderKind::Luks,
        }
    }

    fn encryption_root(&self, target: &str) -> std::result::Result<String, Self::Error> {
        match self {
            RuntimeProvider::Zfs(provider) => provider.encryption_root(target),
            RuntimeProvider::Luks(provider) => provider.encryption_root(target),
        }
    }

    fn locked_descendants(&self, root: &str) -> std::result::Result<Vec<String>, Self::Error> {
        match self {
            RuntimeProvider::Zfs(provider) => provider.locked_descendants(root),
            RuntimeProvider::Luks(provider) => provider.locked_descendants(root),
        }
    }

    fn load_key_tree(
        &self,
        root: &str,
        key: &[u8],
    ) -> std::result::Result<Vec<String>, Self::Error> {
        match self {
            RuntimeProvider::Zfs(provider) => provider.load_key_tree(root, key),
            RuntimeProvider::Luks(provider) => provider.load_key_tree(root, key),
        }
    }

    fn describe_targets(
        &self,
        targets: &[String],
    ) -> std::result::Result<KeyStatusSnapshot, Self::Error> {
        match self {
            RuntimeProvider::Zfs(provider) => provider.describe_targets(targets),
            RuntimeProvider::Luks(provider) => provider.describe_targets(targets),
        }
    }
}

/// Tracks whether USB discovery and unlock routines consider the world healthy.
#[derive(Default)]
struct HealthState {
    usb_ready: bool,
    unlock_ready: bool,
}

/// Shared handle used to notify other tasks when overall health changes.
#[derive(Clone)]
struct HealthChannel {
    inner: Arc<HealthInner>,
}

struct HealthInner {
    state: Mutex<HealthState>,
    tx: watch::Sender<bool>,
}

impl HealthChannel {
    /// Create a new channel bound to the provided watch sender.
    fn new(tx: watch::Sender<bool>) -> Self {
        Self {
            inner: Arc::new(HealthInner {
                state: Mutex::new(HealthState::default()),
                tx,
            }),
        }
    }

    /// Record the latest USB availability status.
    fn set_usb_ready(&self, ready: bool) {
        // Recover from a poisoned mutex rather than crashing the daemon.
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let changed = state.usb_ready != ready;
        state.usb_ready = ready;
        let healthy = state.usb_ready && state.unlock_ready;
        drop(state);
        if changed {
            let _ = self.inner.tx.send(healthy);
        }
    }

    /// Record whether unlock attempts have been succeeding lately.
    fn set_unlock_ready(&self, ready: bool) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let changed = state.unlock_ready != ready;
        state.unlock_ready = ready;
        let healthy = state.usb_ready && state.unlock_ready;
        drop(state);
        if changed {
            let _ = self.inner.tx.send(healthy);
        }
    }
}

/// Entry point for the Tokio runtime; logs failures before exit.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(err) = run().await {
        error!("daemon exit: {err:?}");
        std::process::exit(1);
    }
}

/// Load configuration, start background tasks, and juggle shutdown signals.
async fn run() -> Result<()> {
    logging::init("info");
    let config_path =
        std::env::var("LOCKCHAIN_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let config_path = PathBuf::from(config_path);
    let config = Arc::new(
        LockchainConfig::load_or_bootstrap(&config_path)
            .with_context(|| format!("load config {}", config_path.display()))?,
    );

    workflow::ensure_privilege_support().map_err(anyhow::Error::new)?;

    if config.path != config_path {
        warn!(
            "configuration missing at {}; using bootstrap at {}",
            config_path.display(),
            config.path.display()
        );
    }

    info!(
        "LockChain daemon booting (config: {})",
        config.path.display()
    );

    let provider_kind = config
        .resolve_provider_kind()
        .map_err(anyhow::Error::new)
        .context("resolve provider kind")?;

    let provider = match provider_kind {
        ProviderKind::Zfs => RuntimeProvider::Zfs(
            SystemZfsProvider::from_config(&config).context("initialise zfs provider")?,
        ),
        ProviderKind::Luks => RuntimeProvider::Luks(LuksKeyProvider::new(
            SystemLuksProvider::from_config(&config).context("initialise luks provider")?,
        )),
        ProviderKind::Auto => unreachable!("resolve_provider_kind must return a concrete kind"),
    };
    let service = Arc::new(LockchainService::new(config.clone(), provider));

    // health status broadcast (true = ready, false = degraded)
    let (health_tx, health_rx) = watch::channel(false);
    let health_channel = HealthChannel::new(health_tx.clone());

    let usb_handle = tokio::spawn(usb::watch_usb(config.clone(), health_channel.clone()));
    let unlock_handle = tokio::spawn(periodic_unlock(
        service.clone(),
        config.clone(),
        provider_kind,
        health_channel.clone(),
    ));
    let health_handle = tokio::spawn(health_server(health_rx));

    select! {
        res = usb_handle => res??,
        res = unlock_handle => res??,
        res = health_handle => res??,
        _ = signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    Ok(())
}

/// Periodically attempt to unlock the configured dataset and update health.
async fn periodic_unlock(
    service: Arc<LockchainService<RuntimeProvider>>,
    config: Arc<LockchainConfig>,
    provider_kind: ProviderKind,
    health: HealthChannel,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(30));
    let mut last_success = Instant::now();
    loop {
        ticker.tick().await;
        let target = config
            .targets_for(provider_kind)
            .first()
            .cloned()
            .unwrap_or_default();
        if target.is_empty() {
            warn!("no targets configured for provider={provider_kind:?}; daemon idle");
            continue;
        }

        let key_path = config.key_hex_path();
        let key_ready = std::fs::metadata(&key_path)
            .map(|meta| meta.is_file() && meta.len() == 32)
            .unwrap_or(false);
        if !key_ready {
            health.set_unlock_ready(false);
            continue;
        }

        match service.unlock_with_retry(&target, UnlockOptions::default()) {
            Ok(report) => {
                if report.already_unlocked {
                    info!("target {target} already unlocked");
                } else {
                    info!("unlocked {target} with {} nodes", report.unlocked.len()); // lgtm[rust/cleartext-logging] - dataset count and name; not sensitive
                }
                health.set_unlock_ready(true);
                last_success = Instant::now();
            }
            Err(err) => {
                warn!("unlock attempt failed for {target}: {err}");
                health.set_unlock_ready(false);
                // degrade if failure lasts >5 minutes
                if last_success.elapsed() > Duration::from_secs(300) {
                    warn!(
                        "target {target} has been locked for {:?}",
                        last_success.elapsed()
                    );
                }
            }
        }
    }
}

/// Expose a bare-bones HTTP endpoint for readiness checks.
///
/// Binds to loopback only by default. Consumes the incoming HTTP request
/// (up to a bounded read) before replying, and applies a per-connection
/// timeout to prevent slow-loris resource exhaustion.
async fn health_server(status_rx: watch::Receiver<bool>) -> Result<()> {
    let addr: SocketAddr = std::env::var("LOCKCHAIN_HEALTH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()
        .context("parse LOCKCHAIN_HEALTH_ADDR")?;

    if !addr.ip().is_loopback() {
        warn!(
            "LOCKCHAIN_HEALTH_ADDR is set to non-loopback address {addr}; \
             the health endpoint will be network-accessible"
        );
    }

    let listener = TcpListener::bind(addr).await?;
    info!("health endpoint listening on http://{addr}");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let status_rx = status_rx.clone();

        // Handle each connection in a spawned task with a timeout to prevent
        // slow-loris style resource exhaustion.
        tokio::spawn(async move {
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                // Drain the HTTP request (bounded read to prevent memory exhaustion).
                let mut request_buf = vec![0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request_buf).await;

                let healthy = *status_rx.borrow();
                let body = if healthy { "OK" } else { "DEGRADED" };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                if let Err(err) = stream.write_all(response.as_bytes()).await {
                    warn!("failed to respond to {peer}: {err}");
                }
            })
            .await;

            if result.is_err() {
                warn!("health check from {peer} timed out");
            }
        });
    }
}
