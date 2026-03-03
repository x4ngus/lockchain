<div align="center">

# LockChain  
_Security chain for encrypted storage_

</div>

> **Preview (v0.2.1):** This build targets lab and UAT environments. Expect fast-moving changes and breaking adjustments while we finish the 0.2 line. Keep keys backed up and test on non-production pools first.

LockChain delivers repeatable, headless unlocks for encrypted storage via pluggable providers (ZFS today, LUKS scaffolding underway) with a single operator experience: shared workflows, shared observability, and a minimal early-boot footprint.

https://github.com/user-attachments/assets/e0b79a1e-c088-4b47-a06e-27b238ee021d

## System Overview

LockChain improves interaction with encrypted file systems without trivialising your security posture.

- **Objective**: Deliver a unified unlock workflow for encrypted storage across providers (ZFS & LUKS).  
- **Surfaces**: CLI, daemon, UI, and USB watcher all routing through the same workflow engine.  
- **Docs**: Provider plumbing + shell boundary in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); contracts + capability matrix in [`docs/PROVIDERS.md`](docs/PROVIDERS.md).  

### Why LockChain?
- **Early-boot interactions** — Dracut and initramfs-tools loaders ship with checksum + UUID enforcement for USB.
- **User friendly** — Tuning and Repair self-heal systemd units, initramfs assets, and permissions.
- **Observability first** — Heads up GUI with runtime logs and `LCxxxx` codes for security event messages.

## Prerequisites
- Ubuntu 25.10 (or compatible) with either native ZFS encryption or LUKS (`cryptsetup`).
- Initramfs tooling available (dracut preferred; update-initramfs acceptable).
- systemd present (services and `/run/lockchain` tmpfs mount run under systemd).
- Removable USB flash drive (will be reformatted) discoverable as a block device.
- Rust toolchain if building from source; otherwise Debian package bundles are available.

## Quick Start Guide (ZFS Provider)

Fast path, copy/paste ready. Commands are safe to run on a fresh host; root is only used when touching systemd or `/etc`. For alpha, keep snapshots handy and test on staging pools.

**1) Install & wire up services**
```bash
git clone https://github.com/x4ngus/lockchain.git
cd lockchain
sudo ./lockchain-install.sh
```
What happens: dependencies installed, binaries built and installed to `/usr/local/bin` (so you can run `lockchain-ui`, `lockchain-cli`, etc. from anywhere), `/etc/lockchain.toml` staged (provider set to `zfs`), `zfs allow load-key,key` delegated, systemd units enabled. No key material is forged yet.

**2) Forge the vault key on your USB (adjust dataset/device)**
```bash
lockchain init --dataset rpool/ROOT/ubuntu --device /dev/sdX1
```
This writes raw key bytes, captures the checksum, and refreshes initramfs. Swap `--device` for `--device auto` if you’ve set label/UUID in the config.

**3) Verify the unlock path end-to-end**
```bash
lockchain self-test
```
An ephemeral pool is created, unlocked with your key, and torn down. Add `--strict-usb` to demand the USB be present.

**4) Harden the deployment**
```bash
lockchain tuning   # diagnostics and self-healing
lockchain repair   # only if tuning suggests it
```
These reconcile systemd units, permissions, and ZFS hooks. Run after upgrades or policy edits.

**5) Console unlock**
```bash
lockchain unlock --strict-usb
```
Pair with the Control Deck (`lockchain-ui`) for a cockpit view, or let `lockchain-daemon` keep pools unlocked in the background.

Prefer the manual lane? Swap step 1 for:
```bash
sudo install -Dm640 packaging/systemd/lockchain.toml /etc/lockchain.toml
cargo test -p lockchain-zfs --test unlock_smoke   # fake provider; no root
lockchain validate -f /etc/lockchain.toml
```
Then resume at step 2.

## Module Lineup

| Module | Purpose | Notes |
| --- | --- | --- |
| `lockchain-provider` | Provider contracts (traits + shared types) | Keeps `lockchain-core` focused on workflows |
| `lockchain-core` | Policy engine, workflow orchestration | Houses keyfile guards, checksum enforcement, JSON logging bootstrap |
| `lockchain-zfs` | System provider using native `zfs`/`zpool` binaries | Maps exit codes, parses stdout, backs the unlock smoke test |
| `lockchain-luks` | LUKS provider (`cryptsetup` + `crypttab` + initrd hooks) | Scaffolded; see ADR-003 |
| `lockchain-cli` | Operator console (unlock/status/list/validate/breakglass) | Structured error codes for SIEM correlation (`LCxxxx`) |
| `lockchain-key-usb` | udev watcher & key normaliser | Detects label/UUID, rewrites legacy hex → raw, mirrors to `/run/lockchain/` |
| `lockchain-daemon` | Long-running safety net | Watches USB, retries unlocks, runs health responder (`127.0.0.1:8787`) |
| `lockchain-ui` | Control Deck | Unified UI (ZFS + LUKS contexts) |
| `docs/adr` | Architecture Decisions | ADR-001 captures the provider strategy |

## Configuration Blueprint

Unified configuration lives at `/etc/lockchain.toml` (templates: `packaging/systemd/lockchain.toml`, examples: `docs/examples/lockchain-zfs.toml`, `docs/examples/lockchain-luks.toml`).

```toml
[provider]
# zfs | luks | auto
type = "zfs"

[policy]
# Managed targets: datasets for ZFS, crypt mappings for LUKS.
targets = ["rpool/ROOT/blackice"]
allow_root = false

[zfs]
zfs_path = "/sbin/zfs"
zpool_path = "/sbin/zpool"

[luks]
# cryptsetup_path = "/usr/sbin/cryptsetup"
# crypttab_path = "/etc/crypttab"

[crypto]
timeout_secs = 10

[usb]
key_hex_path = "/run/lockchain/key.raw"
expected_sha256 = "optional sha256 of the decoded raw key"
device_label = "LOCKCHAIN"
# device_uuid = "optional blkid UUID"
device_key_path = "key.raw"
mount_timeout_secs = 10

[fallback]
enabled = true
askpass = true
askpass_path = "/usr/bin/systemd-ask-password"
passphrase_salt = "hex salt emitted during init (optional; set via Settings or Safe forge)"
passphrase_xor = "hex xor blob emitted during init (optional; set via Settings or Safe forge)"
passphrase_iters = 250000

[retry]
max_attempts = 3
base_delay_ms = 500
max_delay_ms = 5000
jitter_ratio = 0.1
```

**Environment Overrides**

| Variable | Intent | Effect |
| --- | --- | --- |
| `LOCKCHAIN_KEY_PATH` | Point to alternate key material | Overrides `usb.key_hex_path`. |
| `LOCKCHAIN_LOG_LEVEL` | Adjust verbosity | Default log filter (`info`). |
| `LOCKCHAIN_LOG_FORMAT` | Switch between JSON/plain logs | `json` (default) or `plain`. |
| `LOCKCHAIN_LOG_ROOT` | Relocate performance profiling logs | Defaults to the platform data dir (`~/.local/share/lockchain/logs/perf`), falling back to `/var/log/lockchain/logs/perf`. |
| `LOCKCHAIN_LOG_EXPORT_DIR` | Override where log bundles are written | Defaults to the OS downloads directory, or the perf log root when unavailable. |
| `LOCKCHAIN_KEY_USB_MOUNTS_PATH` | Provide a mounts fixture for testing | Feeds the USB watcher with synthetic data. |
| `LOCKCHAIN_CONFIG` | Run a surface against a different config | Defaults to `/etc/lockchain.toml` (legacy config paths are auto-discovered when missing). |
| `LOCKCHAIN_HEALTH_ADDR` | Rebind the daemon health endpoint | Default `127.0.0.1:8787`. |

## Console Commands

- `lockchain init --dataset <ds>` — forge or refresh the USB token, rebuild dracut, and capture checksum updates.  
- `lockchain tuning` (`lockchain self-heal`, `lockchain doctor`) — run diagnostics with automatic remediation for config, systemd, and initramfs.  
- `lockchain repair` — reinstall/enable mount and unlock units when doctor suggests manual action.  
- `lockchain unlock --strict-usb` — require the vault stick; no silent fallbacks.  
- `lockchain self-test` — exercise an ephemeral pool to prove the current key still opens the vault.  
- `lockchain unlock --prompt-passphrase` — partner with `systemd-ask-password` when policy allows.  
- `lockchain profile-unlock` — capture unlock timings and append to the performance log (baseline on first success).  
- `lockchain status` — live keystatus for every target in `policy.targets`.  
- `lockchain list-keys` — report encryption roots vs. datasets.  
- `lockchain-key-usb` — enforce USB insertion/removal rules, heal legacy key files.  
- `lockchain tui` — keyboard-only Control Deck for datasets, retries, and passphrases.  
- `lockchain validate -f /path/to/config` — static validator; `--schema` exports the JSON schema.  
- `lockchain-daemon` — schedule unlock attempts, stream health, surface warnings.  

All surfaces emit machine-readable error codes prefixed with `LC`, making SOC integration straightforward.

## Performance Profiling

- Run `packaging/scripts/profile-unlock.sh` (or `lockchain profile-unlock`) to log unlock timings; the first successful run for a dataset establishes its baseline automatically.
- Performance logs live under `$LOCKCHAIN_LOG_ROOT/logs/perf` (defaults to `~/.local/share/lockchain/logs/perf`, falling back to `/var/log/lockchain/logs/perf`).
- The Control Deck action row now exposes **Download Logs**, bundling the baseline + JSONL log to your /tmp/ directory (override with `LOCKCHAIN_LOG_EXPORT_DIR`).

## Build & Quality Gates

- `cargo test -p lockchain-core` — keyfile, workflow, and fallback coverage.  
- `cargo test -p lockchain-zfs` — unlock smoke test with fake binaries.  
- `cargo test -p lockchain-key-usb` — requires `libudev-dev`.  
- `cargo fmt && cargo clippy --all-targets` — routine hygiene.  
- Packaging pipeline (`.github/workflows/release.yml`) builds signed `.deb` releases on Ubuntu 25.10+.

## Further Reading

- [`docs/INSTALL.md`](docs/INSTALL.md) — deployment runbook for operations and platform teams.  
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component map and integration touchpoints.  
- [`docs/PROVIDERS.md`](docs/PROVIDERS.md) — provider contracts and capability matrix.  
- [`docs/UI.md`](docs/UI.md) — Control Deck architecture and context switching.  
- [`docs/SECURITY.md`](docs/SECURITY.md) — hardening posture, disclosure process, break-glass guardrails.  
- [`docs/RELEASE.md`](docs/RELEASE.md) — how we ship signed packages.  
- [`docs/adr/ADR-001-module-provider.md`](docs/adr/ADR-001-module-provider.md) — strategy memo on the provider abstraction.
- [`docs/adr/ADR-003-LUKS.md`](docs/adr/ADR-003-LUKS.md) — LUKS deployment + crypttab patterns.
