# Installation Playbook

This runbook distils the steps needed to deploy LockChain’s **ZFS provider** on Ubuntu/Debian hosts with `systemd` and ZFS tooling available. For the multi-provider overview, see [`docs/PROVIDERS.md`](PROVIDERS.md) and [`docs/adr/ADR-003-LUKS.md`](adr/ADR-003-LUKS.md).

---

## 0. Bootstrap Installer (Recommended)

```bash
sudo ./lockchain-install.sh
```

The shell installer pulls in build dependencies (APT), compiles `target/release`, detects ZFS pools, prompts for the dataset and USB token, writes `/etc/lockchain.toml`, delegates `zfs allow load-key,key`, installs the Lockchain systemd units, and enables the services. It deliberately stops short of forging key material—follow up with `lockchain init --dataset <ds> --device <usb>` once you are ready to seed the vault, then run `lockchain tuning` and `lockchain repair` to validate the integration. The CLI binary ships as `lockchain-cli`; substitute that name if your PATH does not expose a `lockchain` alias.

By default the script prints only final status lines. Export `LOCKCHAIN_INSTALL_VERBOSE=1` if you want to stream every command and plan step while troubleshooting.

Need a dry run first? Use `lockchain bootstrap discover --format plain` to inspect pools/datasets/USB candidates and `lockchain bootstrap plan --dataset <ds> --format plain` to review every host command the installer uses. Set `SKIP_DEPS=1` or `SKIP_BUILD=1` when re-running the installer on a prepped host.

## 1. Pre-flight Checks

1. Confirm the host has `zfsutils-linux` (or your distro’s equivalent).  
2. Make sure you have root or the ability to escalate once.  
3. Decide whether you’ll install from source or drop in the signed `.deb`.

Keep `/var/lib/lockchain` reserved for the service account; the packaging scripts create it, but it never hurts to verify.

## 2. Bring in the Bits

### Option A — Build from Source

```bash
git clone https://github.com/x4ngus/lockchain.git
cd lockchain
cargo build --release
sudo install -Dm755 target/release/lockchain-cli /usr/local/bin/lockchain-cli
sudo install -Dm755 target/release/lockchain-daemon /usr/local/bin/lockchain-daemon
sudo install -Dm755 target/release/lockchain-key-usb /usr/local/bin/lockchain-key-usb
sudo install -Dm755 target/release/lockchain-ui /usr/local/bin/lockchain-ui
sudo ln -sf /usr/local/bin/lockchain-cli /usr/bin/lockchain-cli
sudo ln -sf /usr/local/bin/lockchain-daemon /usr/bin/lockchain-daemon
sudo ln -sf /usr/local/bin/lockchain-key-usb /usr/bin/lockchain-key-usb
sudo ln -sf /usr/local/bin/lockchain-ui /usr/bin/lockchain-ui
```

### Option B — Consume the Signed Package

```bash
curl -LO https://github.com/x4ngus/lockchain/releases/latest/download/lockchain-zfs_0.2.1-1_amd64.deb
curl -LO https://github.com/x4ngus/lockchain/releases/latest/download/lockchain-zfs_0.2.1-1_amd64.deb.asc
curl -LO https://github.com/x4ngus/lockchain/releases/latest/download/SHA256SUMS
curl -LO https://github.com/x4ngus/lockchain/releases/latest/download/SHA256SUMS.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
sudo apt install ./lockchain-zfs_0.2.1-1_amd64.deb
```

Swap the version number when new releases ship. The installer creates the service user, pulls in systemd units, and nudges `update-initramfs`.

## 3. Wire the Configuration

The control file lives at `/etc/lockchain.toml`. Start from a clean slate:

```bash
sudo install -Dm640 /dev/null /etc/lockchain.toml
sudo chgrp lockchain /etc/lockchain.toml
sudo ${EDITOR:-vi} /etc/lockchain.toml
```

Populate the essentials:

- `provider.type = "zfs"` — select the provider explicitly for systemd-managed hosts.  
- `policy.targets` — every dataset you expect to unlock.  
- `usb.device_label` or `usb.device_uuid` — how we recognise the vault stick.  
- `usb.expected_sha256` — golden checksum of the raw 32-byte key.  
- `[zfs] zfs_path` / `[zfs] zpool_path` — optional overrides when binaries are not on PATH.  
- `retry.*` — adjust patience for unlock retries (defaults: 3 attempts, 500 ms base, 5 s ceiling, 0.1 jitter).  
- `fallback.*` — only if you allow passphrase recovery; stash the `salt`/`xor` values from provisioning.

Validate early and often:

```bash
lockchain validate -f /etc/lockchain.toml
```

## 4. Provision or Refresh the USB Token

Use the CLI to normalise the USB token and refresh the initramfs templates:

```bash
sudo lockchain init --dataset tank/secure --device /dev/sdX1
sudo lockchain tuning
sudo lockchain repair
sudo lockchain self-test --dataset tank/secure --strict-usb
```

`lockchain init` wipes (or validates, when `--safe` is set) the token, writes fresh raw key material, configures fallback secrets, and installs the dracut module. `lockchain tuning` (aliases: `lockchain self-heal`, `lockchain doctor`) runs diagnostics and remediation, while `lockchain repair` reinstalls/enables the mount and unlock units if needed. Finish with `lockchain self-test` to prove the key can unlock an ephemeral pool before touching production datasets. From the Control Deck, use **New Key (Safe Mode)** if you prefer a guided workflow that collects the dataset, device, and confirmations one step at a time.

> **Record the recovery key.** The Control Deck and CLI now display a 64-character recovery key (and a QR overlay in the UI) immediately after forging. Copy it to an offline vault before you acknowledge the prompt—this value is required to recreate the USB token later.

### Restore with the Recovery Key

- From the Control Deck, choose **Restore** and paste the recovery key value when prompted (whitespace is ignored). The result is written to `/var/lib/lockchain/<dataset>.key` by default.
- The `lockchain breakglass` CLI continues to support passphrase-derived recovery for legacy deployments. Use the new recovery key whenever possible.

## 5. Lock Down Identity & Permissions

LockChain supports two privilege paths:

- **Polkit/systemd root** — run the services as root (or allow pkexec escalation). Packaging and the Debian artefacts choose this route. Skip the delegation step below and ensure a polkit agent is available (`ensure_privilege_support` will prompt when missing).
- **Delegated ZFS ACLs** — grant the dedicated `lockchain` user `zfs allow load-key,key <dataset>`. The bootstrap installer and this source-based guide follow this model so the long-running services run without full root.

Whichever path you pick, the `lockchain` user should be the only account with key-file access.

```bash
sudo id lockchain || sudo useradd --system --home /var/lib/lockchain --shell /usr/sbin/nologin lockchain
sudo install -d -o lockchain -g lockchain /var/lib/lockchain
sudo chgrp lockchain /etc/lockchain.toml
sudo chmod 640 /etc/lockchain.toml
```

Delegate the minimum ZFS verbs. Either use `zfs allow`:

```bash
sudo zfs allow lockchain load-key,key yourpool/encrypted
```

…or drop a narrowly scoped sudoers file:

```
# /etc/sudoers.d/lockchain
lockchain ALL=(root) NOPASSWD:/usr/sbin/zfs load-key *, \
    /usr/sbin/zfs key -l *, \
    /usr/bin/lockchain-cli unlock *, \
    /usr/bin/lockchain-cli breakglass *
```

Always validate with `visudo -cf /etc/sudoers.d/lockchain`.

## 6. Deploy the Services

The repo ships helper scripts and units; the Debian package installs them automatically. For source builds:

```bash
cd lockchain
sudo packaging/install-systemd.sh
```

Enable the core daemon and any dataset unlock templates:

```bash
sudo systemctl enable --now lockchain.service
sudo systemctl enable "$(systemd-escape --template=lockchain@.service 'tank/secure')"
sudo systemctl enable "$(systemd-escape --template=lockchain@.service 'tank/workload')"
```

(`lockchain repair` enables these units automatically, but the commands are shown here for clarity.)

Need USB event enforcement? Bring the watcher online:

```bash
sudo systemctl enable --now lockchain-key-usb.service
```

Reload systemd if you tweak units by hand:

```bash
sudo systemctl daemon-reload
```

## 7. Confidence Checks

### Health Endpoint

```bash
curl -s http://127.0.0.1:8787
```

Expect `OK`. Change the bind address with `LOCKCHAIN_HEALTH_ADDR`.

### Logs

```bash
sudo journalctl -u lockchain.service -f
sudo journalctl -u lockchain-key-usb.service -f
```

Logs default to JSON. Set `LOCKCHAIN_LOG_FORMAT=plain` if you want human-friendly output for troubleshooting.

### Workflow Smoke Test

Run the self-test from the Control Deck (Self-test directive) or via CLI:

```bash
lockchain self-test --dataset tank/secure --strict-usb
```

You should see `[OK] Self-test unlock` style messages confirming the path and a teardown notice at the end.

## 8. Maintenance & Removal

- Re-run `lockchain validate` after any config change.  
- Rotate the USB key? Forge a new one through the Control Deck or run `lockchain init` (see docs/workflow).  
- To uninstall, disable units and purge binaries/config:

```bash
sudo systemctl disable --now lockchain.service lockchain-key-usb.service
sudo apt remove lockchain-zfs           # or rm /usr/bin/lockchain-*
sudo rm -rf /var/lib/lockchain /etc/lockchain.toml
```

## 9. Operational Notes

- Signed packages and checksums back every deployment; verify before installation when operating under strict governance.  
- Use the Control Deck’s Tuning directive or `lockchain tuning` CLI workflow as part of acceptance testing.  
- Schedule periodic key self-tests (Control Deck or CLI) to prove the USB material still unlocks the pool.  
- Keep the glow subtle but present—consistent theming in terminals and UI helps operators quickly identify the LockChain surfaces.
