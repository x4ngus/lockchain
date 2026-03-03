# LockChain Release Playbook (ZFS package)

This repository now produces signed Debian packages as part of every GitHub
Release. Follow the checklist below to prepare a tag and let the automation
publish `.deb` bundles that install the CLI, daemon, USB watcher, and Control
Deck UI in one shot.

### 1. Rotate the release secrets (maintainers only)

The GitHub Actions workflow expects three secrets:

| Secret | Purpose |
| --- | --- |
| `RELEASE_GPG_KEY` | Base64-encoded ASCII-armoured private key used for signing |
| `RELEASE_GPG_KEY_ID` | The fingerprint or short key ID to select during signing |
| `RELEASE_GPG_PASSPHRASE` | Passphrase for the imported private key |

```bash
# Example: exporting an existing key
gpg --armor --export-secret-keys YOUR_KEY_ID | base64 -w0
```

Paste the output into `RELEASE_GPG_KEY`, then set the corresponding ID and
passphrase secrets. The workflow aborts if any of them are missing.

### 2. Sanity-check the package locally (optional but recommended)

On an Ubuntu 25.10 host (or container) that mirrors the release runner:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libudev-dev libgtk-3-dev \
    libsoup-3.0-dev libxcb-shape0-dev libxcb-render0-dev libxcb-xfixes0-dev \
    libxkbcommon-dev libxi-dev libx11-dev libvulkan1 libdrm-dev zfsutils-linux dracut
cargo build --release --workspace
cargo install cargo-deb --locked
cargo deb --manifest-path packaging/lockchain-deb/Cargo.toml --no-build --target-dir target/debian
```

Install the generated package to confirm the end-to-end experience:

```bash
sudo apt install ./target/debian/lockchain-zfs_*_amd64.deb
sudo systemctl status lockchain.service
lockchain-ui  # launch the Control Deck
```

### 3. Publish the release

1. Update `CHANGELOG.md` and tag the repository (`git tag v0.2.1`, etc.).
2. Push the tag or create a GitHub Release. The `release` workflow triggers on
   `workflow_dispatch` and on `release.published`.
3. The workflow runs on `ubuntu-rolling` (tracking Ubuntu 25.10), builds all
   binaries, runs tests, assembles `lockchain-zfs_*.deb`, signs it, and uploads:
   - The `.deb` file
   - A detached ASCII signature (`.asc`)
   - `SHA256SUMS` and its detached signature
4. On published releases the assets are attached automatically. Manual
   invocations stash them as workflow artifacts instead.

Monitor the workflow at <https://github.com/x4ngus/lockchain/actions>.

### 4. Post-release smoke test

Pull the assets from the GitHub Release and validate on a clean Ubuntu 25.10 VM:

```bash
wget https://github.com/x4ngus/lockchain/releases/download/v0.2.1/lockchain-zfs_0.2.1-1_amd64.deb
wget https://github.com/x4ngus/lockchain/releases/download/v0.2.1/lockchain-zfs_0.2.1-1_amd64.deb.asc
wget https://github.com/x4ngus/lockchain/releases/download/v0.2.1/SHA256SUMS
wget https://github.com/x4ngus/lockchain/releases/download/v0.2.1/SHA256SUMS.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
sudo apt install ./lockchain-zfs_0.2.1-1_amd64.deb
```

Run `lockchain tuning` (aliases: `lockchain self-heal`, `lockchain doctor`) and `lockchain repair` after installation to ensure the mount/unlock units are in place, then confirm `sudo systemctl status lockchain.service lockchain-key-usb.service`. The Control Deck, CLI, and daemon should operate without additional configuration beyond the standard LockChain config file.
