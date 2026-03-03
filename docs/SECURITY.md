# Security Brief

How we handle disclosure, what tracks we support, and the operational controls you should enforce when running LockChain’s **ZFS provider** (v0.2.1). LUKS support is tracked under ADR-003.

---

## Coordinated Disclosure

- **Primary channel:** `security@lockchain.io` (TLS enforced).  
- **Secondary:** GitHub Security Advisories on `x4ngus/lockchain`.  
- **Response targets:** acknowledge within 48 hours, progress updates at least weekly, and remediation plans for high-impact issues within 14 days when a root cause is understood. We will negotiate timelines if additional time is needed for safe rollout.
- **Include in reports:** tag/commit, host OS + kernel/ZFS versions, reproduction steps, minimal config snippets (scrub secrets), and log excerpts (set `LOCKCHAIN_LOG_FORMAT=plain` to aid triage). Note any external disclosure deadlines up front.

Please avoid public issues for vulnerabilities until a fix is available.

## Support Window

| Track | Status | Notes |
| --- | --- | --- |
| `main` | Supported | First to receive security fixes and advisories. |
| Latest two tags (currently `v0.2.1` and previous) | Supported | Signed `.deb` artefacts shipped; breaking changes possible while pre-1.0. |
| Older tags | Best effort | Upgrade recommended for security coverage. |

Release assets are signed in CI; verify `SHA256SUMS` and the detached signatures before installation (see `docs/RELEASE.md`).

## Operating Assumptions

- Ubuntu 25.10 (or compatible) with native ZFS encryption, systemd, and journald.  
- Physical custody of the USB token; secure boot and kernel integrity are out of LockChain’s control.  
- `/run` is tmpfs and available; network connectivity is not required beyond optional updates.

## Hardening Checklist

1. **Service identity** — Run all units as the dedicated `lockchain` user. Packaging and install scripts create the account and `/var/lib/lockchain`.  
2. **Config custody** — `/etc/lockchain.toml` should be `640` owned by `root:lockchain`; avoid world-readable copies or VCS check-ins.  
3. **Key hygiene** — Keys live at `/run/lockchain/key.raw` with `0400`. Do not stage keys in home directories. Keep recovery keys offline and treat Control Deck QR exports as sensitive.  
4. **USB enforcement** — Keep `lockchain-key-usb` enabled; bind tokens by UUID or label and set `usb.expected_sha256`. Prefer read-only mounts in policy.  
5. **Initramfs integrity** — After kernel or policy changes, run `lockchain tuning` (or the Control Deck Tuning directive) to rebuild and audit dracut/initramfs-tools assets.  
6. **Strict unlocks** — Default to `lockchain unlock --strict-usb` (or enable Strict USB in UI) to prevent silent fallbacks.  
7. **Telemetry discipline** — Leave logs in JSON (`LOCKCHAIN_LOG_FORMAT=json`) for SIEM ingestion; switch to `plain` only while debugging. Health endpoint binds to `127.0.0.1:8787` by default—firewall if you rebind it.

## Least Privilege

- Prefer delegated ZFS ACLs over full root:

```bash
sudo zfs allow lockchain load-key,key tank/secure
```

- If sudo is required, scope it narrowly and validate with `visudo -cf`:

```
# /etc/sudoers.d/lockchain
lockchain ALL=(root) NOPASSWD:/usr/sbin/zfs load-key *, \
    /usr/sbin/zfs key -l *, \
    /usr/bin/lockchain-cli unlock *, \
    /usr/bin/lockchain-cli breakglass *
```

- Run `lockchain-cli`, `lockchain-daemon`, `lockchain-key-usb`, and `lockchain-ui` as the `lockchain` user to avoid ambient root privileges.

## Break-Glass & Recovery

Use only with explicit authorisation. All flows emit `[LC4000]` audit events.

```bash
lockchain validate -f /etc/lockchain.toml
lockchain breakglass tank/secure --output /root/tank-secure.key
```

Checklist:

1. CLI confirms the dataset and requires typing `BREAKGLASS`; Enter aborts.  
2. Provide the authorised passphrase (`--passphrase` for automation).  
3. The tool derives the raw 32-byte key, writes it `0400`, and logs the action.  
4. Load immediately (`zfs load-key`) and destroy the file (`shred && rm`) after use.  
5. Re-provision the USB token with `lockchain init --safe --device <usb>` and rerun `lockchain tuning`/`lockchain repair` to restore steady state.  
6. For scripted DR, `--force` bypasses prompts—guard it with the same approvals you would require for a failover.

## CI & Supply Chain Controls

- CI workflows explicitly scope the default `GITHUB_TOKEN` to least privilege (`contents: read`) wherever write access is not required.
- CI avoids privileged `workflow_run` checkouts/restores for pull request code, reducing exposure to untrusted-checkout and cache-poisoning attack classes.
- Release signing remains restricted to maintainer-controlled events; verify published artefacts with `SHA256SUMS` and detached signatures.

## Reporting Channels

- **Email:** security@lockchain.io  
- **GitHub Security Advisories:** create a draft advisory on `x4ngus/lockchain`.  
- **Encrypted reports:** request the current PGP key via the security inbox if needed.

Researchers who help secure LockChain are credited in the changelog unless anonymity is requested. We coordinate with upstream ZFS projects when issues cross boundaries.
