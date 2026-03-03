# Changelog // LockChain

> _"Version numbers are just coordinates through space and time."_

<!--
Format: ## vX.Y.Z — Title (DD-MM-YYYY)
Sub-sections (use only what applies):
  **Highlights** — behavioural changes and new features
  **Fixes**      — bug fixes and regressions
  **Docs & UX**  — documentation, logging, and UI changes
  **Chore**      — dependency bumps, CI, refactors with no behaviour change
Keep entries concise. One line per item. Reference ADRs or issues where useful.
-->

All notable changes to this project are documented here. Follows semantic versioning after `v1.0`; until then every milestone release is logged.

## v0.2.1 — LockChain Unified Baseline (14-12-2025)

**Highlights**
- Rebases LockChain as a unified multi-provider workspace (ZFS implemented; LUKS scaffolded).
- Introduces `lockchain-provider` for shared provider contracts, keeping `lockchain-core` focused on workflows.
- Adds `lockchain-luks` crate scaffolding and provider/packaging placeholders for cryptsetup + crypttab + initrd hooks.

**Docs & UX**
- Adds `docs/PROVIDERS.md`, `docs/UI.md`, and ADR-003 for LUKS deployment patterns.
- Refreshes provider architecture notes to reflect the multi-provider layout.

---

## Earlier Releases — ZFS-only lineage

> These entries predate the repo consolidation at v0.2.1. The project was previously split across
> `x4ngus/lockchain-zfs` and `lockchain-org/lockchain`; history is preserved here for continuity.

## v0.2.0-alpha — LockChain Access Ramp (01-12-2025)

**Highlights**
- Added initramfs-tools support alongside dracut with strict `--add lockchain` rebuilds and hard-fail audits to ensure loader assets ship in every image.
- Hardened diagnostics: privilege-aware mounting, reduced log noise for `lockchain-key-usb`, and clearer remediation when tokens are missing or busy.
- Loader fixes for early-boot environments: removed `dirname` dependency, preserved read-only USB handling, and unified checksum/UUID validation across initramfs and the watcher.

**Docs & UX**
- README refreshed with alpha disclaimer, sharper positioning, and a modernised quickstart.
- INSTALL/RELEASE guides updated to the 0.2.0-alpha package coordinates.
- Added `docs/THREAT_MODEL.md` covering attack surface and standards alignment.

## v0.1.9 — Control Deck Ignition (28-10-2025)

- Initial Control Deck (Iced) release with dataset directives for forge, tuning, and unlock.
- USB watcher normalises raw/hex keys and enforces permissions.
- Systemd units for unlock orchestration and CLI/daemon parity on workflows.
