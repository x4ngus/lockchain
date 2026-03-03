# Contributing Guide

LockChain thrives when contributors treat the codebase like a security control: traceable, testable, and easy to reason about under pressure. This guide sets expectations so every change slots cleanly into the architecture and aesthetic we’ve chosen.

---

## Baseline Requirements

- **Rust toolchain**: stable (`rustup toolchain install stable`)  
- **Formatting & linting**: `cargo fmt` and `cargo clippy --all-targets -- -D warnings`  
- **Coverage signal**: `cargo tarpaulin --workspace --ignore-tests` should keep the core crate ≥ 70%  
- **Docs discipline**: README, ADRs, and relevant runbooks must reflect functional changes

## Getting Started

1. Fork and clone the repository.  
2. Prove the environment by running the integration smoke test:
   ```bash
   cargo test -p lockchain-zfs --test unlock_smoke
   ```
3. Install optional dependencies if you intend to touch the peripherals:
   - `libudev-dev` (or distro equivalent) for `lockchain-key-usb`
   - `pkg-config`, `python3` for simulated provider tests and fixtures

## Branching & Preflight Checklist

- Use `feature/<topic>` or `fix/<issue>` branch names; keep commits scoped and descriptive.  
- Before opening a pull request run:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo tarpaulin --workspace --ignore-tests  # include results in the PR when applicable
```

## Review Expectations

- Every change needs test coverage. Unit tests, integration tests, or targeted smoke tests are acceptable; explain your choice in the PR.  
- Preserve structured logging; default to JSON output and respect existing log helpers.  
- Touching configuration, security posture, or workflows requires documentation updates (README, runbooks, or ADRs).  
- Address reviewer comments collaboratively; rebase or squash only when the discussion has settled.

## Documentation Rhythm

- Keep `docs/` aligned with behaviour. The style is “neon with intent”: professional tone with understated cyberpunk visuals.  
- Record architectural or policy decisions in `docs/adr/ADR-00X-*.md`. Reference them from README or other docs when user-facing impact exists.

## Issue Handling

- **Bug reports** should include: command output, relevant log snippets (set `LOCKCHAIN_LOG_FORMAT=plain` if it aids readability), kernel/ZFS versions, and reproduction notes.  
- **Feature requests** benefit from an initial discussion thread, especially if the change reaches into provider behaviour or privilege boundaries.  
- **Security reports** must follow the disclosure process in [`docs/SECURITY.md`](SECURITY.md); avoid public issues for vulnerabilities.

## Release Workflow (maintainers)

**CHANGELOG entry format** (`CHANGELOG.md` header comment has the canonical spec):
```
## vX.Y.Z — Title (DD-MM-YYYY)
**Highlights** / **Fixes** / **Docs & UX** / **Chore** (use only what applies)
```

1. Update the root `CHANGELOG.md` with a concise entry using the format above.  
2. Tag and push the release (e.g. `v0.2.1`); automation produces signed `.deb` assets.  
3. Attach only supplemental artefacts; the workflow already uploads the `.deb`, signatures, and checksums.

## Thank You

Add yourself to `docs/CONTRIBUTORS.md` (create it if blank), stay active in discussions, and keep the glow consistent. Together we keep the vault resilient.

— LockChain maintainers
