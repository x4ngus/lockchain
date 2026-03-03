# TODO

Flat task list for active development. No sprint tooling required.

---

## Next Up

- [ ] Complete LUKS provider implementation (`crates/lockchain-luks`) — see ADR-003
- [ ] End-to-end install smoke test on clean Ubuntu 24.04 from the `.deb` (no hand-holding)
- [ ] Add `cargo tarpaulin` coverage gate to CI (target: ≥70% on `lockchain-core`)
- [ ] Declare MSRV in `Cargo.toml` and add MSRV check job to `lint.yml`
- [ ] Enable branch protection on `main` (require PR + status checks)
- [ ] Make `lockchain-ui` depend only on `lockchain-provider`, not directly on `lockchain-zfs`/`lockchain-luks`

## In Progress

- [ ] Hyper-V end-to-end test environment (2 VM, Ubuntu, ZFS + LUKS validation)

## Backlog

- [ ] LUKS `crypttab` integration and initrd hooks
- [ ] Full `docs/INSTALL.md` runbook covering both ZFS and LUKS providers
- [ ] Troubleshooting guide for degraded pools, broken hardware, misconfigured datasets
- [ ] Security operations guide aligned to `docs/THREAT_MODEL.md`
- [ ] `cargo tarpaulin` baseline run — establish current coverage before gating on it
- [ ] `lockchain profile-unlock` baseline benchmarks documented in `docs/`
- [ ] Review `lockchain-luks` workspace membership — consider excluding until implementation lands

---

_Manage this list by hand. Open GitHub Issues for anything that needs discussion or external input._
