# E2E Test Plan: Hyper-V Harness - Ubuntu 25.10 (LUKS VM + ZFS VM)

## Purpose
Define UAT steps to build two Hyper-V VMs and install Ubuntu 25.10 using the installer-provided encryption paths (LUKS root and ZFS root) to simulate fresh OS setups ready for LockChain.

## Scope
- Windows host with Hyper-V
- VM A: Ubuntu 25.10 with LUKS-encrypted root via installer
- VM B: Ubuntu 25.10 with ZFS-encrypted root via installer
- Boot-time unlock prompts and post-install validation

## Out of Scope
- LockChain product installation and workflows (see docs/INSTALL.md)
- Performance or stress testing
- Multi-disk data pools beyond the OS disk

## References
- docs/INSTALL.md
- docs/PROVIDERS.md
- Ubuntu 25.10 release notes (record URL and build ID used)

## Roles
- UAT operator: executes steps, captures evidence, reports pass or fail
- Reviewer: validates evidence and sign-off

## Environment and Prerequisites
- Host OS: Windows 11 or Windows Server with Hyper-V role enabled
- CPU: virtualization enabled (Intel VT-x or AMD-V), SLAT supported
- RAM: at least 16 GB total, allocate at least 8 GB to each VM
- Disk: at least 120 GB free for VHDX files
- Networking: External or Default Switch with internet access
- ISO: Ubuntu 25.10 amd64 ISO (if not GA, use daily build and record build label)

## Test Data and Naming
- vSwitch: UAT-SWITCH
- VM A (LUKS): uat-ubuntu-25.10-luks
  - Generation: Gen2
  - CPU: 2 vCPU (minimum)
  - RAM: 8192 MB (Dynamic Memory enabled)
  - OS disk: 40 GB VHDX
  - Encryption: Installer option "Erase disk and encrypt" (LUKS)
- VM B (ZFS): uat-ubuntu-25.10-zfs
  - Generation: Gen2
  - CPU: 2 vCPU (minimum)
  - RAM: 8192 MB (Dynamic Memory enabled)
  - OS disk: 60 GB VHDX
  - Encryption: Installer option "Erase disk and use ZFS" with "Encrypt the new ZFS pool"
- Passphrases: store in UAT vault and record ID only in evidence

## Entry Criteria
- Hyper-V role installed and verified
- Ubuntu 25.10 ISO available
- UAT operator has local admin on host and sudo in guest

## Exit Criteria
- All test cases pass
- Evidence captured and archived
- Any deviations documented

## Evidence to Capture
- Screenshots: Hyper-V VM settings for both VMs
- Installer screens showing encryption selection (LUKS and ZFS)
- Boot-time unlock prompts for both VMs
- Command outputs:
  - LUKS VM: lsblk -f, cryptsetup luksDump (root device), /etc/crypttab
  - ZFS VM: zpool list, zpool status, zfs get encryption,keylocation,keyformat
- OS version confirmation: lsb_release -a

## Test Cases

### TC-01 Create Hyper-V VM Harnesses
Objective: Provision two Gen2 VMs with the Ubuntu ISO.

Steps:
1) Create VM uat-ubuntu-25.10-luks with the LUKS specs in Test Data and Naming.
2) Create VM uat-ubuntu-25.10-zfs with the ZFS specs in Test Data and Naming.
3) Attach Ubuntu 25.10 ISO to both VMs.
4) Confirm Secure Boot is enabled (UEFI) with Microsoft UEFI Certificate Authority.
5) Confirm network is attached to UAT-SWITCH.

Expected Results:
- Both VMs boot to the Ubuntu installer.

Evidence:
- Screenshot of VM settings for each VM.

### TC-02 Install Ubuntu 25.10 with LUKS Root Encryption (VM A)
Objective: Use the installer-provided LUKS root encryption path.

Steps:
1) Boot uat-ubuntu-25.10-luks and select "Install Ubuntu".
2) Use standard install. At storage setup, choose "Erase disk and encrypt".
3) Set the encryption passphrase (record vault ID only).
4) Complete installation and reboot.

Expected Results:
- System installs successfully and reaches the login prompt.

Evidence:
- Screenshot of installer storage screen showing encryption enabled.
- Screenshot of successful login.

### TC-03 Verify LUKS Root Encryption and Unlock Prompt (VM A)
Objective: Confirm root filesystem is LUKS-encrypted and requires unlock on boot.

Steps:
1) After login, run: lsb_release -a
2) Identify the root block device: lsblk -f
3) Capture LUKS header: sudo cryptsetup luksDump /dev/<root-device>
4) Verify crypttab entry: sudo cat /etc/crypttab
5) Reboot and confirm the passphrase prompt appears.

Expected Results:
- Root filesystem is mapped through dm-crypt.
- Boot requires the LUKS passphrase.

Evidence:
- Output for lsblk -f, cryptsetup luksDump, and /etc/crypttab.
- Screenshot of boot unlock prompt.

### TC-04 Install Ubuntu 25.10 with ZFS Root Encryption (VM B)
Objective: Use the installer-provided ZFS root encryption path.

Steps:
1) Boot uat-ubuntu-25.10-zfs and select "Install Ubuntu".
2) At storage setup, choose "Erase disk and use ZFS".
3) Enable "Encrypt the new ZFS pool" and set the passphrase (record vault ID only).
4) Complete installation and reboot.

Expected Results:
- System installs successfully and reaches the login prompt.

Evidence:
- Screenshot of installer storage screen showing ZFS encryption enabled.
- Screenshot of successful login.

### TC-05 Verify ZFS Root Encryption and Unlock Prompt (VM B)
Objective: Confirm root pool is ZFS-encrypted and requires unlock on boot.

Steps:
1) After login, run: lsb_release -a
2) Identify the ZFS pool name: zpool list (pool is usually rpool).
3) Check pool status: zpool status
4) Verify encryption: zfs get encryption,keylocation,keyformat <pool>
5) Reboot and confirm the passphrase prompt appears.

Expected Results:
- Root pool reports encryption enabled.
- Boot requires the ZFS passphrase.

Evidence:
- Output for zpool list, zpool status, and zfs get encryption.
- Screenshot of boot unlock prompt.

### TC-06 Baseline Package Verification (Both VMs)
Objective: Ensure required tooling is present for LockChain readiness.

Steps:
1) On the LUKS VM:
   - sudo apt update
   - sudo apt install -y cryptsetup
   - cryptsetup --version
2) On the ZFS VM:
   - sudo apt update
   - sudo apt install -y zfsutils-linux
   - zpool --version

Expected Results:
- Packages are installed and tools are available.

Evidence:
- Command output logs for each VM.

## Cleanup and Rollback
- Power off and delete both VMs (uat-ubuntu-25.10-luks, uat-ubuntu-25.10-zfs).
- Delete associated VHDX files.

## UAT Report Template
- Build ID (Ubuntu ISO):
- Host OS and Hyper-V version:
- VM A results (LUKS): Pass/Fail, evidence location, passphrase vault ID
- VM B results (ZFS): Pass/Fail, evidence location, passphrase vault ID
- Issues or defects:
- Sign-off:
