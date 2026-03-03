//! Shared bootstrap planning helpers for installers and UI wizards.

use super::provisioning::{discover_usb_candidates, UsbCandidate};
use crate::config::{
    bootstrap_dataset_candidates, default_binary_hint, default_config_path, default_key_filename,
    default_key_mountpoint, default_systemd_hint, default_usb_label, detect_zfs_binary_path,
    detect_zpool_binary_path,
};
use crate::error::{LockchainError, LockchainResult};
use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

/// Snapshot of ZFS pools present on the host.
#[derive(Debug, Clone, Serialize)]
pub struct ZfsPoolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
}

/// Snapshot of encrypted datasets detected on the host.
#[derive(Debug, Clone, Serialize)]
pub struct DatasetInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystatus: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mountpoint: Option<String>,
    pub encrypted: bool,
}

/// Inventory of ZFS and removable media surfaces.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapTopology {
    pub pools: Vec<ZfsPoolInfo>,
    pub datasets: Vec<DatasetInfo>,
    pub usb: Vec<UsbCandidate>,
}

/// Shell command that needs to run as part of bootstrap.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapCommand {
    pub label: String,
    pub command: String,
    pub requires_root: bool,
}

/// Ordered step in the bootstrap plan.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapStep {
    pub id: String,
    pub title: String,
    pub description: String,
    pub commands: Vec<BootstrapCommand>,
}

/// Structured plan tailored to the requested dataset and host paths.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapPlan {
    pub datasets: Vec<String>,
    pub config_path: PathBuf,
    pub service_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usb_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usb_uuid: Option<String>,
    pub key_mountpoint: PathBuf,
    pub key_filename: String,
    pub steps: Vec<BootstrapStep>,
}

/// Tuning knobs that influence the generated bootstrap plan.
#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    pub datasets: Vec<String>,
    pub service_user: String,
    pub config_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub binary_dir: PathBuf,
    pub systemd_dir: PathBuf,
    pub systemd_source: PathBuf,
    pub usb_label: Option<String>,
    pub usb_uuid: Option<String>,
    pub key_mountpoint: PathBuf,
    pub key_filename: String,
    pub usb_device: Option<String>,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        Self {
            datasets: Vec::new(),
            service_user: "lockchain".to_string(),
            config_path: PathBuf::from(default_config_path()),
            artifact_dir: PathBuf::from("."),
            binary_dir: PathBuf::from(default_binary_hint()),
            systemd_dir: PathBuf::from(default_systemd_hint()),
            systemd_source: PathBuf::from("packaging/systemd"),
            usb_label: None,
            usb_uuid: None,
            key_mountpoint: PathBuf::from(default_key_mountpoint()),
            key_filename: default_key_filename().to_string(),
            usb_device: None,
        }
    }
}

impl BootstrapOptions {
    fn resolved_systemd_source(&self) -> PathBuf {
        if self.systemd_source.is_absolute() {
            self.systemd_source.clone()
        } else {
            self.artifact_dir.join(&self.systemd_source)
        }
    }

    fn resolved_artifact(&self, name: &str) -> PathBuf {
        let direct = self.artifact_dir.join(name);
        if direct.exists() {
            direct
        } else {
            PathBuf::from(name)
        }
    }
}

/// Inspect the host for ZFS pools, datasets, and removable USB candidates.
pub fn discover_topology() -> LockchainResult<BootstrapTopology> {
    let pools = discover_pools()?;
    let datasets = discover_datasets()?;
    let usb = discover_usb_candidates()?;
    Ok(BootstrapTopology {
        pools,
        datasets,
        usb,
    })
}

/// Compose a bootstrap plan tailored to the provided options.
pub fn bootstrap_plan(options: &BootstrapOptions) -> LockchainResult<BootstrapPlan> {
    let mut datasets = if options.datasets.is_empty() {
        bootstrap_dataset_candidates()
    } else {
        options
            .datasets
            .iter()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>()
    };

    if datasets.is_empty() {
        return Err(LockchainError::InvalidConfig(
            "no dataset specified; provide --dataset when invoking the bootstrap planner"
                .to_string(),
        ));
    }

    datasets.sort();
    datasets.dedup();

    let usb_label = options
        .usb_label
        .as_ref()
        .map(|label| label.trim().to_string())
        .filter(|label| !label.is_empty())
        .or_else(|| Some(default_usb_label().to_string()));

    // lgtm[rust/cleartext-logging] - device UUID used for bootstrap plan output, not a secret
    let usb_uuid = options
        .usb_uuid
        .as_ref()
        .map(|uuid| uuid.trim().to_string())
        .filter(|uuid| !uuid.is_empty());

    let device_reference = options
        .usb_device
        .as_ref()
        .map(|device| device.trim().to_string())
        .filter(|device| !device.is_empty())
        .unwrap_or_else(|| "<DEVICE>".to_string());

    let device_partition_reference = options
        .usb_device
        .as_ref()
        .map(|device| device.trim().to_string())
        .filter(|device| !device.is_empty())
        .unwrap_or_else(|| "<DEVICE_PARTITION>".to_string());

    let device_str = device_reference.as_str();
    let device_partition_str = device_partition_reference.as_str();

    let mut steps = Vec::new();

    steps.push(BootstrapStep {
        id: "service-account".into(),
        title: "Provision Lockchain service account".into(),
        description:
            "Create the dedicated lockchain service user and staging directory for key material."
                .into(),
        commands: vec![
            BootstrapCommand {
                label: "Ensure system group exists".into(),
                command: format!(
                    "getent group {user} >/dev/null || groupadd --system {user}",
                    user = options.service_user
                ),
                requires_root: true,
            },
            BootstrapCommand {
                label: "Ensure system user exists".into(),
                command: format!(
                    "id -u {user} >/dev/null 2>&1 || useradd --system --home /var/lib/lockchain --shell /usr/sbin/nologin --gid {user} {user}",
                    user = options.service_user
                ),
                requires_root: true,
            },
            BootstrapCommand {
                label: "Create key staging directory".into(),
                command: format!(
                    "install -d -o {user} -g {user} /var/lib/lockchain",
                    user = options.service_user
                ),
                requires_root: true,
            },
        ],
    });

    let binaries = [
        ("lockchain-cli", "Operator console"),
        ("lockchain-daemon", "Unlock daemon"),
        ("lockchain-key-usb", "USB watcher"),
        ("lockchain-ui", "Control Deck UI"),
    ];
    let mut binary_commands = Vec::new();
    for (binary, description) in binaries {
        let source = options.resolved_artifact(binary);
        binary_commands.push(BootstrapCommand {
            label: format!("Install {description}"),
            command: format!(
                "install -Dm755 \"{src}\" \"{dst}/{binary}\"",
                src = source.display(),
                dst = options.binary_dir.display()
            ),
            requires_root: true,
        });
    }
    steps.push(BootstrapStep {
        id: "binary-placement".into(),
        title: "Place binaries on the host".into(),
        description:
            "Install the Lockchain binaries into the system PATH so CLI, daemon, and UI share one implementation."
                .into(),
        commands: binary_commands,
    });

    let mut symlink_commands = Vec::new();
    for (binary, description) in [
        ("lockchain-cli", "CLI"),
        ("lockchain-daemon", "daemon"),
        ("lockchain-key-usb", "USB watcher"),
        ("lockchain-ui", "UI"),
    ] {
        symlink_commands.push(BootstrapCommand {
            label: format!("Link {description} into /usr/bin"),
            command: format!(
                "ln -sf \"{src}/{binary}\" /usr/bin/{binary}",
                src = options.binary_dir.display()
            ),
            requires_root: true,
        });
    }
    steps.push(BootstrapStep {
        id: "binary-symlinks".into(),
        title: "Expose binaries via /usr/bin".into(),
        description:
            "Create compatibility symlinks so systemd units and dracut hooks can invoke Lockchain binaries via /usr/bin."
                .into(),
        commands: symlink_commands,
    });

    let dataset_flags = datasets
        .iter()
        .map(|dataset| format!("--dataset \"{dataset}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let mut template_cmd = format!(
        "lockchain-cli bootstrap template {datasets}",
        datasets = dataset_flags
    );
    if let Some(label) = usb_label.as_ref() {
        template_cmd.push_str(&format!(" --usb-label \"{label}\""));
    }
    if let Some(uuid) = usb_uuid.as_ref() {
        template_cmd.push_str(&format!(" --usb-uuid \"{uuid}\""));
    }

    steps.push(BootstrapStep {
        id: "config-template".into(),
        title: "Generate configuration template".into(),
        description: format!(
            "Create {path} with the selected dataset(s) and USB selector. Adjust policy/fallback values before unlocking production pools.",
            path = options.config_path.display()
        ),
        commands: vec![
            BootstrapCommand {
                label: "Create config skeleton".into(),
                command: format!(
                    "install -Dm640 /dev/null \"{path}\"",
                    path = options.config_path.display()
                ),
                requires_root: true,
            },
            BootstrapCommand {
                label: "Assign group ownership to service account".into(),
                command: format!(
                    "chgrp {user} \"{path}\"",
                    user = options.service_user,
                    path = options.config_path.display()
                ),
                requires_root: true,
            },
            BootstrapCommand {
                label: "Render bootstrap configuration".into(),
                command: format!("{template_cmd} > \"{path}\"", path = options.config_path.display()),
                requires_root: true,
            },
        ],
    });

    steps.push(BootstrapStep {
        id: "zfs-survey".into(),
        title: "Survey pools and encrypted datasets".into(),
        description:
            "Confirm the target dataset is encrypted and note the encryption root before delegating permissions."
                .into(),
        commands: vec![
            BootstrapCommand {
                label: "List pools".into(),
                command: "zpool list -o name,size,alloc,free,health".into(),
                requires_root: false,
            },
            BootstrapCommand {
                label: "Inspect dataset keystatus".into(),
                command: "zfs list -t filesystem -o name,keystatus,encroot,mountpoint".into(),
                requires_root: false,
            },
        ],
    });

    let mut delegation_commands = Vec::new();
    for dataset in &datasets {
        if dataset.contains('/') {
            delegation_commands.push(BootstrapCommand {
                label: format!("Delegate load-key for {dataset}"),
                command: format!(
                    "zfs allow {user} load-key,key \"{dataset}\" || echo 'Skipping delegation for {dataset}; verify encryption root supports `zfs allow`.'",
                    user = options.service_user,
                    dataset = dataset
                ),
                requires_root: true,
            });
        } else {
            delegation_commands.push(BootstrapCommand {
                label: format!("Manual delegation required for pool {dataset}"),
                command: format!(
                    "echo 'Dataset `{dataset}` is a pool; run `zfs allow {user} load-key,key <filesystem>` manually if needed.'",
                    dataset = dataset,
                    user = options.service_user
                ),
                requires_root: false,
            });
        }
    }
    steps.push(BootstrapStep {
        id: "delegate-permissions".into(),
        title: "Delegate ZFS permissions".into(),
        description: format!(
            "Allow the {user} account to run the key loading sequence without full root.",
            user = options.service_user
        ),
        commands: delegation_commands,
    });

    let systemd_source = options.resolved_systemd_source();
    let unit_files = [
        "run-lockchain.mount",
        "lockchain.service",
        "lockchain@.service",
        "lockchain-key-usb.service",
    ];
    let mut systemd_commands = Vec::new();
    for unit in &unit_files {
        let src = systemd_source.join(unit);
        systemd_commands.push(BootstrapCommand {
            label: format!("Install {unit}"),
            command: format!(
                "install -Dm644 \"{src}\" \"{dst}/{unit}\"",
                src = src.display(),
                dst = options.systemd_dir.display()
            ),
            requires_root: true,
        });
    }
    systemd_commands.push(BootstrapCommand {
        label: "Create runtime mountpoint".into(),
        command: format!(
            "install -d -m 0755 \"{mount}\"",
            mount = options.key_mountpoint.display()
        ),
        requires_root: true,
    });
    systemd_commands.push(BootstrapCommand {
        label: "Reload systemd manager configuration".into(),
        command: "systemctl daemon-reload".into(),
        requires_root: true,
    });
    systemd_commands.push(BootstrapCommand {
        label: "Enable volatile key staging mount".into(),
        command: "systemctl enable --now run-lockchain.mount".into(),
        requires_root: true,
    });
    systemd_commands.push(BootstrapCommand {
        label: "Enable base services".into(),
        command: "systemctl enable --now lockchain.service lockchain-key-usb.service".into(),
        requires_root: true,
    });
    for dataset in &datasets {
        systemd_commands.push(BootstrapCommand {
            label: format!("Enable unlock unit for {dataset}"),
            command: format!(
                "systemctl enable \"$(systemd-escape --template=lockchain@.service \"{dataset}\")\""
            ),
            requires_root: true,
        });
    }
    steps.push(BootstrapStep {
        id: "systemd-enable".into(),
        title: "Install and enable systemd unlock units".into(),
        description:
            "Stage the Lockchain service units and have systemd manage the unlock and USB watcher lifecycles."
                .into(),
        commands: systemd_commands,
    });

    let label_hint = usb_label
        .clone()
        .unwrap_or_else(|| default_usb_label().to_string());
    let mut usb_commands = vec![
        BootstrapCommand {
            label: "Review removable media".into(),
            command: "lsblk -o NAME,PATH,TYPE,RM,SIZE,MODEL,SERIAL,LABEL,TRAN,MOUNTPOINT".into(),
            requires_root: false,
        },
        BootstrapCommand {
            label: "Flush device buffers".into(),
            command: "udevadm settle".into(),
            requires_root: true,
        },
        BootstrapCommand {
            label: "Unmount existing partitions".into(),
            command: format!("umount \"{}\" || true", device_str),
            requires_root: true,
        },
        BootstrapCommand {
            label: "Clear prior signatures".into(),
            command: format!("wipefs -a \"{}\"", device_str),
            requires_root: true,
        },
        BootstrapCommand {
            label: "Format USB key".into(),
            command: format!(
                "mkfs.ext4 -F -L \"{label}\" \"{device}\"",
                label = label_hint,
                device = device_str
            ),
            requires_root: true,
        },
    ];
    usb_commands.push(BootstrapCommand {
        label: "Prime key directory".into(),
        command: format!(
            "mount \"{device}\" /mnt && install -d -o {user} -g {user} /mnt && touch /mnt/{key} && umount /mnt",
            device = device_str,
            user = options.service_user,
            key = options.key_filename
        ),
        requires_root: true,
    });
    steps.push(BootstrapStep {
        id: "usb-prepare".into(),
        title: "Prepare the USB token".into(),
        description:
            "Format the removable media with a fresh filesystem and stage a placeholder key file for Lockchain UI."
                .into(),
        commands: usb_commands,
    });

    let mut key_commands = Vec::new();
    for dataset in &datasets {
        key_commands.push(BootstrapCommand {
            label: format!("Forge key for {dataset}"),
            command: format!(
                "lockchain-cli init --dataset \"{dataset}\" --device \"{device}\" --safe",
                device = device_partition_str
            ),
            requires_root: true,
        });
    }
    key_commands.push(BootstrapCommand {
        label: "Run tuning after provisioning".into(),
        command: "lockchain-cli tuning".into(),
        requires_root: true,
    });
    key_commands.push(BootstrapCommand {
        label: "Repair systemd bindings if needed".into(),
        command: "lockchain-cli repair".into(),
        requires_root: true,
    });
    steps.push(BootstrapStep {
        id: "key-generation".into(),
        title: "Seed key material and validate integration".into(),
        description:
            "After the initial bootstrap, invoke the forge/tuning workflows to place real key material and verify the unlock path."
                .into(),
        commands: key_commands,
    });

    Ok(BootstrapPlan {
        datasets,
        config_path: options.config_path.clone(),
        service_user: options.service_user.clone(),
        usb_label,
        usb_uuid,
        key_mountpoint: options.key_mountpoint.clone(),
        key_filename: options.key_filename.clone(),
        steps,
    })
}

fn discover_pools() -> LockchainResult<Vec<ZfsPoolInfo>> {
    let binary = detect_zpool_binary_path().unwrap_or_else(|| "/usr/sbin/zpool".to_string());
    let output = Command::new(&binary)
        .args(["list", "-H", "-o", "name,size,alloc,free,health"])
        .output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LockchainError::Provider(format!(
            "zpool list failed: {stderr}"
        )));
    }
    let mut pools = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut cols = line.split('\t');
        let name = cols.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let size = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        let alloc = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        let free = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        let health = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        pools.push(ZfsPoolInfo {
            name: name.to_string(),
            size,
            alloc,
            free,
            health,
        });
    }
    Ok(pools)
}

fn discover_datasets() -> LockchainResult<Vec<DatasetInfo>> {
    let binary = detect_zfs_binary_path().unwrap_or_else(|| "/usr/sbin/zfs".to_string());
    let output = Command::new(&binary)
        .args([
            OsString::from("list"),
            OsString::from("-H"),
            OsString::from("-o"),
            OsString::from("name,keystatus,encroot,mountpoint"),
            OsString::from("-t"),
            OsString::from("filesystem"),
        ])
        .output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LockchainError::Provider(format!(
            "zfs list failed: {stderr}"
        )));
    }
    let mut datasets = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut cols = line.split('\t');
        let name = cols.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let keystatus = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        let encroot = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty() && c != "-");
        let mountpoint = cols
            .next()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty() && c != "-");
        let encrypted = encroot.is_some();
        datasets.push(DatasetInfo {
            name: name.to_string(),
            encryption_root: encroot,
            keystatus,
            mountpoint,
            encrypted,
        });
    }
    Ok(datasets)
}
