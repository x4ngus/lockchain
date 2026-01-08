#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

log() {
  printf '[lockchain-install] %s\n' "$*"
}

die() {
  printf '[lockchain-install] error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die 'installer must run as root'
  fi
}

INITRAMFS_TOOL=""
INITRAMFS_DRACUT_PATH=""
INITRAMFS_UPDATE_PATH=""

resolve_initramfs_tool() {
  INITRAMFS_DRACUT_PATH=$(command -v dracut 2>/dev/null || true)
  INITRAMFS_UPDATE_PATH=$(command -v update-initramfs 2>/dev/null || true)

  if [[ -n "$INITRAMFS_DRACUT_PATH" ]]; then
    INITRAMFS_TOOL="dracut"
    if [[ -n "$INITRAMFS_UPDATE_PATH" ]]; then
      log "Initramfs tooling detected: dracut ($INITRAMFS_DRACUT_PATH) and update-initramfs ($INITRAMFS_UPDATE_PATH); preferring dracut."
    else
      log "Initramfs tooling detected: dracut ($INITRAMFS_DRACUT_PATH)."
    fi
  elif [[ -n "$INITRAMFS_UPDATE_PATH" ]]; then
    INITRAMFS_TOOL="initramfs-tools"
    log "Initramfs tooling detected: update-initramfs ($INITRAMFS_UPDATE_PATH)."
  else
    INITRAMFS_TOOL=""
    log "Initramfs tooling not detected (dracut/update-initramfs missing)."
  fi
}

initramfs_rollback_hint() {
  local tool="$1"
  case "$tool" in
    dracut)
      log "Rollback (dracut): rm -rf /usr/lib/dracut/modules.d/90lockchain /lib/dracut/modules.d/90lockchain"
      log "Rollback (dracut): dracut -f"
      ;;
    initramfs-tools)
      log "Rollback (initramfs-tools): rm -f /etc/initramfs-tools/hooks/zz-lockchain /etc/initramfs-tools/scripts/local-top/lockchain /etc/initramfs-tools/scripts/init-top/00-lockchain-cryptsetup-keys"
      log "Rollback (initramfs-tools): update-initramfs -u"
      ;;
    *)
      log "Rollback: remove LockChain initramfs assets and rebuild your initramfs image."
      ;;
  esac
}

run_as_build_user() {
  local script="$1"
  if [[ -z "$script" ]]; then
    return 0
  fi
  if [[ "$BUILD_USER" == "root" ]]; then
    bash -lc "$script"
  else
    sudo -u "$BUILD_USER" -H bash -lc "$script"
  fi
}

SUMMARY_LINES=()

record_status() {
  SUMMARY_LINES+=("$1")
}

install_build_dependencies() {
  if [[ ${SKIP_DEPS:-0} -eq 1 ]]; then
    record_status 'Build dependency installation skipped (SKIP_DEPS=1)'
    return
  fi

  if ! command -v apt-get >/dev/null 2>&1; then
    record_status 'Build dependencies not installed automatically (apt-get unavailable)'
    return
  fi

  local apt_log
  apt_log=$(mktemp)
  export DEBIAN_FRONTEND=noninteractive
  if ! apt-get update -y -qq >"$apt_log" 2>&1; then
    cat "$apt_log" >&2
    rm -f "$apt_log"
    die 'apt-get update failed'
  fi
  if ! apt-get install -y -qq "${BUILD_PACKAGES[@]}" >>"$apt_log" 2>&1; then
    cat "$apt_log" >&2
    rm -f "$apt_log"
    die 'apt-get install failed'
  fi
  if [[ ${LOCKCHAIN_INSTALL_VERBOSE:-0} -eq 1 ]]; then
    cat "$apt_log"
  fi
  rm -f "$apt_log"
  record_status 'Build dependencies installed'
}

ensure_rust_toolchain() {
  if [[ ${SKIP_RUST:-0} -eq 1 ]]; then
    record_status 'Rust toolchain check skipped (SKIP_RUST=1)'
    return
  fi

  if run_as_build_user "source ~/.cargo/env 2>/dev/null || true; command -v cargo >/dev/null"; then
    local version
    version=$(run_as_build_user "source ~/.cargo/env 2>/dev/null || true; cargo --version" 2>/dev/null || echo 'unknown')
    record_status "Rust toolchain detected (${version})"
    return
  fi

  local rustup_log
  rustup_log=$(mktemp /tmp/lockchain-rustup.XXXXXX)
  local install_script
  install_script=$(cat <<EOF
set -euo pipefail
tmp_log="$rustup_log"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >"\$tmp_log" 2>&1
source ~/.cargo/env 2>/dev/null || true
rustup toolchain install stable >/dev/null 2>&1 || true
rustup default stable >/dev/null 2>&1
EOF
)
  if ! run_as_build_user "$install_script"; then
    if [[ -f "$rustup_log" ]]; then
      cat "$rustup_log" >&2
    fi
    rm -f "$rustup_log"
    die "Rust toolchain installation failed for user '${BUILD_USER}'"
  fi
  if [[ ${LOCKCHAIN_INSTALL_VERBOSE:-0} -eq 1 && -f "$rustup_log" ]]; then
    cat "$rustup_log"
  fi
  rm -f "$rustup_log"
  local version
  version=$(run_as_build_user "source ~/.cargo/env 2>/dev/null || true; cargo --version" 2>/dev/null || echo 'stable')
  record_status "Rust toolchain installed (${version})"
}

build_release() {
  if [[ ${SKIP_BUILD:-0} -eq 1 ]]; then
    record_status 'Release build skipped (SKIP_BUILD=1)'
    return
  fi

  local build_cmd="source ~/.cargo/env 2>/dev/null || true; cd \"$SCRIPT_DIR\" && cargo build --release --quiet"
  if ! run_as_build_user "$build_cmd"; then
    die 'cargo build --release failed'
  fi
  record_status 'Release artifacts built'
}

run_plan_steps() {
  local plan_file="$1"
  shift
  local device="$1"
  shift
  if [[ $# -eq 0 ]]; then
    return
  fi
  python3 - "$plan_file" "$device" "$@" <<'PY'
import json
import os
import subprocess
import sys

plan_path = sys.argv[1]
device = sys.argv[2]
steps = sys.argv[3:]

with open(plan_path, 'r', encoding='utf-8') as handle:
    plan = json.load(handle)

step_lookup = {step['id']: step for step in plan.get('steps', [])}
verbose_env = os.environ.get('LOCKCHAIN_INSTALL_VERBOSE', '')
verbose = verbose_env.lower() not in ('', '0', 'false', 'no')

for step_id in steps:
    step = step_lookup.get(step_id)
    if not step:
        continue
    title = step.get('title', step_id)
    description = step.get('description')
    commands = step.get('commands', [])
    header_state = [False]

    def emit_header():
        if header_state[0]:
            return
        print(f"[{step['id']}] {title}")
        if description:
            print(description)
        header_state[0] = True

    if verbose and (description or commands):
        emit_header()

    for command in commands:
        label = command.get('label', 'Command')
        cmd = command.get('command', '')
        requires_root = command.get('requires_root', False)
        if device:
            cmd = cmd.replace('<DEVICE>', device)
            cmd = cmd.replace('<DEVICE_PARTITION>', device)
        scope = 'root' if requires_root else 'user'
        result = subprocess.run(
            ['/bin/bash', '-lc', cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode == 0:
            if verbose:
                print(f"  ✓ ({scope}) {label}")
        else:
            if not header_state[0]:
                emit_header()
            print(f"  ✗ ({scope}) {label}")
            output = result.stdout.strip()
            if output:
                for line in output.splitlines():
                    print(f"    {line}")
            result.check_returncode()
    if header_state[0]:
        print()
PY
}

print_plan_step() {
  local plan_file="$1"
  local device="$2"
  local step_id="$3"
  python3 - "$plan_file" "$device" "$step_id" <<'PY'
import json
import sys

plan_path = sys.argv[1]
device = sys.argv[2]
target_step = sys.argv[3]

with open(plan_path, 'r', encoding='utf-8') as handle:
    plan = json.load(handle)

for step in plan.get('steps', []):
    if step.get('id') != target_step:
        continue
    print(f"[{step['id']}] {step.get('title', '')}")
    description = step.get('description')
    if description:
        print(description)
    for command in step.get('commands', []):
        label = command.get('label', 'Command')
        print(f"  - {label}")
    break
PY
}

select_dataset() {
  local discovery_json="$1"
  mapfile -t DATASET_JSON < <(
    printf '%s' "$discovery_json" |
      jq -c '
        .datasets
        | map(select(.encrypted == true))
        | .[]
      '
  )
  if ((${#DATASET_JSON[@]} == 0)); then
    die 'No encrypted datasets detected. Ensure zfs keystatus reports encrypted datasets.'
  fi

  echo 'Select the dataset to manage:'
  local idx=0
  local default_idx=0
  for payload in "${DATASET_JSON[@]}"; do
    local name
    name=$(jq -r '.name' <<<"$payload")
    if [[ "$name" == "rpool" ]]; then
      default_idx=$idx
      break
    fi
    idx=$((idx + 1))
  done

  idx=0
  for payload in "${DATASET_JSON[@]}"; do
    local name encroot keystatus mount
    name=$(jq -r '.name' <<<"$payload")
    encroot=$(jq -r '.encryption_root // "unknown"' <<<"$payload")
    keystatus=$(jq -r '.keystatus // "unknown"' <<<"$payload")
    mount=$(jq -r '.mountpoint // "-"' <<<"$payload")
    local marker=""
    if (( idx == default_idx )); then
      marker=" [default]"
    fi
    printf '  %d) %s (encroot %s, keystatus %s, mount %s)%s\n' $((idx + 1)) "$name" "$encroot" "$keystatus" "$mount" "$marker"
    idx=$((idx + 1))
  done

  local choice=""
  while [[ -z "$choice" ]]; do
    read -rp "Dataset [1-${#DATASET_JSON[@]}] (default $((default_idx + 1))): " answer
    if [[ -z "$answer" ]]; then
      choice=$default_idx
    elif [[ $answer =~ ^[0-9]+$ ]] && ((answer >= 1 && answer <= ${#DATASET_JSON[@]})); then
      choice=$((answer - 1))
    else
      echo 'Invalid selection.' >&2
    fi
  done

  SELECTED_DATASET=$(jq -r '.name' <<<"${DATASET_JSON[$choice]}")
  SELECTED_ENCROOT=$(jq -r '.encryption_root // .name' <<<"${DATASET_JSON[$choice]}")
}

select_usb_device() {
  local discovery_json="$1"
  mapfile -t USB_JSON < <(printf '%s' "$discovery_json" | jq -c '.usb[]')

  if ((${#USB_JSON[@]} == 0)); then
    echo 'No removable USB candidates detected; manual entry required.'
    read -rp 'Enter USB block device (e.g., /dev/sdX1): ' manual
    [[ -b "$manual" ]] || die "$manual is not a block device"
    SELECTED_DEVICE="$manual"
    SELECTED_LABEL="LOCKCHAINKEY"
    return
  fi

  echo 'Select the USB device to format:'
  local idx=0
  for payload in "${USB_JSON[@]}"; do
    local device disk label size model bus mount
    device=$(jq -r '.device' <<<"$payload")
    disk=$(jq -r '.disk' <<<"$payload")
    label=$(jq -r '.label // "-"' <<<"$payload")
    size=$(jq -r '.size // "-"' <<<"$payload")
    model=$(jq -r '.model // "-"' <<<"$payload")
    bus=$(jq -r '.transport // "-"' <<<"$payload")
    mount=$(jq -r '.mountpoint // "-"' <<<"$payload")
    printf '  %d) %s (%s, label %s, model %s, bus %s, mount %s)\n' \
      $((idx + 1)) "$device" "$size" "$label" "$model" "$bus" "$mount"
    idx=$((idx + 1))
  done
  echo '  m) Manual entry'

  local choice=""
  while [[ -z "$choice" ]]; do
    read -rp "Device [1-${#USB_JSON[@]}|m]: " answer
    if [[ $answer =~ ^[0-9]+$ ]] && ((answer >= 1 && answer <= ${#USB_JSON[@]})); then
      local entry=${USB_JSON[$((answer - 1))]}
      SELECTED_DEVICE=$(jq -r '.device' <<<"$entry")
      SELECTED_DISK=$(jq -r '.disk' <<<"$entry")
      SELECTED_LABEL=$(jq -r '.label // "LOCKCHAINKEY"' <<<"$entry")
      choice='ok'
    elif [[ $answer == "m" || $answer == "M" ]]; then
      read -rp 'Enter USB block device (e.g., /dev/sdX1): ' manual
      [[ -b "$manual" ]] || die "$manual is not a block device"
      SELECTED_DEVICE="$manual"
      SELECTED_DISK="$(lsblk -no pkname "$manual" 2>/dev/null || basename "$manual")"
      SELECTED_LABEL="LOCKCHAINKEY"
      choice='ok'
    else
      echo 'Invalid selection.' >&2
    fi
  done
}

require_root

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TARGET_DIR=${TARGET_DIR:-"$SCRIPT_DIR/target/release"}
BINARY_DEST=${BINARY_DEST:-/usr/local/bin}
SYSTEMD_DEST=${SYSTEMD_DEST:-/etc/systemd/system}
SYSTEMD_SOURCE=${SYSTEMD_SOURCE:-"$SCRIPT_DIR/packaging/systemd"}
CONFIG_PATH=${CONFIG_PATH:-/etc/lockchain.toml}
SERVICE_USER=${SERVICE_USER:-lockchain}
KEY_MOUNT=${KEY_MOUNT:-/run/lockchain}
KEY_FILENAME=${KEY_FILENAME:-key.raw}
BUILD_USER=${BUILD_USER:-${SUDO_USER:-root}}

export LOCKCHAIN_CONFIG=${LOCKCHAIN_CONFIG:-$CONFIG_PATH}

BUILD_PACKAGES=(
  build-essential
  pkg-config
  libssl-dev
  libudev-dev
  libgtk-3-dev
  libxcb-render0-dev
  libxcb-shape0-dev
  libxcb-xfixes0-dev
  libxkbcommon-dev
  libvulkan-dev
  python3
  jq
  curl
  ca-certificates
)

if [[ ${LOCKCHAIN_INSTALL_VERBOSE:-0} -eq 0 ]]; then
  log 'LockChain installer starting (quiet mode). Detailed output suppressed.'
fi

install_build_dependencies
ensure_rust_toolchain
build_release
resolve_initramfs_tool
if [[ -n "$INITRAMFS_TOOL" ]]; then
  record_status "Initramfs tooling detected (${INITRAMFS_TOOL})"
else
  record_status 'Initramfs tooling not detected'
fi

CLI_BIN="$TARGET_DIR/lockchain-cli"
[[ -x "$CLI_BIN" ]] || die "lockchain-cli not found at $CLI_BIN. Ensure cargo build succeeded."

DISCOVERY_JSON=$("$CLI_BIN" bootstrap discover --format json)

select_dataset "$DISCOVERY_JSON"
select_usb_device "$DISCOVERY_JSON"

USB_LABEL_DEFAULT=${SELECTED_LABEL:-LOCKCHAINKEY}
read -rp "USB label [$USB_LABEL_DEFAULT]: " usb_label_input
if [[ -n $usb_label_input ]]; then
  USB_LABEL="$usb_label_input"
else
  USB_LABEL="$USB_LABEL_DEFAULT"
fi

[[ -b "$SELECTED_DEVICE" ]] || die "$SELECTED_DEVICE is not a block device"

echo "Warning: formatting $SELECTED_DEVICE will erase all data."
read -rp 'Proceed with formatting? [y/N]: ' confirm_fmt
if [[ ! $confirm_fmt =~ ^[Yy]$ ]]; then
  die 'Aborted by user'
fi

PLAN_USB=$(mktemp)
PLAN_MAIN=$(mktemp)
cleanup() {
  rm -f "$PLAN_USB" "$PLAN_MAIN"
}
trap cleanup EXIT

PLAN_ARGS=(bootstrap plan --dataset "$SELECTED_DATASET" --config "$CONFIG_PATH" --user "$SERVICE_USER" \
  --artifacts "$TARGET_DIR" --bin-dir "$BINARY_DEST" --systemd-dir "$SYSTEMD_DEST" \
  --systemd-source "$SYSTEMD_SOURCE" --usb-label "$USB_LABEL" --usb-device "$SELECTED_DEVICE" \
  --key-mount "$KEY_MOUNT" --key-filename "$KEY_FILENAME" --format json)

"$CLI_BIN" "${PLAN_ARGS[@]}" >"$PLAN_USB"

run_plan_steps "$PLAN_USB" "$SELECTED_DEVICE" service-account
record_status 'Service account ready'

run_plan_steps "$PLAN_USB" "$SELECTED_DEVICE" usb-prepare
record_status 'USB media prepared'

USB_UUID=$(blkid -s UUID -o value "$SELECTED_DEVICE" 2>/dev/null || true)

PLAN_ARGS_MAIN=(${PLAN_ARGS[@]})
if [[ -n $USB_UUID ]]; then
  PLAN_ARGS_MAIN+=(--usb-uuid "$USB_UUID")
fi

"$CLI_BIN" "${PLAN_ARGS_MAIN[@]}" >"$PLAN_MAIN"

# Install and start the volatile key mount before enabling services to satisfy dependencies.
if [[ -f "$SYSTEMD_SOURCE/run-lockchain.mount" ]]; then
  install -Dm644 "$SYSTEMD_SOURCE/run-lockchain.mount" "$SYSTEMD_DEST/run-lockchain.mount"
  systemctl daemon-reload
  systemctl enable --now run-lockchain.mount
fi

run_plan_steps "$PLAN_MAIN" "$SELECTED_DEVICE" zfs-survey binary-placement binary-symlinks config-template delegate-permissions systemd-enable
record_status 'System configuration applied'

# Ensure release binaries are available on PATH for interactive use.
for bin in lockchain-cli lockchain-daemon lockchain-key-usb lockchain-ui; do
  if [[ -x "$TARGET_DIR/$bin" ]]; then
    install -Dm755 "$TARGET_DIR/$bin" "$BINARY_DEST/$bin"
  fi
done
record_status "Binaries installed to $BINARY_DEST"

CONFIG_VALID=1
if [[ -x "$CLI_BIN" ]]; then
  if ! validation_output=$("$CLI_BIN" validate -f "$CONFIG_PATH" 2>&1); then
    log 'Configuration validation failed; skipping key provisioning and initramfs integration.'
    printf '%s\n' "$validation_output" >&2
    record_status 'Configuration invalid; initramfs integration skipped'
    CONFIG_VALID=0
  fi
else
  log 'lockchain-cli not available for configuration validation.'
  CONFIG_VALID=0
fi

KEYGEN_RAN=0
if [[ ${SKIP_KEYGEN:-0} -eq 1 ]]; then
  log 'Skipping key provisioning and initramfs integration (SKIP_KEYGEN=1).'
  record_status 'Key provisioning skipped'
elif [[ $CONFIG_VALID -eq 0 ]]; then
  log 'Skipping key provisioning because configuration validation failed.'
  record_status 'Key provisioning skipped (config invalid)'
else
  log 'Provisioning key material and refreshing initramfs integration.'
  run_plan_steps "$PLAN_MAIN" "$SELECTED_DEVICE" key-generation
  record_status 'Key material provisioned and initramfs integration refreshed'
  KEYGEN_RAN=1
fi

if ((${#SUMMARY_LINES[@]} > 0)); then
  echo
  log 'Installer status:'
  for line in "${SUMMARY_LINES[@]}"; do
    printf '  - %s\n' "$line"
  done
fi

if [[ ${LOCKCHAIN_INSTALL_VERBOSE:-0} -eq 1 ]]; then
  print_plan_step "$PLAN_MAIN" "$SELECTED_DEVICE" key-generation
fi

echo
echo 'Environment summary:'
echo "  Dataset:        $SELECTED_DATASET (encroot $SELECTED_ENCROOT)"
echo "  Config path:    $CONFIG_PATH"
echo "  Service user:   $SERVICE_USER"
echo "  Binary dest:    $BINARY_DEST"
echo "  Systemd units:  $SYSTEMD_DEST"
echo "  USB device:     $SELECTED_DEVICE"
echo "  USB label:      $USB_LABEL"
echo "  USB UUID:       ${USB_UUID:-unknown}"

echo
echo 'Initramfs integration:'
if [[ -n "$INITRAMFS_TOOL" ]]; then
  echo "  Tool detected:  $INITRAMFS_TOOL"
else
  echo '  Tool detected:  none (dracut/update-initramfs missing)'
fi

if [[ -n "$INITRAMFS_TOOL" ]]; then
  initramfs_rollback_hint "$INITRAMFS_TOOL"
else
  log 'Install dracut or initramfs-tools, then run `lockchain-cli tuning` to install boot assets.'
fi

echo
echo 'Next steps:'
echo '  1. Launch `lockchain-ui` to complete the Control Deck walkthrough.'
if [[ $KEYGEN_RAN -eq 1 ]]; then
  echo '  2. Reboot and confirm the system unlocks with the USB token.'
  echo '  3. Re-run `lockchain-cli tuning` after kernel or policy changes.'
else
  echo "  2. Forge key material (CLI fallback): lockchain-cli init --dataset \"$SELECTED_DATASET\" --device $SELECTED_DEVICE"
  echo '  3. Validate with `lockchain-cli tuning` and `lockchain-cli repair`.'
fi
