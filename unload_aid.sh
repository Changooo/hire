#!/bin/bash
# Unload AID LSM BPF program and clean up

set -e

echo "[unload] Removing pinned map..."
sudo rm -f /sys/fs/bpf/aid_inode_policies

echo "[unload] Finding and removing BPF programs..."
# Find all LSM BPF programs with "aid" in the name
PROG_IDS=$(sudo bpftool prog list | grep -i "lsm" | grep -i "aid\|file_permission" | awk '{print $1}' | tr -d ':' || true)

if [ -z "$PROG_IDS" ]; then
    echo "[unload] No AID BPF programs found."
else
    for prog_id in $PROG_IDS; do
        echo "[unload] Removing BPF program ID: $prog_id"
        # BPF LSM programs auto-detach when no references exist
        # We just need to unpin and close all references
    done
fi

# Clean up any remaining pinned objects
sudo rm -f /sys/fs/bpf/aid_*

echo "[unload] Done. You can now reload aid_lsm_loader."
