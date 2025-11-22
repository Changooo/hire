#!/bin/bash
# Fully unload AID LSM eBPF program and clean pinned resources

set -e

echo "[unload] === AID LSM full cleanup ==="

### 1. Remove pinned maps
echo "[unload] Removing pinned AID maps..."
sudo rm -f /sys/fs/bpf/aid_inode_policies 2>/dev/null || true
sudo rm -f /sys/fs/bpf/aid_network_policies 2>/dev/null || true
sudo rm -f /sys/fs/bpf/aid_* 2>/dev/null || true

### 2. Find bpf_link objects that belong to AID LSM
echo "[unload] Searching for BPF links..."
LINK_IDS=$(sudo bpftool link show 2>/dev/null \
              | grep -i "lsm" \
              | grep -i "aid" \
              | awk '{print $1}' | tr -d ':' || true)

if [ -z "$LINK_IDS" ]; then
    echo "[unload] No AID LSM links found."
else
    echo "[unload] Found links: $LINK_IDS"
    for link_id in $LINK_IDS; do
        echo "[unload] Detaching link ID: $link_id"
        sudo bpftool link detach id $link_id 2>/dev/null || \
        sudo bpftool link delete $link_id 2>/dev/null || true
    done
fi

### 3. Remove pinned BPF programs (if any)
echo "[unload] Removing pinned programs..."
PINNED_PROGS=$(sudo bpftool prog show 2>/dev/null \
                 | grep pinned \
                 | grep -i "aid" \
                 | awk -F'pinned ' '{print $2}')

for p in $PINNED_PROGS; do
    echo "[unload] Removing pinned program: $p"
    sudo rm -f "$p" || true
done

### 4. (Optional) force delete remaining program IDs containing “aid”
echo "[unload] Checking remaining AID programs..."
PROG_IDS=$(sudo bpftool prog show \
              | grep -i "aid" \
              | awk '{print $1}' | tr -d ':' || true)

if [ -z "$PROG_IDS" ]; then
    echo "[unload] No remaining AID programs."
else
    echo "[unload] Programs still visible: $PROG_IDS"
    echo "[unload] Trying force-delete..."
    for prog in $PROG_IDS; do
        sudo bpftool prog delete id $prog 2>/dev/null || true
    done
fi

echo "[unload] === Cleanup done. AID LSM is fully unloaded. ==="
