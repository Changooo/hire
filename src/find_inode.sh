#!/bin/bash
# Find file path from device and inode numbers

if [ $# -ne 2 ]; then
    echo "Usage: $0 <dev_number> <inode_number>"
    echo "Example: $0 64512 1194207"
    exit 1
fi

DEV=$1
INO=$2

# Convert dev number to major/minor
MAJOR=$((DEV >> 8))
MINOR=$((DEV & 0xFF))

echo "Looking for: dev=$DEV (major=$MAJOR, minor=$MINOR) inode=$INO"
echo ""

# Find the device
DEVICE=$(lsblk -n -o NAME,MAJ:MIN | awk -v maj=$MAJOR -v min=$MINOR '$2 == maj":"min {print "/dev/"$1}')

if [ -z "$DEVICE" ]; then
    echo "Device not found for major=$MAJOR, minor=$MINOR"
    echo "Trying to search all mounted filesystems..."
    DEVICE=""
else
    echo "Device: $DEVICE"
fi

# Search for the inode
echo "Searching for inode $INO..."
if [ -n "$DEVICE" ]; then
    # Get mount point
    MOUNT=$(mount | grep "$DEVICE" | awk '{print $3}' | head -1)
    if [ -n "$MOUNT" ]; then
        echo "Mount point: $MOUNT"
        sudo find "$MOUNT" -inum "$INO" 2>/dev/null
    fi
else
    # Search all filesystems
    sudo find / -inum "$INO" 2>/dev/null | head -5
fi
