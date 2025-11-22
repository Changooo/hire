// bpf/aid_lsm.bpf.c
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/aid_shared.h"

#define MAY_EXEC  0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ  0x00000004

#define EACCES 13

// File type macros (from linux/stat.h)
#define S_IFMT   00170000
#define S_IFBLK  0060000
#define S_IFCHR  0020000

#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)


char LICENSE[] SEC("license") = "GPL";

// inode + uid -> file_perm
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_uid_key);
    __type(value, struct file_perm);
    __uint(max_entries, 16384);
} inode_policies SEC(".maps");

// LSM: file_permission - called on every file access
SEC("lsm/file_permission")
int BPF_PROG(aid_enforce_file_permission, struct file *file, int mask)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xffffffff;

    // Ignore non-AID users
    if (uid < AID_UID_BASE || uid >= AID_UID_MAX) {
        return 0;
    }

    struct dentry *dentry;
    struct inode *inode;
    struct inode_uid_key key = {};
    struct file_perm *perm;

    // file -> dentry -> inode
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        bpf_printk("[AID] ALLOW no dentry\n");
        return 0;
    }

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        bpf_printk("[AID] ALLOW no inode\n");
        return 0;
    }

    // Allow access to character/block devices (stdin/stdout/stderr, /dev/null, etc.)
    umode_t mode = BPF_CORE_READ(inode, i_mode);
    if (S_ISCHR(mode) || S_ISBLK(mode)) {
        bpf_printk("[AID] ALLOW device mode=0x%x\n", mode);
        return 0;
    }

    // Convert kernel dev to stat-compatible format
    // Kernel uses new_encode_dev: (major << 20) | minor
    // stat uses old format: (major << 8) | minor
    __u64 kdev = BPF_CORE_READ(inode, i_sb, s_dev);
    __u32 major = kdev >> 20;
    __u32 minor = kdev & 0xfffff;

    key.dev = (major << 8) | (minor & 0xff);  // Old stat format
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.uid = uid;

    bpf_printk("[AID] CHECK uid=%u dev=%llu ino=%llu mask=0x%x\n",
               uid, key.dev, key.ino, mask);

    // Allow EXEC unconditionally (including exec+read combinations)
    // When executing a file, kernel may check MAY_EXEC | MAY_READ together
    if (mask & MAY_EXEC) {
        bpf_printk("[AID] ALLOW EXEC mask=0x%x\n", mask);
        return 0;
    }

    // Also allow pure READ on executable files (for dynamic linker, libraries, etc.)
    // This is a pragmatic approach: we only strictly control writes
    if (mask == MAY_READ) {
        // If file has any execute bit, allow read
        if (mode & 0111) {
            bpf_printk("[AID] ALLOW executable file mode=0x%x\n", mode);
            return 0;
        }
    }

    // First, check if there's a policy for this specific inode
    perm = bpf_map_lookup_elem(&inode_policies, &key);
    if (!perm) {
        // bpf_printk("[AID] No direct policy, checking parent\n");
        // // No direct policy - check parent directory
        // struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        // if (parent && parent != dentry) {
        //     struct inode *parent_inode = BPF_CORE_READ(parent, d_inode);
        //     if (parent_inode) {
        //         __u64 parent_kdev = BPF_CORE_READ(parent_inode, i_sb, s_dev);
        //         __u32 parent_major = parent_kdev >> 20;
        //         __u32 parent_minor = parent_kdev & 0xfffff;
        //         key.dev = (parent_major << 8) | (parent_minor & 0xff);
        //         key.ino = BPF_CORE_READ(parent_inode, i_ino);
        //         bpf_printk("[AID] Parent check dev=%llu ino=%llu\n", key.dev, key.ino);
        //         perm = bpf_map_lookup_elem(&inode_policies, &key);
        //     }
        // }

        // Still no policy found - deny READ/WRITE (fail-close / whitelist mode)
        if (!perm) {
            bpf_printk("[AID] DENY no policy dev=%llu ino=%llu\n", key.dev, key.ino);
            return -EACCES;
        }
    } else {
        bpf_printk("[AID] Found direct policy read=%d write=%d\n",
                   perm->allow_read, perm->allow_write);
    }

    // Check MAY_READ / MAY_WRITE bits in mask
    if ((mask & MAY_READ) && !perm->allow_read) {
        bpf_printk("[AID] DENY READ not allowed\n");
        return -EACCES;
    }

    if ((mask & MAY_WRITE) && !perm->allow_write) {
        bpf_printk("[AID] DENY WRITE not allowed\n");
        return -EACCES;
    }

    bpf_printk("[AID] ALLOW policy match\n");
    return 0;
}
