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


char LICENSE[] SEC("license") = "GPL";

// inode + uid -> file_perm
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_uid_key);
    __type(value, struct file_perm);
    __uint(max_entries, 16384);
} inode_policies SEC(".maps");

// LSM: file_open
SEC("lsm/file_open")
int BPF_PROG(aid_enforce_file_open, struct file *file, int mask)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xffffffff;

    // 일반 uid는 무시
    if (uid < AID_UID_BASE || uid >= AID_UID_MAX)
        return 0;

    struct dentry *dentry;
    struct inode *inode;
    struct inode_uid_key key = {};
    struct file_perm *perm;

    // file -> dentry -> inode
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.uid = uid;

    perm = bpf_map_lookup_elem(&inode_policies, &key);
    if (!perm) {
        // 정책 없으면 허용 (fail-open). 필요시 여기서 deny로 바꿔도 됨.
        return 0;
    }

    // mask에 MAY_READ / MAY_WRITE 비트 설정 여부 확인
    if ((mask & MAY_READ) && !perm->allow_read) {
        bpf_printk("AID uid=%u denied READ dev=%llu ino=%llu\n",
                   uid, key.dev, key.ino);
        return -EACCES;
    }

    if ((mask & MAY_WRITE) && !perm->allow_write) {
        bpf_printk("AID uid=%u denied WRITE dev=%llu ino=%llu\n",
                   uid, key.dev, key.ino);
        return -EACCES;
    }

    return 0;
}
