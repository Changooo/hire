// bpf/aid_lsm.bpf.c
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "../include/aid_shared.h"

#define MAY_EXEC  0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ  0x00000004

#define EACCES 13

// File type macros (from linux/stat.h)
#define S_IFMT   00170000
#define S_IFBLK  0060000
#define S_IFCHR  0020000
#define S_IFSOCK 0140000

#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define AF_INET 2


char LICENSE[] SEC("license") = "GPL";

// inode + uid -> file_perm
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_uid_key);
    __type(value, struct file_perm);
    __uint(max_entries, 16384);
} inode_policies SEC(".maps");

// uid + addr/port -> socket_perm (IPv4 only for now)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct socket_key_v4);
    __type(value, struct socket_perm);
    __uint(max_entries, 4096);
} socket_policies SEC(".maps");

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
    // Also allow sockets so that connect() is enforced in socket_connect hook
    if (S_ISCHR(mode) || S_ISBLK(mode) || S_ISSOCK(mode)) {
        bpf_printk("[AID] ALLOW special mode=0x%x\n", mode);
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

    // Try to get filename for debugging
    const char *filename = BPF_CORE_READ(dentry, d_name.name);
    char fname[64] = {0};
    if (filename) {
        bpf_probe_read_kernel_str(fname, sizeof(fname), filename);
    }

    bpf_printk("[AID] CHECK uid=%u dev=%llu ino=%llu mask=0x%x file=%s\n",
               uid, key.dev, key.ino, mask, fname);

    // Allow EXEC unconditionally (including exec+read combinations)
    // When executing a file, kernel may check MAY_EXEC | MAY_READ together
    if (mask & MAY_EXEC) {
        bpf_printk("[AID] ALLOW EXEC mask=0x%x\n", mask);
        return 0;
    }

    // Also allow pure READ on executable files (for dynamic linker, libraries, etc.)
    // This is a pragmatic approach: we only strictly control writes
    if (mask == MAY_READ) {

        int len = 0;
        #pragma unroll
        for (int i = 0; i < sizeof(fname); i++) {
            if (fname[i] == '\0')
                break;
            len++;
        }

        if (len >= 4) {
            if (!(fname[len - 4] == '.' &&
                fname[len - 3] == 't' &&
                fname[len - 2] == 'x' &&
                fname[len - 1] == 't')) {
                return 0;
            }
        }

        // If file has any execute bit, allow read
        if (mode & 0111) {
            bpf_printk("[AID] ALLOW executable file mode=0x%x\n", mode);
            return 0;
        }

        // // Allow READ from system library directories
        // // Get path from dentry chain
        // struct dentry *d = dentry;
        // char path[256] = {0};
        // int pos = 255;

        // // Walk up dentry tree to build path (backwards)
        // #pragma unroll
        // for (int i = 0; i < 20; i++) {
        //     if (!d) break;

        //     const char *name = BPF_CORE_READ(d, d_name.name);
        //     if (!name) break;

        //     // Read name into buffer
        //     char namebuf[64];
        //     bpf_probe_read_kernel_str(namebuf, sizeof(namebuf), name);

        //     bpf_printk("[AID] LOGLOG file=%s namebuf=%s\n", fname, namebuf);

        //     // Allow READ from other files than *.txt
        //     if (!(namebuf[0] == 'h' && namebuf[1] == 'o' && namebuf[2] == 'm' && namebuf[3] == 'e' && namebuf[4] == '\0')) {
        //         bpf_printk("[AID] ALLOW READ from system files\n");
        //         return 0;
        //     }
        //     // Check for system directories at any level
        //     // if (namebuf[0] == 'l' && namebuf[1] == 'i' && namebuf[2] == 'b' && namebuf[3] == '\0') {
        //     //     // Found "lib" directory
        //     //     bpf_printk("[AID] ALLOW READ from /lib or /usr/lib\n");
        //     //     return 0;
        //     // }
        //     // if (namebuf[0] == 'u' && namebuf[1] == 's' && namebuf[2] == 'r' && namebuf[3] == '\0') {
        //     //     // Found "usr" directory - likely /usr/lib
        //     //     struct dentry *parent = BPF_CORE_READ(d, d_parent);
        //     //     if (parent) {
        //     //         const char *pname = BPF_CORE_READ(parent, d_name.name);
        //     //         char pbuf[8];
        //     //         if (pname) {
        //     //             bpf_probe_read_kernel_str(pbuf, sizeof(pbuf), pname);
        //     //             // If parent is "lib", this is /usr/lib
        //     //             if (pbuf[0] == 'l' && pbuf[1] == 'i' && pbuf[2] == 'b' && pbuf[3] == '\0') {
        //     //                 bpf_printk("[AID] ALLOW READ from /usr/lib\n");
        //     //                 return 0;
        //     //             }
        //     //         }
        //     //     }
        //     // }

        //     // Move to parent
        //     d = BPF_CORE_READ(d, d_parent);
        //     if (d == BPF_CORE_READ(d, d_parent)) break; // reached root
        // }
    }

    // First, check if there's a policy for this specific inode
    perm = bpf_map_lookup_elem(&inode_policies, &key);
    if (!perm) {
        bpf_printk("[AID] DENY no policy file=%s dev=%llu ino=%llu\n", fname, key.dev, key.ino);
        return -EACCES;
    } else {
        bpf_printk("[AID] Found direct policy read=%d write=%d\n",
                   perm->allow_read, perm->allow_write);
    }

    // Check MAY_READ / MAY_WRITE bits in mask
    if ((mask & MAY_READ) && !perm->allow_read) {
        bpf_printk("[AID] DENY READ not allowed file=%s\n", fname);
        return -EACCES;
    }

    if ((mask & MAY_WRITE) && !perm->allow_write) {
        bpf_printk("[AID] DENY WRITE not allowed file=%s\n", fname);
        return -EACCES;
    }

    bpf_printk("[AID] ALLOW policy match\n");
    return 0;
}

// LSM: socket_connect - called before connect(2)
SEC("lsm/socket_connect")
int BPF_PROG(aid_enforce_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xffffffff;

    if (uid < AID_UID_BASE || uid >= AID_UID_MAX) {
        return 0; // Non-AID user
    }

    if (!address) {
        bpf_printk("[AID] SOCKET DENY uid=%u no address\n", uid);
        return -EACCES;
    }

    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    // Currently only guard IPv4; other families are allowed
    if (family != AF_INET) {
        bpf_printk("[AID] SOCKET ALLOW uid=%u family=%u (non-IPv4)\n", uid, family);
        return 0;
    }

    if (addrlen < sizeof(struct sockaddr_in)) {
        bpf_printk("[AID] SOCKET DENY uid=%u short addrlen=%d\n", uid, addrlen);
        return -EACCES;
    }

    struct sockaddr_in addr = {};
    if (bpf_probe_read_kernel(&addr, sizeof(addr), address) < 0) {
        bpf_printk("[AID] SOCKET DENY uid=%u read sockaddr failed\n", uid);
        return -EACCES;
    }

    __u16 port = bpf_ntohs(addr.sin_port);
    struct socket_key_v4 key = {
        .uid = uid,
        .family = family,
        .port = port,
        .addr = addr.sin_addr.s_addr, // network order
    };

    struct socket_perm *perm = bpf_map_lookup_elem(&socket_policies, &key);
    if (!perm || !perm->allow_connect) {
        bpf_printk("[AID] SOCKET DENY uid=%u addr=0x%x port=%u\n", uid, key.addr, key.port);
        return -EACCES;
    }

    bpf_printk("[AID] SOCKET ALLOW uid=%u addr=0x%x port=%u\n", uid, key.addr, key.port);
    return 0;
}
