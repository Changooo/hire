// include/aid_shared.h
#ifndef AID_SHARED_H
#define AID_SHARED_H

// For userspace code, include standard headers
// For BPF code, use kernel types from vmlinux.h
#ifndef __BPF__
#include <stdint.h>
#endif

#define AID_UID_BASE 50000
#define AID_UID_MAX  60000

// inode + uid key
struct inode_uid_key {
#ifdef __BPF__
    __u64 dev;   // st_dev
    __u64 ino;   // st_ino
    __u32 uid;   // agent uid (>= AID_UID_BASE)
#else
    uint64_t dev;   // st_dev
    uint64_t ino;   // st_ino
    uint32_t uid;   // agent uid (>= AID_UID_BASE)
#endif
};

// Permissions allowed for this uid on this inode
struct file_perm {
#ifdef __BPF__
    __u8 allow_read;
    __u8 allow_write;
    __u8 _pad[6];   // padding for alignment
#else
    uint8_t allow_read;
    uint8_t allow_write;
    uint8_t _pad[6];   // padding for alignment
#endif
};

#endif // AID_SHARED_H
