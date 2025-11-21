// include/aid_shared.h
#ifndef AID_SHARED_H
#define AID_SHARED_H

#include <stdint.h>

#define AID_UID_BASE 50000
#define AID_UID_MAX  60000

// inode + uid key
struct inode_uid_key {
    uint64_t dev;   // st_dev
    uint64_t ino;   // st_ino
    uint32_t uid;   // agent uid (>= AID_UID_BASE)
};

// Permissions allowed for this uid on this inode
struct file_perm {
    uint8_t allow_read;
    uint8_t allow_write;
    uint8_t _pad[6];   // padding for alignment
};

#endif // AID_SHARED_H
