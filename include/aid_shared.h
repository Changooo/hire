// include/aid_shared.h
#ifndef AID_SHARED_H
#define AID_SHARED_H

#define AID_UID_BASE 50000
#define AID_UID_MAX  60000

// inode + uid 키
struct inode_uid_key {
    uint64_t dev;   // st_dev
    uint64_t ino;   // st_ino
    uint32_t uid;   // agent uid (>= AID_UID_BASE)
};

// 해당 uid에 대해 이 inode에서 허용되는 권한
struct file_perm {
    uint8_t allow_read;
    uint8_t allow_write;
    uint8_t _pad[6];   // alignment 맞추기용 padding
};

#endif // AID_SHARED_H
