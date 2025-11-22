// src/dump_policies.c
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/aid_shared.h"

#define AID_MAP_PATH "/sys/fs/bpf/aid_inode_policies"

int main(void)
{
    int map_fd = bpf_obj_get(AID_MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map at %s: %s\n",
                AID_MAP_PATH, strerror(errno));
        return 1;
    }

    printf("Dumping policies from %s:\n", AID_MAP_PATH);
    printf("%-6s %-20s %-20s %-6s %-6s\n",
           "UID", "DEV", "INO", "READ", "WRITE");
    printf("---------------------------------------------------------------\n");

    struct inode_uid_key key = {0}, next_key;
    struct file_perm perm;
    int count = 0;

    // Iterate through all entries
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &perm) == 0) {
            printf("%-6u %-20llu %-20llu %-6d %-6d\n",
                   next_key.uid,
                   (unsigned long long)next_key.dev,
                   (unsigned long long)next_key.ino,
                   perm.allow_read,
                   perm.allow_write);
            count++;
        }
        key = next_key;
    }

    printf("---------------------------------------------------------------\n");
    printf("Total entries: %d\n", count);

    close(map_fd);
    return 0;
}
