// src/aid_lsm_loader.c
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>

#define AID_MAP_PATH "/sys/fs/bpf/aid_inode_policies"


static int libbpf_print_fn(enum libbpf_print_level lvl,
                           const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}



int main(void)
{
    struct bpf_object *obj = NULL;
    int err;
    char bpf_obj_path[PATH_MAX];
    char exe_path[PATH_MAX];

    // Get executable path
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        // If readlink fails, try relative path from current directory
        snprintf(bpf_obj_path, sizeof(bpf_obj_path), "bpf/aid_lsm.bpf.o");
    } else {
        exe_path[len] = '\0';
        char *dir = dirname(exe_path);
        // Executable may be in src/ or root directory
        snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/../bpf/aid_lsm.bpf.o", dir);

        // If file doesn't exist, try from current directory
        if (access(bpf_obj_path, F_OK) != 0) {
            snprintf(bpf_obj_path, sizeof(bpf_obj_path), "bpf/aid_lsm.bpf.o");
        }
    }

    // Check if map is already pinned
    if (access(AID_MAP_PATH, F_OK) == 0) {
        fprintf(stderr, "AID LSM already loaded (map exists at %s)\n", AID_MAP_PATH);
        fprintf(stderr, "To reload, first run: sudo rm %s\n", AID_MAP_PATH);
        return 1;
    }

    // libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "bpf_object__open_file(%s) failed\n", bpf_obj_path);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "bpf_object__load failed: %d\n", err);
        return 1;
    }

    // Attach LSM program
    struct bpf_program *prog;
    struct bpf_link *link;

    prog = bpf_object__find_program_by_name(obj, "aid_enforce_file_permission");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program 'aid_enforce_file_permission'\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach LSM program: %s\n", strerror(errno));
        return 1;
    }

    printf("[aid_lsm_loader] LSM program attached successfully\n");

    struct bpf_map *map;

    map = bpf_object__find_map_by_name(obj, "inode_policies");
    if (!map) {
        fprintf(stderr, "map 'inode_policies' not found\n");
        return 1;
    }

    err = bpf_map__pin(map, AID_MAP_PATH);
    if (err) {
        fprintf(stderr, "failed to pin map: %d\n", err);
        return 1;
    }

    // Pin the link to keep LSM attached
    err = bpf_link__pin(link, "/sys/fs/bpf/aid_lsm_link");
    if (err) {
        fprintf(stderr, "failed to pin link: %d\n", err);
        return 1;
    }

    printf("[aid_lsm_loader] AID LSM BPF loaded successfully.\n");
    // LSM BPF is attached to kernel, safe to exit process now.
    return 0;
}
