// src/aid_lsm_loader.c
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BPF_OBJ_FILE "bpf/aid_lsm.bpf.o"
#define AID_MAP_PATH "/sys/fs/bpf/aid_inode_policies"

int main(void)
{
    struct bpf_object *obj = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
    if (!obj) {
        fprintf(stderr, "bpf_object__open_file(%s) 실패\n", BPF_OBJ_FILE);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "bpf_object__load 실패: %d\n", err);
        return 1;
    }

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


    printf("[aid_lsm_loader] aid LSM BPF 로드 완료.\n");
    // LSM BPF는 커널에 붙었으므로, 여기서 프로세스 종료해도 됨.
    return 0;
}
