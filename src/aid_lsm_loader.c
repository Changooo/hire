// src/aid_lsm_loader.c
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>

#define AID_MAP_PATH "/sys/fs/bpf/aid_inode_policies"

int main(void)
{
    struct bpf_object *obj = NULL;
    int err;
    char bpf_obj_path[PATH_MAX];
    char exe_path[PATH_MAX];

    // 실행 파일의 경로 가져오기
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        // readlink 실패 시 현재 디렉토리 기준 상대 경로 시도
        snprintf(bpf_obj_path, sizeof(bpf_obj_path), "bpf/aid_lsm.bpf.o");
    } else {
        exe_path[len] = '\0';
        char *dir = dirname(exe_path);
        // 실행 파일이 src/ 또는 루트에 있을 수 있음
        snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/../bpf/aid_lsm.bpf.o", dir);

        // 파일이 없으면 현재 디렉토리 기준으로 시도
        if (access(bpf_obj_path, F_OK) != 0) {
            snprintf(bpf_obj_path, sizeof(bpf_obj_path), "bpf/aid_lsm.bpf.o");
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "bpf_object__open_file(%s) 실패\n", bpf_obj_path);
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
