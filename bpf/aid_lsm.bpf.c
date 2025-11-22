// bpf/aid_lsm.bpf.c
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// LSM: file_permission - called on every file access
SEC("lsm/file_open")
int BPF_PROG(aid_enforce_file_permission, struct file *file, int mask)
{
    // 그냥 무조건 허용
    return 0;
}
