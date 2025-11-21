// src/addagent.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/bpf.h>
#include <pwd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/aid_shared.h"

#define AID_MAP_PATH "/sys/fs/bpf/aid_inode_policies"
#define AGENT_USER_PREFIX "agent_"

// --- String utilities ---

static char *trim(char *s)
{
    char *end;
    while (*s && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r'))
        s++;
    if (*s == 0)
        return s;
    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        *end-- = 0;
    return s;
}

static int starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

// --- File permission rule structure ---

#define MAX_FILE_RULES 256
#define MAX_PATH_LEN   4096

struct file_rule {
    char path[MAX_PATH_LEN];
    int read;
    int write;
};

struct manifest_data {
    char agentname[128];
    struct file_rule files[MAX_FILE_RULES];
    int file_count;
};

// --- Simple manifest.yaml parser ---
// Supported format (whitespace/indentation must be roughly correct):
//
// agentname: foo
// permissions:
//   files:
//     - path: /path/pattern
//       read: true
//       write: false
//
// network/devices are ignored for now (can be extended later)

static int parse_manifest(const char *filename, struct manifest_data *out)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Failed to open manifest '%s': %s\n", filename, strerror(errno));
        return -1;
    }

    memset(out, 0, sizeof(*out));
    char line[8192];
    int in_permissions = 0;
    int in_files = 0;
    int current_rule_index = -1;

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == 0 || *p == '#')
            continue;

        if (starts_with(p, "agentname:")) {
            p += strlen("agentname:");
            p = trim(p);
            strncpy(out->agentname, p, sizeof(out->agentname) - 1);
            continue;
        }

        if (starts_with(p, "permissions:")) {
            in_permissions = 1;
            continue;
        }

        if (!in_permissions)
            continue;

        if (starts_with(p, "files:")) {
            in_files = 1;
            continue;
        }

        if (in_files && starts_with(p, "-")) {
            // Start new file rule
            if (out->file_count >= MAX_FILE_RULES) {
                fprintf(stderr, "Too many file rules (>%d)\n", MAX_FILE_RULES);
                fclose(f);
                return -1;
            }
            current_rule_index = out->file_count++;
            memset(&out->files[current_rule_index], 0, sizeof(struct file_rule));
            out->files[current_rule_index].read = 0;
            out->files[current_rule_index].write = 0;
            // May be in "- path: ..." format
            p++; // skip '-'
            p = trim(p);
            if (starts_with(p, "path:")) {
                p += strlen("path:");
                p = trim(p);
                strncpy(out->files[current_rule_index].path, p,
                        sizeof(out->files[current_rule_index].path) - 1);
            }
            continue;
        }

        // Set path/read/write inside file rule
        if (in_files && current_rule_index >= 0) {
            if (starts_with(p, "path:")) {
                p += strlen("path:");
                p = trim(p);
                strncpy(out->files[current_rule_index].path, p,
                        sizeof(out->files[current_rule_index].path) - 1);
            } else if (starts_with(p, "read:")) {
                p += strlen("read:");
                p = trim(p);
                out->files[current_rule_index].read =
                    (strcmp(p, "true") == 0 || strcmp(p, "True") == 0 || strcmp(p, "1") == 0);
            } else if (starts_with(p, "write:")) {
                p += strlen("write:");
                p = trim(p);
                out->files[current_rule_index].write =
                    (strcmp(p, "true") == 0 || strcmp(p, "True") == 0 || strcmp(p, "1") == 0);
            }
        }
    }

    fclose(f);

    if (out->agentname[0] == 0) {
        fprintf(stderr, "No agentname in manifest.\n");
        return -1;
    }
    return 0;
}

// --- AID uid allocation/lookup utilities ---

static uid_t find_free_aid_uid(void)
{
    struct passwd *pw;
    uid_t used[AID_UID_MAX - AID_UID_BASE];
    int used_count = 0;

    memset(used, 0, sizeof(used));

    setpwent();
    while ((pw = getpwent()) != NULL) {
        if (pw->pw_uid >= AID_UID_BASE && pw->pw_uid < AID_UID_MAX) {
            if (used_count < (int)(sizeof(used) / sizeof(used[0])))
                used[used_count++] = pw->pw_uid;
        }
    }
    endpwent();

    for (uid_t u = AID_UID_BASE; u < AID_UID_MAX; u++) {
        int found = 0;
        for (int i = 0; i < used_count; i++) {
            if (used[i] == u) {
                found = 1;
                break;
            }
        }
        if (!found)
            return u;
    }
    return (uid_t)-1;
}

static uid_t ensure_agent_user(const char *agentname)
{
    char username[256];
    snprintf(username, sizeof(username), "%s%s", AGENT_USER_PREFIX, agentname);

    struct passwd *pw = getpwnam(username);
    if (pw) {
        if (pw->pw_uid < AID_UID_BASE || pw->pw_uid >= AID_UID_MAX) {
            fprintf(stderr,
                    "Existing user %s uid=%d is not in AID range (%d~%d).\n",
                    username, pw->pw_uid, AID_UID_BASE, AID_UID_MAX);
            return (uid_t)-1;
        }
        printf("[addagent] Using existing agent user '%s' uid=%d\n", username, pw->pw_uid);
        return pw->pw_uid;
    }

    uid_t uid = find_free_aid_uid();
    if ((int)uid < 0) {
        fprintf(stderr, "No available uid in AID range (%d~%d).\n",
                AID_UID_BASE, AID_UID_MAX);
        return (uid_t)-1;
    }

    // Create system account (useradd call)
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "useradd -r -M -s /usr/sbin/nologin -u %u %s",
             uid, username);
    printf("[addagent] Executing useradd: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "useradd failed, return value=%d\n", ret);
        return (uid_t)-1;
    }

    printf("[addagent] Created agent user '%s' uid=%u\n", username, uid);
    return uid;
}

// --- eBPF map update ---

static int open_inode_policy_map(void)
{
    int fd = bpf_obj_get(AID_MAP_PATH);
    if (fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s) failed: %s\n",
                AID_MAP_PATH, strerror(errno));
    }
    return fd;
}

static int register_file_policy_for_inode(int map_fd,
                                          uid_t uid,
                                          dev_t dev,
                                          ino_t ino,
                                          int allow_read,
                                          int allow_write)
{
    struct inode_uid_key key = {
        .dev = (uint64_t)dev,
        .ino = (uint64_t)ino,
        .uid = (uint32_t)uid,
    };

    struct file_perm perm = {
        .allow_read = (uint8_t)(allow_read ? 1 : 0),
        .allow_write = (uint8_t)(allow_write ? 1 : 0),
    };

    int ret = bpf_map_update_elem(map_fd, &key, &perm, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr,
                "bpf_map_update_elem failed: uid=%u dev=%llu ino=%llu errno=%s\n",
                uid, (unsigned long long)key.dev, (unsigned long long)key.ino,
                strerror(errno));
        return -1;
    }

    printf("[addagent] Registered uid=%u dev=%llu ino=%llu read=%d write=%d\n",
           uid, (unsigned long long)key.dev, (unsigned long long)key.ino,
           allow_read, allow_write);
    return 0;
}

// Register parent directory policy to allow file creation/access
static int register_directory_policy(int map_fd,
                                      uid_t uid,
                                      const char *dir_path,
                                      int allow_read,
                                      int allow_write)
{
    struct stat st;
    if (stat(dir_path, &st) < 0) {
        fprintf(stderr, "[addagent] Warning: stat(%s) failed: %s\n", dir_path, strerror(errno));
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        return 0;  // Not a directory
    }

    printf("[addagent] Registering directory policy: %s\n", dir_path);
    return register_file_policy_for_inode(map_fd, uid, st.st_dev, st.st_ino,
                                          allow_read, allow_write);
}

// Register path (or glob pattern) → stat() → inode
static int register_file_policy_for_path(int map_fd,
                                         uid_t uid,
                                         const char *path_pattern,
                                         int allow_read,
                                         int allow_write)
{
    glob_t g;
    memset(&g, 0, sizeof(g));

    int flags = 0;
    int ret = glob(path_pattern, flags, NULL, &g);
    if (ret == GLOB_NOMATCH) {
        fprintf(stderr, "[addagent] Warning: No files matching '%s'.\n", path_pattern);

        // Extract parent directory and register it
        char *path_copy = strdup(path_pattern);
        if (path_copy) {
            char *dir = dirname(path_copy);
            if (dir && strcmp(dir, ".") != 0 && strcmp(dir, "/") != 0) {
                printf("[addagent] Attempting to register parent directory: %s\n", dir);
                register_directory_policy(map_fd, uid, dir, allow_read, allow_write);
            }
            free(path_copy);
        }

        globfree(&g);
        return 0;  // Changed from -1 to 0 to continue processing
    } else if (ret != 0) {
        fprintf(stderr, "[addagent] glob('%s') failed: ret=%d\n", path_pattern, ret);
        globfree(&g);
        return -1;
    }

    for (size_t i = 0; i < g.gl_pathc; i++) {
        const char *path = g.gl_pathv[i];
        struct stat st;
        if (stat(path, &st) < 0) {
            fprintf(stderr, "[addagent] stat(%s) failed: %s\n", path, strerror(errno));
            continue;
        }
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            // Only target files/directories (can extend to devices if needed)
            continue;
        }
        register_file_policy_for_inode(map_fd, uid, st.st_dev, st.st_ino,
                                       allow_read, allow_write);

        // Also register parent directory
        char *path_copy = strdup(path);
        if (path_copy) {
            char *dir = dirname(path_copy);
            if (dir && strcmp(dir, ".") != 0) {
                register_directory_policy(map_fd, uid, dir, allow_read, allow_write);
            }
            free(path_copy);
        }
    }

    globfree(&g);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <manifest.yaml>\n", argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "addagent must be run as root.\n");
        return 1;
    }

    const char *manifest_path = argv[1];
    struct manifest_data m;
    if (parse_manifest(manifest_path, &m) < 0) {
        return 1;
    }

    printf("[addagent] manifest agentname='%s', file rules=%d\n",
           m.agentname, m.file_count);

    uid_t uid = ensure_agent_user(m.agentname);
    if ((int)uid < 0)
        return 1;

    int map_fd = open_inode_policy_map();
    if (map_fd < 0)
        return 1;

    for (int i = 0; i < m.file_count; i++) {
        struct file_rule *r = &m.files[i];
        if (r->path[0] == 0) {
            fprintf(stderr, "[addagent] rule %d: path is empty. Ignoring.\n", i);
            continue;
        }
        printf("[addagent] rule %d: path='%s' read=%d write=%d\n",
               i, r->path, r->read, r->write);
        register_file_policy_for_path(map_fd, uid, r->path, r->read, r->write);
    }

    close(map_fd);
    printf("[addagent] Done.\n");
    return 0;
}
