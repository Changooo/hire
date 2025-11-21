// src/hire.c
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/aid_shared.h"

#define AGENT_USER_PREFIX "agent_"

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <agentname> <command> [args...]\n", prog);
    fprintf(stderr, "Execute command as agent user with AID enforcement\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s testagent ./bin/myprogram arg1 arg2\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
    }

    const char *agentname = argv[1];
    const char *command = argv[2];
    char **command_args = &argv[2];

    // Build full agent username
    char username[256];
    snprintf(username, sizeof(username), "%s%s", AGENT_USER_PREFIX, agentname);

    // Look up agent user
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "[hire] Error: Agent user '%s' does not exist.\n", username);
        fprintf(stderr, "[hire] Have you run 'addagent' for this agent?\n");
        return 1;
    }

    // Verify UID is in AID range
    if (pw->pw_uid < AID_UID_BASE || pw->pw_uid >= AID_UID_MAX) {
        fprintf(stderr, "[hire] Error: User '%s' (uid=%d) is not in AID range (%d-%d).\n",
                username, pw->pw_uid, AID_UID_BASE, AID_UID_MAX);
        return 1;
    }

    printf("[hire] Executing as agent '%s' (uid=%d): %s\n",
           agentname, pw->pw_uid, command);

    // Check if we're running as root
    if (geteuid() != 0) {
        fprintf(stderr, "[hire] Error: Must run as root to switch UID.\n");
        return 1;
    }

    // Switch to agent user
    if (setgid(pw->pw_gid) != 0) {
        fprintf(stderr, "[hire] Error: Failed to set gid=%d: %s\n",
                pw->pw_gid, strerror(errno));
        return 1;
    }

    if (setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "[hire] Error: Failed to set uid=%d: %s\n",
                pw->pw_uid, strerror(errno));
        return 1;
    }

    // Execute the command
    execvp(command, command_args);

    // If execvp returns, it failed
    fprintf(stderr, "[hire] Error: Failed to execute '%s': %s\n",
            command, strerror(errno));
    return 1;
}
