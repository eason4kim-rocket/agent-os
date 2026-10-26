/*
 * llandlock — minimal Landlock policy enforcer (AgentOS P1 enforcement compiler, C target)
 *
 * Usage: llandlock [--rw PATH]... [--rox PATH]... -- CMD [ARGS]...
 *   --rw PATH   allow read/write/make/remove beneath PATH (no execute)
 *   --rox PATH  allow read + execute beneath PATH
 *
 * Landlock ABI: targets v1 FS rights + REFER (v2) + TRUNCATE (v3), which every
 * kernel >= 6.2 provides. Network restriction is out of scope here: callers run
 * the process inside a network-less container/VM (defense in depth).
 * Stable syscalls: 444 create_ruleset, 445 add_rule, 446 restrict_self.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* linux/landlock.h ABI constants (stable; defined here to avoid header dependency) */
#define LL_CREATE_RULESET 444
#define LL_ADD_RULE       445
#define LL_RESTRICT_SELF  446
#define LL_RULE_PATH_BENEATH 1

#define LL_FS_EXECUTE    (1ULL <<  0)
#define LL_FS_WRITE_FILE (1ULL <<  1)
#define LL_FS_READ_FILE  (1ULL <<  2)
#define LL_FS_READ_DIR   (1ULL <<  3)
#define LL_FS_REMOVE_DIR (1ULL <<  4)
#define LL_FS_REMOVE_C   (1ULL <<  5)
#define LL_FS_MAKE_DIR   (1ULL <<  6)
#define LL_FS_MAKE_FIFO  (1ULL <<  7)
#define LL_FS_MAKE_SOCK  (1ULL <<  8)
#define LL_FS_MAKE_CHAR  (1ULL <<  9)
#define LL_FS_MAKE_BLK   (1ULL << 10)
#define LL_FS_MAKE_SYM   (1ULL << 11)
#define LL_FS_REFER      (1ULL << 13)
#define LL_FS_TRUNC      (1ULL << 14)

#define LL_HANDLED_ALL ( \
    LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE | LL_FS_READ_DIR | \
    LL_FS_REMOVE_DIR | LL_FS_REMOVE_C | LL_FS_MAKE_DIR | LL_FS_MAKE_FIFO | \
    LL_FS_MAKE_SOCK | LL_FS_MAKE_CHAR | LL_FS_MAKE_BLK | LL_FS_MAKE_SYM | \
    LL_FS_REFER | LL_FS_TRUNC)

#define LL_RW (LL_FS_WRITE_FILE | LL_FS_READ_FILE | LL_FS_READ_DIR | \
    LL_FS_REMOVE_DIR | LL_FS_REMOVE_C | LL_FS_MAKE_DIR | LL_FS_MAKE_FIFO | \
    LL_FS_MAKE_SOCK | LL_FS_MAKE_CHAR | LL_FS_MAKE_BLK | LL_FS_MAKE_SYM | \
    LL_FS_REFER | LL_FS_TRUNC)
#define LL_ROX (LL_FS_EXECUTE | LL_FS_READ_FILE | LL_FS_READ_DIR)

struct ll_ruleset_attr { unsigned long long handled_access_fs; };
struct ll_path_beneath { unsigned long long allowed_access; int parent_fd; unsigned int reserved; };

static int add_path(int ruleset_fd, const char *path, unsigned long long access) {
    struct ll_path_beneath rule;
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) { fprintf(stderr, "[llandlock] warn: skip missing path %s\n", path); return 0; }
        fprintf(stderr, "[llandlock] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    rule.allowed_access = access;
    rule.parent_fd = fd;
    rule.reserved = 0;
    if (syscall(LL_ADD_RULE, ruleset_fd, LL_RULE_PATH_BENEATH, &rule, 0) < 0) {
        fprintf(stderr, "[llandlock] add_rule %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    struct ll_ruleset_attr attr = { .handled_access_fs = LL_HANDLED_ALL };
    const char *rw_paths[64] = {0}, *rox_paths[64] = {0};
    int nrw = 0, nrox = 0, ruleset_fd, i, cmd_index = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rw") == 0 && i + 1 < argc && nrw < 64) rw_paths[nrw++] = argv[++i];
        else if (strcmp(argv[i], "--rox") == 0 && i + 1 < argc && nrox < 64) rox_paths[nrox++] = argv[++i];
        else if (strcmp(argv[i], "--") == 0) { cmd_index = i + 1; break; }
        else { fprintf(stderr, "usage: llandlock [--rw P]... [--rox P]... -- CMD...\n"); return 2; }
    }
    if (cmd_index == 0 || cmd_index >= argc) {
        fprintf(stderr, "usage: llandlock [--rw P]... [--rox P]... -- CMD...\n");
        return 2;
    }

    ruleset_fd = syscall(LL_CREATE_RULESET, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "[llandlock] kernel Landlock unavailable: %s\n", strerror(errno));
        return 126;
    }
    for (i = 0; i < nrw; i++)
        if (add_path(ruleset_fd, rw_paths[i], LL_RW) < 0) return 126;
    for (i = 0; i < nrox; i++)
        if (add_path(ruleset_fd, rox_paths[i], LL_ROX) < 0) return 126;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("[llandlock] prctl");
        return 126;
    }
    if (syscall(LL_RESTRICT_SELF, ruleset_fd, 0) < 0) {
        fprintf(stderr, "[llandlock] restrict_self: %s\n", strerror(errno));
        return 126;
    }
    execvp(argv[cmd_index], &argv[cmd_index]);
    fprintf(stderr, "[llandlock] exec %s: %s\n", argv[cmd_index], strerror(errno));
    return 127;
}
