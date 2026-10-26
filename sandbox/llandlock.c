/*
 * llandlock — minimal Landlock policy enforcer (AgentOS P1 enforcement compiler, C target)
 *
 * Usage: llandlock [--rw PATH]... [--rox PATH]... -- CMD [ARGS]...
 *   --rw PATH   allow read/write/make/remove/truncate beneath PATH (no execute)
 *   --rox PATH  allow read + execute beneath PATH
 *
 * Uses the official UAPI header (linux-libc-dev). Handled access rights cover
 * ABI v3 (filesystem incl. REFER/TRUNCATE/MAKE_SYM). Network restriction and
 * IOCTL_DEV (ABI v4/v5) are out of scope here: the caller runs the process in a
 * network-less container (defense in depth); IOCTL_DEV gap is documented.
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
#include <linux/landlock.h>

#define LL_CREATE_RULESET 444
#define LL_ADD_RULE       445
#define LL_RESTRICT_SELF  446
#define LL_RULE_PATH_BENEATH 1

#define LL_HANDLED_ALL ( \
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
    LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | \
    LANDLOCK_ACCESS_FS_TRUNCATE)

/* ABI v4（内核 6.7+）网络位：deny-all 语义 = handled 置位且不加任何 net 规则 */
#define LL_NET_BIND_TCP    (1ULL << 0)
#define LL_NET_CONNECT_TCP (1ULL << 1)
#define LL_NET_ALL (LL_NET_BIND_TCP | LL_NET_CONNECT_TCP)
#define LL_CREATE_RULESET_VERSION (1U << 0)

#define LL_RW (LL_HANDLED_ALL & ~LANDLOCK_ACCESS_FS_EXECUTE)
#define LL_ROX (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | \
                LANDLOCK_ACCESS_FS_READ_DIR)

_Static_assert(sizeof(struct landlock_path_beneath_attr) == 12,
               "landlock_path_beneath_attr must be 12 bytes as per UAPI");

static int add_path(int ruleset_fd, const char *path, __u64 access) {
    struct landlock_path_beneath_attr rule;
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) { fprintf(stderr, "[llandlock] warn: skip missing path %s\n", path); return 0; }
        fprintf(stderr, "[llandlock] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    rule.allowed_access = access;
    rule.parent_fd = fd;
    if (syscall(LL_ADD_RULE, ruleset_fd, LL_RULE_PATH_BENEATH, &rule, 0) < 0) {
        fprintf(stderr, "[llandlock] add_rule %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    struct landlock_ruleset_attr attr = { .handled_access_fs = LL_HANDLED_ALL };
    const char *rw_paths[64] = {0}, *rox_paths[64] = {0};
    int nrw = 0, nrox = 0, ruleset_fd, i, cmd_index = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rw") == 0 && i + 1 < argc) {
            if (nrw >= 64) { fprintf(stderr, "[llandlock] too many --rw paths\n"); return 2; }
            rw_paths[nrw++] = argv[++i];
        } else if (strcmp(argv[i], "--rox") == 0 && i + 1 < argc) {
            if (nrox >= 64) { fprintf(stderr, "[llandlock] too many --rox paths\n"); return 2; }
            rox_paths[nrox++] = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) { cmd_index = i + 1; break; }
        else { fprintf(stderr, "usage: llandlock [--rw P]... [--rox P]... -- CMD...\n"); return 2; }
    }
    if (cmd_index == 0 || cmd_index >= argc) {
        fprintf(stderr, "usage: llandlock [--rw P]... [--rox P]... -- CMD...\n");
        return 2;
    }

    /* M1 修复：ABI >= 4 时把 TCP bind/connect 纳入 handled（无 net 规则 = 全拒）。
       ABI < 4 无法经 Landlock 强制网络 → 打印诚实告警（调用方容器层 --network none 兜底）。 */
    int net_enforced = 0;
    long abi = syscall(LL_CREATE_RULESET, NULL, 0, LL_CREATE_RULESET_VERSION);
    if (abi >= 4) {
        attr.handled_access_net = LL_NET_ALL;
        net_enforced = 1;
    } else if (abi >= 0) {
        fprintf(stderr, "[llandlock] warn: kernel Landlock ABI %ld < 4，网络不受内核强制\n", abi);
    }

    size_t attr_size = net_enforced ? sizeof(attr) : sizeof(attr.handled_access_fs);
    ruleset_fd = syscall(LL_CREATE_RULESET, &attr, attr_size, 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "[llandlock] kernel Landlock unavailable: %s\n", strerror(errno));
        return 126;
    }
    for (i = 0; i < nrw; i++)
        if (add_path(ruleset_fd, rw_paths[i], LL_RW) < 0) { close(ruleset_fd); return 126; }
    for (i = 0; i < nrox; i++)
        if (add_path(ruleset_fd, rox_paths[i], LL_ROX) < 0) { close(ruleset_fd); return 126; }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("[llandlock] prctl");
        close(ruleset_fd);
        return 126;
    }
    if (syscall(LL_RESTRICT_SELF, ruleset_fd, 0) < 0) {
        fprintf(stderr, "[llandlock] restrict_self: %s\n", strerror(errno));
        close(ruleset_fd);
        return 126;
    }
    close(ruleset_fd);
    execvp(argv[cmd_index], &argv[cmd_index]);
    fprintf(stderr, "[llandlock] exec %s: %s\n", argv[cmd_index], strerror(errno));
    return 127;
}
