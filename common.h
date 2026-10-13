/*
 * common.h — shared between supervisor.c and namelist.c.
 *
 * Keeping install_filter() identical in both means the bake-off
 * (supervisor vs namelist) isolates ONE variable: whether the
 * decision is stateful. Both get the same architecture check, so
 * neither is more or less vulnerable to an ABI-confusion bypass
 * than the other — see "ARCH CHECK" below for why that matters.
 */
#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE

#include <asm/unistd.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

static inline void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static inline const char *sysname(int nr)
{
    switch (nr) {
    case __NR_socket:  return "socket";
    case __NR_bind:    return "bind";
    case __NR_listen:  return "listen";
    case __NR_accept:  return "accept";
    case __NR_accept4: return "accept4";
    case __NR_connect:   return "connect";
    case __NR_execve:    return "execve";
    case __NR_execveat:  return "execveat";
    case __NR_sendto:    return "sendto";
    case __NR_sendmsg:   return "sendmsg";
    default:             return "other";
    }
}

/*
 * Fd handoff: parent/child.
 *
 * An EARLIER version of this handoff used sendmsg()+SCM_RIGHTS over
 * a unix socketpair. That meant __NR_sendmsg could never be trapped
 * at all: trapping it would suspend the child's OWN handoff call
 * awaiting a USER_NOTIF reply the supervisor cannot send until it
 * already HAS the listener fd — a real deadlock, reproduced while
 * building this project (see git history / REPORT.md). sendmsg()
 * was excluded from the trap list as a documented gap because of it.
 *
 * This version instead uses pidfd_getfd(): the child just tells the
 * PARENT, over a plain pipe (not a syscall we ever trap), which fd
 * number the listener ended up as; the parent then pulls a working
 * duplicate of that fd directly out of the child's fd table via
 * pidfd_open()+pidfd_getfd(). The child's handoff no longer uses
 * sendmsg() — or any trapped syscall — at all, so sendmsg() can now
 * be trapped and enforced like everything else (supervisor.c adds a
 * real, argument-aware check for it, the same kind sendto() needed).
 *
 * pidfd_open() needs Linux 5.3+, pidfd_getfd() needs Linux 5.6+ —
 * both are old enough now that "a modern kernel" is deemed an
 * acceptable requirement, and pidfd_getfd() additionally requires
 * being able to ptrace the target, which a same-UID parent of its
 * own child always can.
 */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

/* Child side: tell the parent which fd the listener ended up as,
 * then WAIT for the parent's ack that it has pulled its own
 * independent reference via pidfd_getfd() before closing our copy.
 * Without this second leg there is a real race: if the child closes
 * its only reference before the parent has duplicated it, the
 * kernel's notifier object can be torn down (no references left),
 * which then breaks the child's OWN next trapped syscall (its
 * execv() call) with no listener left to notify — reproduced while
 * building this handoff; the fix is this explicit two-way sync, not
 * just "signal and immediately close". */
static inline void child_signal_listener_fd(int to_parent_fd, int from_parent_fd,
                                             int listener_fd)
{
    char ack;

    if (write(to_parent_fd, &listener_fd, sizeof(listener_fd)) != sizeof(listener_fd))
        die("write (listener fd handoff)");
    close(to_parent_fd);

    if (read(from_parent_fd, &ack, 1) != 1)
        die("read (listener fd handoff ack)");
    close(from_parent_fd);
}

/* Parent side: receive that fd number, pull a real duplicate of it
 * directly out of the child's fd table — no sendmsg() involved —
 * then ack so the child knows it's safe to close its own copy. */
static inline int parent_receive_listener_fd(pid_t child_pid, int from_child_fd,
                                              int to_child_fd)
{
    int fd_in_child = -1;
    long pidfd, listener;
    char ack = 1;

    if (read(from_child_fd, &fd_in_child, sizeof(fd_in_child)) != sizeof(fd_in_child))
        die("read (listener fd handoff)");
    close(from_child_fd);

    pidfd = syscall(__NR_pidfd_open, child_pid, 0);
    if (pidfd < 0)
        die("pidfd_open (needs Linux 5.3+)");

    listener = syscall(__NR_pidfd_getfd, (int)pidfd, fd_in_child, 0);
    close((int)pidfd);
    if (listener < 0)
        die("pidfd_getfd (needs Linux 5.6+)");

    if (write(to_child_fd, &ack, 1) != 1)
        die("write (listener fd handoff ack)");
    close(to_child_fd);

    return (int)listener;
}

/*
 * Install the seccomp filter and return the notification-listener fd.
 *
 * ARCH CHECK (fix): the original filter read seccomp_data.nr and
 * compared it straight against the native __NR_* constants. On an
 * x86-64 kernel a 32-bit process (or a 64-bit process issuing a
 * syscall through the legacy `int $0x80` / ia32 entry point) uses a
 * DIFFERENT number for the same call — ia32 connect() is a
 * socketcall() with its own numbering, not __NR_connect. Those
 * numbers were simply never on our list, so the old filter's
 * default BPF_RET SECCOMP_RET_ALLOW let them straight through —
 * confirmed: an ia32 connect() after listen() reached the kernel
 * un-intercepted.
 *
 * The fix is the first two instructions below: load
 * seccomp_data.arch and kill the process outright unless it is
 * AUDIT_ARCH_X86_64. That removes the ABI-confusion bypass
 * entirely, rather than trying to enumerate every alternate syscall
 * number.
 */
static inline int install_filter(void)
{
    struct sock_filter filter[] = {
        /* --- arch check: only the native 64-bit ABI is allowed --- */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* --- syscall number --- */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    int listener;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("PR_SET_NO_NEW_PRIVS");

    listener = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0)
        die("seccomp NEW_LISTENER");
    return listener;
}

#endif /* COMMON_H */
