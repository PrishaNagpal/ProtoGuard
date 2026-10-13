/*
 * namelist.c — the baseline: a name-based seccomp allowlist.
 *
 * Same trapped syscalls as supervisor.c (via common.h — including
 * the same architecture check, so the bake-off isolates ONE
 * variable: statefulness, not an unrelated ABI bypass; now also
 * including sendmsg, trappable since the fd handoff below no longer
 * uses sendmsg() itself — see common.h). Every trapped name is
 * always allowed. There is no PCB, no phase. connect() after
 * listen() is still CONTINUE here — this is what a typical seccomp
 * allowlist does: "is the NAME ok?", never "is it ok RIGHT NOW?".
 *
 * Run:  ./namelist ./attack
 */

#define _GNU_SOURCE

#include "common.h"

#include <poll.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    const char *child_path = "./attack";
    int c2p[2], p2c[2]; /* child->parent: fd number; parent->child: ack */
    pid_t pid;
    int listener;
    int status;
    int child_done = 0;

    if (argc >= 2)
        child_path = argv[1];

    if (pipe(c2p) < 0 || pipe(p2c) < 0)
        die("pipe");

    printf("namelist: allowlist = socket,bind,listen,accept,accept4,connect,\n");
    printf("namelist:             execve,execveat,sendto,sendmsg\n");
    printf("namelist: starting %s (names only — no phase / no protocol)\n",
           child_path);
    fflush(stdout);

    pid = fork();
    if (pid < 0)
        die("fork");

    if (pid == 0) {
        int listener_fd;
        char *child_argv[] = { (char *)child_path, NULL };

        close(c2p[0]);
        close(p2c[1]);
        listener_fd = install_filter();
        child_signal_listener_fd(c2p[1], p2c[0], listener_fd);
        close(listener_fd);
        execv(child_path, child_argv);
        die("execv");
    }

    close(c2p[1]);
    close(p2c[0]);
    listener = parent_receive_listener_fd(pid, c2p[0], p2c[1]);

    while (!child_done) {
        struct pollfd pfd = { .fd = listener, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        pid_t w;

        if (pr < 0) {
            if (errno == EINTR)
                continue;
            die("poll");
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            struct seccomp_notif req;
            struct seccomp_notif_resp resp;

            memset(&req, 0, sizeof(req));
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
                if (errno == ENOENT || errno == EINTR)
                    continue;
                die("NOTIF_RECV");
            }

            printf("namelist: name '%s' is on the allowlist -> CONTINUE\n",
                   sysname(req.data.nr));
            fflush(stdout);

            memset(&resp, 0, sizeof(resp));
            resp.id = req.id;
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 &&
                errno != ENOENT)
                die("NOTIF_SEND");
        }

        w = waitpid(pid, &status, WNOHANG);
        if (w < 0)
            die("waitpid");
        if (w == pid)
            child_done = 1;
    }

    close(listener);
    if (WIFEXITED(status))
        printf("namelist: child exited normally with code %d\n",
               WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("namelist: child was killed by signal %d\n", WTERMSIG(status));
    return 0;
}
