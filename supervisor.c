/*
 * supervisor.c — enforce a POLICY-DEFINED syscall protocol on a child.
 *
 * A healthy network server follows:
 *   socket -> bind -> listen -> accept -> read/write -> close
 *
 * Once a process reaches a "listening-type" state, it usually has no
 * legitimate reason to connect() out, execve() a new program, or
 * send data to an address it was never told to talk to. A name-based
 * allowlist (see namelist.c) still permits all of these, because it
 * only checks WHICH syscall, never WHEN. This supervisor checks
 * both, using seccomp SECCOMP_RET_USER_NOTIF to ask before each
 * trapped call is allowed to run.
 *
 * The protocol itself — states, and which syscall is legal in which
 * state — now lives in a POLICY (policy.h): either an external text
 * file (--policy FILE) or, if none is given, a built-in default that
 * reproduces the project's original INIT/BOUND/LISTENING protocol
 * exactly, so every existing demo/test/bench script still works
 * unchanged.
 *
 * Run (WSL, this folder):
 *   make
 *   ./supervisor                         # built-in policy, ./agent
 *   ./supervisor ./attack                # killed: connect() after listen()
 *   ./supervisor --policy policies/echo.policy ./agent
 *   ./supervisor --policy policies/redis.policy redis-server --port 6380 \
 *       --bind 127.0.0.1 --save "" --appendonly no --daemonize no
 *   (everything after the child's own path is passed through as ITS
 *   argv, unchanged — needed for a real program like Redis)
 *
 *   ./supervisor --learn out.policy ./agent   # writes a draft policy
 *   (traps every known syscall, always CONTINUEs, and writes out
 *   what it saw when the child exits — see learn_observe() below
 *   and policy_save() in policy.h for what this does and does not
 *   guarantee)
 *
 * Fixes applied vs the earlier hardcoded version (see common.h for #1,
 * policy.h for the policy engine itself):
 *   1. install_filter() (common.h, used by namelist.c's fixed
 *      baseline) checks seccomp_data.arch first. Without it, a
 *      32-bit-ABI syscall (e.g. ia32 connect() via int $0x80) carries
 *      a DIFFERENT syscall number and sailed straight through the
 *      old filter's default ALLOW — confirmed with a hand-built ia32
 *      connect() after listen(), which reached the kernel
 *      un-intercepted. supervisor.c's own dynamic filter
 *      (install_filter_dynamic, below) carries the same check.
 *   2. kill(pid, SIGKILL) used to always kill the ORIGINAL child,
 *      even when a process it had fork()'d was the one that
 *      violated. Fixed by killing the actual violator's thread
 *      group, via get_tgid().
 *   3. State was a single global struct, so a fork()'d child shared
 *      the parent's PCB, and two real OS processes were tracked as
 *      one. Replaced with a table keyed by thread-group ID
 *      (struct proc_state[]).
 *   4. A successful execve() used to leave the OLD phase in place
 *      for the NEW program image. Now expressed directly in the
 *      policy/table as ordinary rules ("... execve allow -> INIT"),
 *      not special-cased in code.
 *   5. describe_violation() didn't NUL-terminate a short partial
 *      read of an execve() path. Fixed.
 *   6. Reading the child's memory (process_vm_readv) for logging is
 *      inherently racy (TOCTOU) — never used for the allow/deny
 *      decision, only for the log line, and narrowed (not removed)
 *      with a SECCOMP_IOCTL_NOTIF_ID_VALID check beforehand.
 *   7. sendto()/execveat() were not trapped at all in the original
 *      code, bypassing the protocol entirely (confirmed). Both are
 *      now trapped; sendto's address-dependent legality is checked
 *      ahead of the policy table (policy.h explains why).
 *   8. A process fork()'d from a tracked process used to start fresh
 *      at INIT, so a plain child that never called listen() itself
 *      could connect() freely — a real bypass found while testing
 *      fix #2. Fixed with taint propagation, now generalized: a new
 *      process whose real OS parent is tracked inherits the
 *      PARENT'S CURRENT STATE, whatever it is (not just a
 *      LISTENING special case).
 *   9. The protocol was hardcoded in this file. Moved to policy.h /
 *      an external policy file, so the same binary can enforce a
 *      different protocol (e.g. for Redis) without a code change.
 *  10. The parent/child fd handoff used to use sendmsg()+SCM_RIGHTS,
 *      which meant sendmsg() itself could never be trapped (doing so
 *      deadlocked the handoff — a bug introduced and then caught
 *      while building fix #7, see common.h's old comment in git
 *      history). Replaced with pidfd_open()+pidfd_getfd(): the child
 *      tells the parent its listener fd NUMBER over a plain pipe
 *      (not a syscall we ever trap), and the parent pulls a working
 *      duplicate directly out of the child's fd table. No trapped
 *      syscall is used for the handoff anymore, so sendmsg() is now
 *      fully trapped and enforced — denied outright at LISTENING,
 *      deliberately WITHOUT inspecting its destination argument,
 *      because that argument lives behind a pointer (msg_name
 *      inside struct msghdr) and checking it would mean basing a
 *      security decision on a dereference that can be raced, unlike
 *      sendto()'s address check (a direct, TOCTOU-free argument).
 *
 * Round-robin scheduling (the earlier Phase 7) has been removed —
 * it is out of scope for this submission.
 */

#define _GNU_SOURCE

#include "policy.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#ifndef SECCOMP_IOC_MAGIC
#define SECCOMP_IOC_MAGIC '!'
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW(SECCOMP_IOC_MAGIC, 2, __u64)
#endif

#define MAX_FDS      16
#define MAX_TRACKED  16
#define MAX_FILTER_LEN (3 + 1 + 2 * 16 + 1)

static struct policy g_policy;

enum fd_st {
    FD_UNUSED = 0,
    FD_BOUND,
    FD_LISTENING,
    FD_CONNECTED
};

struct fd_entry {
    int fd;
    enum fd_st st;
};

/* One of these per thread-group (i.e. per OS process, including
 * ones the supervised program fork()'d). Fix #3. */
struct proc_state {
    int used;
    pid_t tgid;
    int phase; /* index into g_policy.state_names[] */
    struct fd_entry fds[MAX_FDS];
};

static struct proc_state procs[MAX_TRACKED];

static const char *fdst_name(enum fd_st s)
{
    switch (s) {
    case FD_BOUND:      return "BOUND";
    case FD_LISTENING:  return "LISTENING";
    case FD_CONNECTED:  return "CONNECTED";
    default:            return "UNUSED";
    }
}

/* A traditional fork()'d process has tgid == pid. A pthread-created
 * thread shares its creator's tgid. Reading /proc keeps this correct
 * either way, which matters once a multi-threaded target (Redis)
 * shows up. */
static pid_t get_tgid(pid_t pid)
{
    char path[64], line[256];
    FILE *f;
    pid_t tgid = pid;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return tgid;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "Tgid:", 5) == 0) { tgid = (pid_t)atoi(line + 5); break; }
    fclose(f);
    return tgid;
}

static pid_t get_ppid(pid_t pid)
{
    char path[64], line[256];
    FILE *f;
    pid_t ppid = -1;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return ppid;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "PPid:", 5) == 0) { ppid = (pid_t)atoi(line + 5); break; }
    fclose(f);
    return ppid;
}

static struct proc_state *find_tracked(pid_t tgid)
{
    int i;
    for (i = 0; i < MAX_TRACKED; i++)
        if (procs[i].used && procs[i].tgid == tgid)
            return &procs[i];
    return NULL;
}

/* Fix #8, generalized: a new process whose real OS parent is a
 * tracked process inherits the PARENT'S CURRENT phase, whatever it
 * is — not only when the parent happens to be the "listening-type"
 * state. A process that forks while still at an early state passes
 * that same early state to its child, which is simply correct: the
 * child hasn't done anything of its own yet either. */
static struct proc_state *find_or_create(pid_t tgid, pid_t reporting_pid)
{
    int i, empty = -1;
    struct proc_state *ps = find_tracked(tgid);

    if (ps)
        return ps;

    for (i = 0; i < MAX_TRACKED; i++)
        if (!procs[i].used) { empty = i; break; }
    if (empty < 0)
        return NULL;

    memset(&procs[empty], 0, sizeof(procs[empty]));
    procs[empty].used = 1;
    procs[empty].tgid = tgid;
    procs[empty].phase = g_policy.initial_state;

    pid_t ppid = get_ppid(reporting_pid);
    struct proc_state *parent = (ppid > 0) ? find_tracked(ppid) : NULL;

    if (parent) {
        procs[empty].phase = parent->phase;
        printf("supervisor:   note: tgid=%d inherits state %s from parent pid=%d (taint propagation)\n",
               (int)tgid, policy_state_name(&g_policy, parent->phase), (int)ppid);
    }
    return &procs[empty];
}

static void set_fd_state(struct proc_state *ps, int fd, enum fd_st st)
{
    int i, empty = -1;
    for (i = 0; i < MAX_FDS; i++) {
        if (ps->fds[i].st != FD_UNUSED && ps->fds[i].fd == fd) { ps->fds[i].st = st; return; }
        if (empty < 0 && ps->fds[i].st == FD_UNUSED) empty = i;
    }
    if (empty >= 0) { ps->fds[empty].fd = fd; ps->fds[empty].st = st; }
}

static void print_os_state(struct proc_state *ps)
{
    int i, any = 0;
    printf("supervisor:   PCB tgid=%d state=%s  fds:",
           (int)ps->tgid, policy_state_name(&g_policy, ps->phase));
    for (i = 0; i < MAX_FDS; i++) {
        if (ps->fds[i].st == FD_UNUSED) continue;
        printf(" [%d]=%s", ps->fds[i].fd, fdst_name(ps->fds[i].st));
        any = 1;
    }
    if (!any) printf(" (none yet)");
    printf("\n");
}

/* Fd-table bookkeeping only — display/logging, never used for the
 * allow/deny decision itself (that is policy_lookup()/the sendto
 * special-case, below). Runs AFTER a syscall has been allowed. */
static void note_fds(struct proc_state *ps, const struct seccomp_notif *req)
{
    int nr = req->data.nr;
    int fd = (int)req->data.args[0];

    if (nr == __NR_socket) { printf("supervisor:   note: socket() — new fd unknown until bind/listen\n"); return; }
    if (nr == __NR_bind)    { set_fd_state(ps, fd, FD_BOUND); return; }
    if (nr == __NR_listen)  { set_fd_state(ps, fd, FD_LISTENING); return; }
    if (nr == __NR_connect) { set_fd_state(ps, fd, FD_CONNECTED); return; }
}

static ssize_t read_child(pid_t pid, unsigned long remote, void *local, size_t n)
{
    struct iovec lv = { .iov_base = local, .iov_len = n };
    struct iovec rv = { .iov_base = (void *)(uintptr_t)remote, .iov_len = n };
    return process_vm_readv(pid, &lv, 1, &rv, 1, 0);
}

/* Peek connect()/sendto() address or execve()/execveat() path, for
 * the LOG LINE only — see note #6 above on why this is never used
 * for the allow/deny decision. */
static void describe_violation(int listener, const struct seccomp_notif *req,
                                char *out, size_t outsz)
{
    pid_t pid = (pid_t)req->pid;
    int nr = req->data.nr;

    snprintf(out, outsz, "(args unreadable)");

    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) < 0)
        return;

    if (nr == __NR_connect || nr == __NR_sendto) {
        struct sockaddr_in sin;
        unsigned long addr = (nr == __NR_connect) ? req->data.args[1] : req->data.args[4];
        unsigned long len  = (nr == __NR_connect) ? req->data.args[2] : req->data.args[5];

        if (addr == 0) { snprintf(out, outsz, "(no address — already-connected socket)"); return; }
        if (len < sizeof(sin)) return;
        if (read_child(pid, addr, &sin, sizeof(sin)) != (ssize_t)sizeof(sin)) return;
        if (sin.sin_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin.sin_addr, ip, sizeof(ip));
            snprintf(out, outsz, "%s:%u", ip, ntohs(sin.sin_port));
        } else {
            snprintf(out, outsz, "family=%u", (unsigned)sin.sin_family);
        }
        return;
    }

    if (nr == __NR_sendmsg) {
        /* Unlike connect()/sendto() above, msg_name lives INSIDE a
         * struct the syscall only points to — reading it needs a
         * dereference, which is why the DECISION (decide(), above)
         * never looks at it and denies sendmsg() outright instead.
         * This is purely cosmetic for the log line; a racy read
         * here only risks a wrong log message, never a wrong
         * allow/deny. */
        struct msghdr hdr;
        if (read_child(pid, req->data.args[1], &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
            return;
        if (hdr.msg_name == NULL || hdr.msg_namelen < sizeof(struct sockaddr_in)) {
            snprintf(out, outsz, "(no usable destination in msghdr)");
            return;
        }
        struct sockaddr_in sin;
        if (read_child(pid, (unsigned long)(uintptr_t)hdr.msg_name, &sin, sizeof(sin)) != (ssize_t)sizeof(sin))
            return;
        if (sin.sin_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin.sin_addr, ip, sizeof(ip));
            snprintf(out, outsz, "%s:%u", ip, ntohs(sin.sin_port));
        } else {
            snprintf(out, outsz, "family=%u", (unsigned)sin.sin_family);
        }
        return;
    }

    if (nr == __NR_execve || nr == __NR_execveat) {
        char path[128];
        unsigned long path_ptr = (nr == __NR_execve) ? req->data.args[0] : req->data.args[1];
        ssize_t n = read_child(pid, path_ptr, path, sizeof(path) - 1);
        if (n <= 0) return;
        path[n] = '\0'; /* Fix #5 */
        snprintf(out, outsz, "%s", path);
    }
}

/*
 * Learn mode (--learn OUTFILE): instead of enforcing a policy, trap
 * EVERY known syscall and always CONTINUE, building a policy from
 * what actually happens. This is NOT a generic automata-learning
 * algorithm — it leans on the same TCP-server-lifecycle knowledge
 * the rest of this project already encodes: bind() starts a new
 * phase called BOUND, listen() starts LISTENING, execve()/execveat()
 * resets to INIT (a new program image), and everything else
 * (socket, accept, accept4, connect, sendto) is recorded as legal
 * WITHIN whatever phase it was observed in, without starting a new
 * one. The result is a draft a human still has to read — see the
 * warning policy_save() writes into the file itself. Validated by
 * using it to regenerate policies/echo.policy from a traced run of
 * agent.c/attack.c and diffing the two (see REPORT.md).
 */
static int transition_target(struct policy *p, int nr, int current_state)
{
    if (nr == __NR_bind)
        return policy_state_index(p, "BOUND");
    if (nr == __NR_listen)
        return policy_state_index(p, "LISTENING");
    if (nr == __NR_execve || nr == __NR_execveat)
        return policy_state_index(p, "INIT");
    return current_state; /* socket, accept, accept4, connect, sendto: stay */
}

static void learn_observe(struct proc_state *ps, const struct seccomp_notif *req)
{
    int nr = req->data.nr;
    enum policy_action existing_action;
    int existing_next;

    if (policy_lookup(&g_policy, ps->phase, nr, &existing_action, &existing_next))
        return; /* already recorded for this (state, syscall) — nothing new */

    int next = transition_target(&g_policy, nr, ps->phase);

    policy_add_rule(&g_policy, ps->phase, nr, POLICY_ALLOW,
                     (next == ps->phase) ? -1 : next);
    printf("learn: observed %s --%s--> %s (tgid=%d)\n",
           policy_state_name(&g_policy, ps->phase), sysname(nr),
           policy_state_name(&g_policy, next), (int)ps->tgid);
    ps->phase = next;
}

enum verdict { V_ALLOW, V_DENY };

/* The whole point of the project: consult the POLICY (state +
 * syscall -> allow/deny + next state), with one hardcoded exception
 * (sendto's address-dependent legality — see policy.h). Unmatched
 * (state, syscall) pairs default-deny. */
static enum verdict decide(struct proc_state *ps, const struct seccomp_notif *req,
                            int *next_state)
{
    int nr = req->data.nr;

    *next_state = ps->phase;

    if (nr == __NR_sendto) {
        unsigned long addr = req->data.args[4]; /* NULL => already-connected socket */
        return (addr != 0) ? V_DENY : V_ALLOW;
    }

    enum policy_action action;
    int next;
    if (policy_lookup(&g_policy, ps->phase, nr, &action, &next)) {
        if (action == POLICY_DENY)
            return V_DENY;
        *next_state = (next == -1) ? ps->phase : next;
        return V_ALLOW;
    }

    return V_DENY; /* no rule for this (state, syscall): default-deny */
}

static int install_filter_dynamic(const struct policy *p)
{
    struct sock_filter filter[MAX_FILTER_LEN];
    int idx = 0, i;

    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                        offsetof(struct seccomp_data, arch));
    filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                        AUDIT_ARCH_X86_64, 1, 0);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                        offsetof(struct seccomp_data, nr));

    for (i = 0; i < p->n_syscalls_used; i++) {
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                            p->syscalls_used[i], 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    }
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { .len = (unsigned short)idx, .filter = filter };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("PR_SET_NO_NEW_PRIVS");
    int listener = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                                 SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0)
        die("seccomp NEW_LISTENER");
    return listener;
}

static void print_exit(int status)
{
    if (WIFEXITED(status))
        printf("supervisor: child exited normally with code %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("supervisor: child was killed by signal %d\n", WTERMSIG(status));
    else
        printf("supervisor: child ended in an unexpected way\n");
}

int main(int argc, char **argv)
{
    const char *child_path = "./agent";
    const char *policy_path = NULL;
    const char *learn_path = NULL;
    char **child_argv = NULL; /* NULL => build the default {child_path, NULL} below */
    int i;

    /* --policy FILE / --learn FILE may appear only before the
     * child's own path; the FIRST token that isn't one of those (or
     * its argument) is the child's path, and EVERYTHING from there
     * on (including further flags) belongs to the child's own argv,
     * not to us — this is what lets a real program like Redis
     * receive its own --port etc. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--policy") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "supervisor: --policy needs a file argument\n"); return 1; }
            policy_path = argv[++i];
        } else if (strcmp(argv[i], "--learn") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "supervisor: --learn needs a file argument\n"); return 1; }
            learn_path = argv[++i];
        } else {
            child_path = argv[i];
            child_argv = &argv[i]; /* argv[i..argc-1], already NULL-terminated by the OS */
            break;
        }
    }

    if (policy_path && learn_path) {
        fprintf(stderr, "supervisor: --policy and --learn are mutually exclusive\n");
        return 1;
    }

    if (learn_path) {
        memset(&g_policy, 0, sizeof(g_policy));
        g_policy.initial_state = policy_state_index(&g_policy, "INIT");
        /* Trap everything we know how to recognize, so nothing the
         * child does is missed — enforcement mode only traps what a
         * loaded policy references, but learn mode has no policy
         * yet, that's the point. */
        policy_mark_syscall_used(&g_policy, __NR_socket);
        policy_mark_syscall_used(&g_policy, __NR_bind);
        policy_mark_syscall_used(&g_policy, __NR_listen);
        policy_mark_syscall_used(&g_policy, __NR_accept);
        policy_mark_syscall_used(&g_policy, __NR_accept4);
        policy_mark_syscall_used(&g_policy, __NR_connect);
        policy_mark_syscall_used(&g_policy, __NR_execve);
        policy_mark_syscall_used(&g_policy, __NR_execveat);
        policy_mark_syscall_used(&g_policy, __NR_sendto);
        policy_mark_syscall_used(&g_policy, __NR_sendmsg);
        printf("supervisor: LEARN MODE — observing %s, writing a draft policy to '%s' when it exits\n",
               child_path, learn_path);
    } else if (policy_path) {
        char err[256];
        if (policy_load(&g_policy, policy_path, err, sizeof(err)) != 0) {
            fprintf(stderr, "supervisor: policy error: %s\n", err);
            return 1;
        }
        printf("supervisor: loaded policy '%s' (%d states, %d rules, initial=%s)\n",
               policy_path, g_policy.n_states, g_policy.n_rules,
               policy_state_name(&g_policy, g_policy.initial_state));
    } else {
        policy_load_builtin(&g_policy);
        printf("supervisor: using built-in default policy (INIT/BOUND/LISTENING)\n");
    }

    int c2p[2], p2c[2]; /* child->parent: fd number; parent->child: ack */
    pid_t pid;
    int listener, status, child_done = 0;

    printf("supervisor: I am the parent, pid=%d\n", getpid());
    memset(procs, 0, sizeof(procs));

    if (pipe(c2p) < 0 || pipe(p2c) < 0)
        die("pipe");

    printf("supervisor: starting child %s\n", child_path);
    fflush(stdout);

    pid = fork();
    if (pid < 0)
        die("fork");

    if (pid == 0) {
        char *default_argv[] = { (char *)child_path, NULL };
        int listener_fd;

        close(c2p[0]);
        close(p2c[1]);
        listener_fd = install_filter_dynamic(&g_policy);
        child_signal_listener_fd(c2p[1], p2c[0], listener_fd);
        close(listener_fd);

        execv(child_path, child_argv ? child_argv : default_argv);
        die("execv");
    }

    close(c2p[1]);
    close(p2c[0]);
    listener = parent_receive_listener_fd(pid, c2p[0], p2c[1]);

    find_or_create(pid, pid);

    printf("supervisor: watching syscalls for child pid=%d\n", pid);
    fflush(stdout);

    while (!child_done) {
        struct pollfd pfd = { .fd = listener, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        pid_t w;

        if (pr < 0) {
            if (errno == EINTR) continue;
            die("poll");
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            struct seccomp_notif req;
            struct seccomp_notif_resp resp;
            struct proc_state *ps;
            pid_t tgid;
            int next_state;

            memset(&req, 0, sizeof(req));
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
                if (errno == ENOENT || errno == EINTR) continue;
                die("SECCOMP_IOCTL_NOTIF_RECV");
            }

            tgid = get_tgid((pid_t)req.pid);
            ps = find_or_create(tgid, (pid_t)req.pid);
            if (!ps) {
                memset(&resp, 0, sizeof(resp));
                resp.id = req.id;
                resp.error = -EPERM;
                if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 && errno != ENOENT)
                    die("SECCOMP_IOCTL_NOTIF_SEND");
                continue;
            }

            if (learn_path) {
                learn_observe(ps, &req);
                fflush(stdout);
                memset(&resp, 0, sizeof(resp));
                resp.id = req.id;
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 && errno != ENOENT)
                    die("SECCOMP_IOCTL_NOTIF_SEND");
                w = waitpid(pid, &status, WNOHANG);
                if (w < 0) die("waitpid");
                if (w == pid) child_done = 1;
                continue;
            }

            enum verdict v = decide(ps, &req, &next_state);

            if (v == V_DENY) {
                char detail[160];
                describe_violation(listener, &req, detail, sizeof(detail));
                printf("supervisor: trap pid=%d tgid=%d syscall=%s (nr=%d) -> DENY\n",
                       (int)req.pid, (int)tgid, sysname(req.data.nr), req.data.nr);
                printf("supervisor: PROTOCOL VIOLATION: %s at state %s target=%s — killing pid %d\n",
                       sysname(req.data.nr), policy_state_name(&g_policy, ps->phase), detail, (int)req.pid);
                print_os_state(ps);
                fflush(stdout);

                memset(&resp, 0, sizeof(resp));
                resp.id = req.id;
                resp.error = -EPERM;
                if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 && errno != ENOENT)
                    die("SECCOMP_IOCTL_NOTIF_SEND");

                if (kill(tgid, SIGKILL) < 0 && errno != ESRCH)
                    die("kill");
            } else {
                printf("supervisor: trap pid=%d tgid=%d syscall=%s (nr=%d) -> CONTINUE (%s -> %s)\n",
                       (int)req.pid, (int)tgid, sysname(req.data.nr), req.data.nr,
                       policy_state_name(&g_policy, ps->phase),
                       policy_state_name(&g_policy, next_state));
                note_fds(ps, &req);
                ps->phase = next_state;
                print_os_state(ps);
                fflush(stdout);

                memset(&resp, 0, sizeof(resp));
                resp.id = req.id;
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 && errno != ENOENT)
                    die("SECCOMP_IOCTL_NOTIF_SEND");
            }
        }

        w = waitpid(pid, &status, WNOHANG);
        if (w < 0) die("waitpid");
        if (w == pid) child_done = 1;
    }

    close(listener);
    print_exit(status);

    if (learn_path) {
        if (policy_save(&g_policy, learn_path) == 0) {
            printf("supervisor: wrote learned policy to '%s' (%d states, %d rules)\n",
                   learn_path, g_policy.n_states, g_policy.n_rules);
            printf("supervisor: this is a DRAFT — read it before trusting it (see the\n");
            printf("supervisor: comment at the top of the file, and policy.h/REPORT.md)\n");
        } else {
            fprintf(stderr, "supervisor: could not write '%s'\n", learn_path);
            return 1;
        }
    }
    return 0;
}
