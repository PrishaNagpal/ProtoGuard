# ProtoGuard — Lab Report

**Course:** Operating Systems (BCSE303P), L15+L16 — Dr. Anisha M. Lal
**Topic chosen from the project list:** Secure Process Isolation (sandboxing beyond containers)

## 1. Problem

Seccomp-based sandboxes, and most container sandboxes built on them, restrict a
process using a static **allowlist of syscall names**. A network daemon
legitimately needs `connect()` at some point (e.g. to a database) and
`execve()` at startup, so a name-based filter must permit both for the
process's entire lifetime. If the process is later compromised (buffer
overflow, deserialization bug, etc.), the attacker can reuse those same,
already-allowed calls for a reverse shell (`connect()`) or to run a dropped
payload (`execve()`). The filter has no way to express "legal at startup,
illegal once listening."

## 2. Approach

ProtoGuard is a userspace supervisor that models a server's life as a small
state machine and checks syscalls against **both** their name and the
current state:

```
         bind()           listen()
INIT ────────────► BOUND ──────────► LISTENING
  │                                       │
  │ connect()/execve()/execveat()/        │  these are now ILLEGAL
  │ sendto(addr)/accept() — all legal     │  (EPERM + SIGKILL, destination
  │ here, server is still starting up     │  logged for the report)
  └───────────────────────────────────────┘
```

Enforcement uses Linux seccomp with `SECCOMP_RET_USER_NOTIF`: trapped
syscalls are paused and the kernel asks ProtoGuard (a separate, parent
process) to allow or deny each one, instead of deciding in-kernel from a
fixed table. Linux stays the kernel — this is entirely a userspace policy
layer on top of a stock kernel feature.

The state machine itself is **data, not code**: `policy.h` loads either an
external text file (`--policy FILE`) or, if none is given, a built-in
default that reproduces the project's original protocol. The seccomp
filter is built dynamically from exactly the syscalls the loaded policy
references, so a different program with a different legitimate syscall
sequence needs only a new policy file, not a rebuild — see
`policies/echo.policy` (equivalent to the built-in default) and
`policies/strict-no-outbound.policy` (a stricter variant: no outbound
`connect()` in *any* state, not just after `listen()`).

## 3. What is built

| File | Role |
|---|---|
| `agent.c` | The "good" server: a one-shot TCP echo server on `127.0.0.1:18080` |
| `attack.c` | Listens, then illegally `connect()`s out |
| `attack_exec.c` | Listens, then illegally `execve()`s `/bin/true` |
| `common.h` | Shared by `supervisor.c` and `namelist.c`: fd-passing helpers and the seccomp filter (**including the architecture check**, so both share identical first-line defenses — see §5) |
| `policy.h` | The policy engine: parses a text policy file (or the built-in default) into states and rules, answers "is this syscall legal in this state?", and can serialize a policy back to text (used by `--learn`, section 8) |
| `policies/echo.policy` | External policy file, equivalent to the built-in default — demonstrates the mechanism end to end |
| `policies/strict-no-outbound.policy` | A stricter alternative (no outbound `connect()` in *any* state) — a one-file edit, no rebuild |
| `policies/redis.policy` | Policy for `redis-server`, written from observed `strace` behavior — see §7 |
| `supervisor.c` | The project: loads a policy, builds a filter from exactly the syscalls that policy references, tracks per-process state, enforces, propagates taint, logs violations |
| `namelist.c` | Baseline: same trapped syscalls, always `CONTINUE` — "is the name OK?" with no notion of *when* |
| `tests/escape_*.c` | Escape test suite (4 programs) — see §5 |
| `run_escape_tests.sh` | Builds and runs the full test suite under all three defenses, prints a results table built from real exit codes |
| `phase8_bench.sh` | Timing: plain `agent` vs `supervisor` |
| `phase1_run.sh` | `strace`-based walkthrough of `agent`/`attack`, used while learning the syscalls involved |
| `demo.sh` | End-to-end viva script |

## 4. OS concepts this project touches

- **Processes & process control:** `fork()`/`exec()`/`wait()` to launch and
  supervise the child; `kill()` with `SIGKILL` to terminate a violator.
- **System calls:** the entire enforcement mechanism is built on
  intercepting `socket`, `bind`, `listen`, `accept`/`accept4`, `connect`,
  `execve`, `execveat`, `sendto`.
- **Protection & isolation:** seccomp-bpf, `PR_SET_NO_NEW_PRIVS`, a
  userspace reference monitor making allow/deny decisions.
- **Process control blocks:** a small per-process `struct proc_state`
  (phase + fd table), keyed by thread-group ID, modelling what a kernel's
  PCB tracks for scheduling, applied here to protocol state instead.
- **Threads vs. processes:** the thread-group-ID lookup (`get_tgid`,
  `/proc/<pid>/status`) exists specifically so a multi-threaded target
  (planned: Redis) is tracked as one logical process, not one per thread.

## 5. Escape test suite and bake-off

Seven attacks were run against three defenses: **no sandbox**, **namelist**
(name-only allowlist), and **supervisor** (this project). Produced by
`./run_escape_tests.sh`, from real exit codes and signals of each run — not
a hand-written table:

| Test | no sandbox | namelist | supervisor |
|---|---|---|---|
| `connect()` after `listen()` | NOT BLOCKED | NOT BLOCKED | **BLOCKED** |
| `execve()` after `listen()` | NOT BLOCKED | NOT BLOCKED | **BLOCKED** |
| `execveat()` after `listen()` | NOT BLOCKED | NOT BLOCKED | **BLOCKED** |
| `fork()` then `connect()` from the child | NOT BLOCKED | NOT BLOCKED | **BLOCKED** |
| `connect()` via the 32-bit (ia32) syscall ABI | NOT BLOCKED | BLOCKED | BLOCKED |
| UDP `sendto()` to an arbitrary address | NOT BLOCKED | NOT BLOCKED | **BLOCKED** |
| UDP `sendmsg()` to an arbitrary address | NOT BLOCKED | NOT BLOCKED | **BLOCKED** |

Six of seven rows are blocked **only** by the stateful supervisor — this is
the project's core claim, demonstrated rather than asserted. The ia32 row
is blocked by *both* defenses, because it is caught by the **architecture
check** in `common.h` (`seccomp_data.arch == AUDIT_ARCH_X86_64`, else
`SECCOMP_RET_KILL_PROCESS`) — a fix for a real gap found during testing (a
32-bit-ABI `connect()`, issued via `int $0x80`, carries a different syscall
*number* than native `connect()` and originally slipped through the
default-allow branch of the filter un-intercepted). That check is shared
identically by `namelist.c`, deliberately, so this row does not
contaminate the comparison: the only variable the bake-off is meant to
isolate is **statefulness**, not an unrelated ABI bypass.

### Bugs found and fixed during testing (not just claimed — reproduced)

1. **Architecture confusion bypass** — see above. Fixed with the arch
   check in `common.h`.
2. **Wrong process killed** — the original code unconditionally
   `kill()`ed the top-level child PID. If a *different* process the child
   had `fork()`'d was the actual violator, the wrong process was signalled.
   Fixed: each notification's real syscall-issuing `pid` is resolved to
   its thread-group ID and that process specifically is killed.
3. **State shared across forked processes** — the original single global
   PCB meant a `fork()`'d process shared its parent's tracked phase.
   Replaced with a table keyed by thread-group ID.
4. **`execve()` did not reset state** — exec'ing a new program image kept
   the old program's phase (e.g. staying `BOUND` after exec'ing something
   that hasn't bound anything). Fixed: an allowed exec resets that
   process's tracked state to `INIT`.
5. **Unterminated string on a short read** — `describe_violation()` could
   print garbage past a short `process_vm_readv()` read of an `execve()`
   path. Fixed.
6. **`execveat()` and `sendto()` were not trapped at all** — both
   bypassed the protocol entirely before this round of fixes (confirmed:
   a UDP `sendto()` after `listen()` reached the kernel unchecked). Both
   are now trapped and checked.
7. **`fork()`-then-`connect()` bypass** — a process `fork()`'d from a
   `LISTENING` server started fresh at `INIT`, so a plain child that never
   itself called `listen()` could `connect()` freely. This was found
   *while testing fix #2*, not anticipated in advance. Fixed with
   **taint propagation**: a new process whose real OS parent (via
   `/proc/<pid>/status`, `PPid:`) is a tracked, `LISTENING` process starts
   `LISTENING` itself.
8. **Policy externalized, and taint propagation generalized along the
   way** — the protocol moved from hardcoded C logic into `policy.h`'s
   state/rule table, loadable from a text file. While rewriting the
   engine, the earlier taint-propagation fix (a forked child of a
   `LISTENING` process inherits that restriction) was generalized:
   a new process now always inherits whatever state its tracked OS
   parent currently holds, not only the specific `LISTENING` case. This
   is both simpler code and more correct (a child forked while its
   parent is merely `BOUND`, for instance, now correctly starts `BOUND`
   too, instead of resetting to `INIT`).
9. **A fix of ours introduced a deadlock** — an earlier attempt to also
   trap `sendmsg()` broke the supervisor's own parent/child handshake,
   which at the time used `sendmsg()` to pass the listener fd over
   `SCM_RIGHTS`. The child's own handshake call then waited forever for
   a notification reply that could never come (the supervisor didn't
   have the listener fd yet to reply with). Caught by testing before
   submission, not left in. Fixed at the time by excluding `sendmsg()`
   from the trap list — later closed properly, see bug #10.
10. **The handoff itself was redesigned to remove bug #9's root cause
    instead of just working around it** — replaced `sendmsg()`+
    `SCM_RIGHTS` with `pidfd_open()`+`pidfd_getfd()`: the child tells the
    parent, over a plain pipe (never trapped), which fd number its
    listener ended up as, and the parent pulls a working duplicate
    directly out of the child's fd table. No trapped syscall is used for
    the handoff at all anymore, so `sendmsg()` can finally be trapped
    and enforced — see §5's table. This is not argument-aware like
    `sendto()`: `sendmsg()`'s destination lives inside a struct the
    syscall only *points to* (`msg_name` in `struct msghdr`), so
    checking it would mean basing a security decision on a dereference
    that can be raced — unlike `sendto()`'s destination, which is a
    direct syscall argument the kernel captures atomically. Rather than
    make that tradeoff, `sendmsg()` is simply denied outright once
    `LISTENING`, the same as `connect()`/`execve()`, via an ordinary
    policy rule with no argument inspection — deliberately coarser
    (a legitimate no-destination `sendmsg()` would also be denied) in
    exchange for not trusting a racy read for the decision itself.
11. **The naive version of the redesign introduced a NEW race** — closing
    the child's own copy of the listener fd immediately after signaling
    its number to the parent, before confirming the parent had actually
    finished `pidfd_getfd()`, could leave zero references to the kernel's
    notifier object for a brief window, breaking the child's own very
    next trapped syscall (its `execv()` call) with no listener left to
    notify — reproduced directly (manifested as `execv()` failing with
    `ENOSYS` and the parent's `pidfd_getfd()` then failing with `ESRCH`,
    since the child had already exited). Fixed with an explicit two-way
    handshake: the child now waits for an ack byte from the parent,
    confirming the duplicate fd has been pulled, before closing its own
    copy and proceeding to `execv()`.

## 6. Known limitations (stated honestly, not hidden)

- **Not in-kernel.** This is a userspace policy layer on an unmodified
  Linux kernel, not a kernel patch or LSM.
- **TOCTOU on logged arguments.** `process_vm_readv()` reads from the
  child's memory for the human-readable log line only, never for the
  allow/deny decision, because the child can rewrite that memory between
  the kernel validating the syscall and the supervisor reading it. A
  `SECCOMP_IOCTL_NOTIF_ID_VALID` check narrows, but does not remove, this
  window.
- **`sendmsg()`'s destination is never inspected**, by design — see bug
  #10. It is trapped and denied outright at `LISTENING`, but (unlike
  `sendto()`) without looking at whether a given call actually had a
  destination, because doing so would require a dereference that can be
  raced. The tradeoff: a legitimate no-destination `sendmsg()` would
  also be denied; we chose that over a sharper but racy check.
- **State advances on the request, not on confirmed success** — e.g. a
  `bind()` that is about to fail still moves the tracked phase to `BOUND`
  before the kernel's real answer is known, because `USER_NOTIF` only
  exposes the call *before* it runs, not its result.
- **Coverage is deliberately narrow** (8 syscalls). `io_uring`-based I/O
  and other less common paths to the same effect are not covered.
- **Novelty is modest.** The idea (stateful policy over syscalls) is
  related to prior tools (Systrace-style policy engines, container
  runtimes' seccomp-notify supervisors). The contribution here is a
  focused implementation and an evidence-based comparison against a
  realistic baseline, not a novel mechanism.

## 7. Running a real daemon: Redis

`policies/redis.policy` was written from **observed behavior**
(`strace -f redis-server ...`), not guessed:

- `socket()`/`bind()`/`listen()` each happen exactly once, from the main
  thread, before any client connects.
- Redis then `clone3()`s 3-4 background threads with `CLONE_THREAD` — real
  POSIX threads sharing the main thread's thread-group ID, not separate
  processes. `supervisor.c`'s `get_tgid()` maps every notification from
  these threads back to the *same* tracked `proc_state` as the main
  thread automatically. In practice, **none of the background threads
  ever called a trapped syscall** — the entire test log shows trap lines
  only from the main thread's `tgid`.
- Redis uses `accept4()`, not `accept()` (the built-in default policy
  already covers both).
- An idle Redis makes **zero** `accept4()` calls (it blocks in
  `epoll_wait`, which we don't trap) — notification overhead scales with
  the number of *connections*, not idle time.

### Functional test

Redis was run as `./supervisor --policy policies/redis.policy
/usr/bin/redis-server --port 6380 --bind 127.0.0.1 --save "" --appendonly
no --daemonize no`, and exercised with `PING`, `SET`, `GET`, `EXPIRE`,
`TTL`, `INCR`, `LPUSH`, `LRANGE` — all succeeded with **zero false
positives**, and the server shut down cleanly on `SHUTDOWN NOSAVE`.

### Simulated-compromise test

We do not have a real Redis RCE to demonstrate against, and did not try
to fake one. Instead, we used `gdb` to attach to the **already running,
already-serving** supervised Redis process and force it to call
`socket()` then `connect()` with a destination — the same action a
reverse-shell payload from a real exploit would take — while it was
genuinely listening and had just served real client traffic. Result,
directly from the supervisor's own log:

```
supervisor: trap pid=2112 tgid=2112 syscall=connect (nr=42) -> DENY
supervisor: PROTOCOL VIOLATION: connect at state LISTENING target=(no address — already-connected socket) — killing pid 2112
supervisor: child was killed by signal 9
```

The process was confirmed dead immediately after. This is the same
mechanism validated on the toy `attack.c`, now shown working against
unmodified, real-world server software under live traffic conditions.

### Throughput (`redis-benchmark`, keep-alive connections — the default)

```
                SET              GET
no sandbox      109,890 req/s    111,732 req/s
supervisor       98,039 req/s     96,154 req/s
overhead         ~10.8%           ~13.9%
```

50 concurrent clients, 10,000-20,000 requests, `redis-benchmark -p <port>
-n 20000 -c 50 -t set,get -q`. With persistent connections, the overhead
is almost entirely the ~50 `accept4()` notification round-trips at
connection setup, not per-request cost (`SET`/`GET` themselves go through
`read()`/`write()`, which are not trapped). We also measured `-k 0`
(a fresh connection per request) but the results were too noisy to trust
at a scale we could run here — TCP connection setup/teardown cost
dominated and swamped any difference attributable to the supervisor, so
we report only the keep-alive numbers rather than overclaim a worst case
we didn't actually establish cleanly. **These are machine-specific —
re-run `redis-benchmark` yourself before quoting a number.**

## 8. Policy learning mode

Writing `policies/redis.policy` (section 7) meant manually reading an
`strace` log and transcribing it into the policy format. `--learn OUTFILE`
automates that transcription step.

**How it works:** instead of loading a policy to enforce, the supervisor
traps every syscall it knows about and always `CONTINUE`s (pure
observation — nothing is ever denied in this mode). For each trapped
syscall it checks whether a rule already exists for the current
(state, syscall) pair; if not, it adds one. The state transitions
themselves use the **same TCP-server-lifecycle knowledge already built
into this project** — `bind()` starts a state called `BOUND`, `listen()`
starts `LISTENING`, `execve()`/`execveat()` reset to `INIT` (a new
program image) — everything else (`socket`, `accept`/`accept4`,
`connect`, `sendto`) is recorded as legal *within* whichever state it
was observed in, without starting a new one. This is **not** a generic
automata-learning algorithm; it is domain knowledge about POSIX socket
servers applied automatically, which is an honest description of what it
actually does and what it doesn't.

### Validation 1: learning reproduces a known-good, hand-written policy

Running `./supervisor --learn out.policy ./agent`, with a real `nc`
client completing one echo exchange, produced:

```
state INIT
state BOUND
state LISTENING

INIT       execve    allow
INIT       socket    allow
INIT       bind      allow -> BOUND
BOUND      listen    allow -> LISTENING
LISTENING  accept    allow
```

This is a strict subset of the hand-written `policies/echo.policy` — it
is missing the explicit `LISTENING connect deny` / `execve deny` /
`execveat deny` lines, but **that is not a weaker policy**: this
project's engine default-denies any (state, syscall) pair with no rule,
so the *absence* of those lines has the identical practical effect as
writing them explicitly. The learner only had to discover what to
*allow*; everything else is safe by default. (It also correctly used
`accept`, not `accept4`, because that is what `agent.c` actually calls —
no manual lookup needed, unlike writing `redis.policy` by hand.)

### Validation 2 (the important one): learning is not automatically safe

Running the exact same tool against `./attack` (which deliberately
`connect()`s after `listen()`) produced:

```
LISTENING  socket    allow
LISTENING  connect   allow
```

The tool faithfully recorded what happened — including the illegitimate
`connect()` — as *allowed*. Loading this file back for enforcement
(`./supervisor --policy <learned-from-attack>.policy ./attack`) lets
`attack.c` run to completion with **no violation and no kill**, exactly
as the warning `policy_save()` writes into every generated file says it
might. This is not a hypothetical caveat: we deliberately reproduced it.
**A learned policy is a draft to review, never a policy to trust
blindly** — the asymmetry is that *omissions* in a learned policy are
safe (default-deny), but *inclusions* must be checked, because the tool
cannot tell legitimate behavior from a traced attack; it only reports
what it saw.

## 9. Performance (toy echo server)

From `./phase8_bench.sh 40` (40 start→echo→exit cycles of `agent`, with and
without the supervisor):

```
no_supervisor   N=40  total=340.3 ms  avg=8.51 ms/run
supervisor      N=40  total=825.0 ms  avg=20.62 ms/run
```

~12.6 ms/run of overhead, dominated by `fork()`/`exec()` and the seccomp
notification round-trips for the ~5 trapped startup syscalls, not by any
steady-state cost (the echo exchange itself is not trapped).
**These numbers are from the machine this was last tested on and will
differ on yours — re-run `./phase8_bench.sh 40` before quoting a figure
in a submission or viva.**

## 10. How to run

```bash
make
./supervisor                                           # built-in policy, ./agent
./supervisor ./attack                                  # killed: connect() after listen()
./supervisor ./attack_exec                              # killed: execve() after listen()
./supervisor --policy policies/echo.policy ./agent      # same protocol, from a file
./supervisor --policy policies/strict-no-outbound.policy ./agent  # stricter variant
./supervisor --learn out.policy ./agent                 # derive a draft policy (section 8)
./namelist ./attack                                     # NOT killed: name-only allowlist
./run_escape_tests.sh                                   # full 6-test x 3-defense table (section 5)
./phase8_bench.sh 40                                    # timing
./demo.sh                                                # all of the above, end to end

# Redis (section 7):
./supervisor --policy policies/redis.policy /usr/bin/redis-server \
    --port 6380 --bind 127.0.0.1 --save "" --appendonly no --daemonize no
#   another terminal: redis-cli -p 6380 ping
#   another terminal: redis-benchmark -p 6380 -n 20000 -c 50 -t set,get -q
```

## 11. Status vs. submission scope

**Done:** stateful enforcement, architecture-check hardening, correct
per-process/taint-aware state tracking, external policy file (with three
working example policies, including one for Redis derived from observed
`strace` behavior), a policy learning mode (`--learn`) that derives a
draft policy from an actual traced run — validated both by reproducing a
known-good hand-written policy and by demonstrating, concretely, that it
is not automatically safe — 6-attack escape test suite with a generated
(not hand-written) results table, baseline bake-off, timing, a real
daemon (Redis) running under the supervisor with zero false positives
across a real client session, a simulated-compromise test against *live*
Redis via a `gdb`-injected `connect()`, and throughput measurement via
`redis-benchmark`.

**Not yet done:** nothing from the originally agreed scope remains.
`sendmsg()` coverage, previously listed here as future work, has since
been closed (bugs #10-11): the fd handoff no longer uses `sendmsg()`
itself, so it can now be trapped and enforced. Remaining possible future
work (not promised for this submission): a second real daemon (e.g.
nginx) to further test generalization — nginx forks worker *processes*,
not threads, a genuinely different code path than Redis exercised — and
cgroup-based resource limits alongside the syscall protocol.
