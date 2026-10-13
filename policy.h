/*
 * policy.h — turns the protocol supervisor.c enforces into DATA.
 *
 * Format (one rule per line; '#' starts a comment; blank lines ok):
 *
 *   state NAME                      declare a state; FIRST one
 *                                    declared is the initial state
 *                                    for every new tracked process
 *
 *   STATE  SYSCALL  allow [-> NEXT]  allow SYSCALL while in STATE;
 *                                    move to NEXT afterwards (or
 *                                    stay in STATE if "-> NEXT" is
 *                                    omitted)
 *
 *   STATE  SYSCALL  deny             deny SYSCALL while in STATE
 *                                    (EPERM + SIGKILL, as before)
 *
 * Supported syscall names: socket, bind, listen, accept, accept4,
 * connect, execve, execveat, sendto, sendmsg. (An earlier version of
 * this project excluded "sendmsg" because of a deadlock in how the
 * fd handoff worked; the handoff was redesigned — see common.h — and
 * sendmsg is now fully supported.)
 *
 * Any (state, syscall) pair with NO matching rule is DENIED by
 * default — a policy author must list every legitimate transition
 * explicitly. This is the secure-default choice; it also means an
 * incomplete policy will kill a perfectly innocent program, which
 * is the price of writing your own policy (see REPORT.md).
 *
 * KNOWN GAP, kept deliberately out of this format: sendto()'s real
 * legality also depends on an ARGUMENT — is a destination address
 * given, or is this an already-connected socket's sendto() with no
 * address? A plain state+syscall table has no way to express that,
 * so supervisor.c keeps that one check hardcoded ahead of the table
 * lookup. Checking it is TOCTOU-free, because "is the address
 * argument NULL" is a direct syscall argument the kernel captured
 * atomically — no dereference needed. A fuller policy language
 * could add argument predicates generally; that is future work.
 *
 * sendmsg() does NOT get the same treatment, deliberately: its
 * destination (msg_name) lives inside a struct the syscall only
 * POINTS to, so checking it would require dereferencing child
 * memory — a read that genuinely can be raced (the child can
 * rewrite the struct between the kernel validating the syscall and
 * us reading it). Rather than base a security DECISION on a racy
 * read, sendmsg() is simply denied outright once LISTENING (same as
 * connect()/execve()), via an ordinary table rule, with no argument
 * inspection at all. This is deliberately conservative: a legitimate
 * sendmsg() call with no destination would also be denied. We chose
 * the safe-but-coarser rule over a sharper-but-racy one.
 *
 * Because of the above, "sendto" is handled specially by
 * supervisor.c BEFORE the table is consulted at all, while
 * "sendmsg" is an entirely ordinary table-governed syscall like
 * connect/execve. Either way, the filter only traps a syscall if
 * something in the policy references it, so a CUSTOM policy must
 * include at least one rule mentioning each one it wants trapped
 * (e.g. "LISTENING sendto deny" / "LISTENING sendmsg deny") — for
 * sendto its allow/deny value is ignored at decision time (the
 * hardcoded check decides); for sendmsg it is used normally. The
 * built-in default policy below does this for both automatically.
 */
#ifndef POLICY_H
#define POLICY_H

#include "common.h"

#define POLICY_MAX_STATES 16
#define POLICY_MAX_RULES  128

enum policy_action { POLICY_ALLOW = 0, POLICY_DENY = 1 };

struct policy_rule {
    int state;
    int nr;
    enum policy_action action;
    int next_state; /* -1 = stay in the same state */
};

struct policy {
    char state_names[POLICY_MAX_STATES][32];
    int n_states;
    int initial_state;

    struct policy_rule rules[POLICY_MAX_RULES];
    int n_rules;

    int syscalls_used[16]; /* unique nr values, for building the filter */
    int n_syscalls_used;
};

/* Same name set as common.h's sysname(), in the other direction.
 * Returns the syscall number, or -1 if unknown. */
static inline int policy_name_to_nr(const char *name)
{
    if (strcmp(name, "socket") == 0)   return __NR_socket;
    if (strcmp(name, "bind") == 0)     return __NR_bind;
    if (strcmp(name, "listen") == 0)   return __NR_listen;
    if (strcmp(name, "accept") == 0)   return __NR_accept;
    if (strcmp(name, "accept4") == 0)  return __NR_accept4;
    if (strcmp(name, "connect") == 0)  return __NR_connect;
    if (strcmp(name, "execve") == 0)   return __NR_execve;
    if (strcmp(name, "execveat") == 0) return __NR_execveat;
    if (strcmp(name, "sendto") == 0)   return __NR_sendto;
    if (strcmp(name, "sendmsg") == 0)  return __NR_sendmsg;
    return -1;
}

static inline int policy_state_index(struct policy *p, const char *name)
{
    int i;

    for (i = 0; i < p->n_states; i++)
        if (strcmp(p->state_names[i], name) == 0)
            return i;
    if (p->n_states >= POLICY_MAX_STATES)
        return -1;
    strncpy(p->state_names[p->n_states], name,
            sizeof(p->state_names[p->n_states]) - 1);
    return p->n_states++;
}

static inline void policy_mark_syscall_used(struct policy *p, int nr)
{
    int i;

    for (i = 0; i < p->n_syscalls_used; i++)
        if (p->syscalls_used[i] == nr)
            return;
    if (p->n_syscalls_used < (int)(sizeof(p->syscalls_used) / sizeof(p->syscalls_used[0])))
        p->syscalls_used[p->n_syscalls_used++] = nr;
}

/* Returns 0 on success, -1 on error (message in errbuf). */
static inline int policy_load(struct policy *p, const char *path,
                               char *errbuf, size_t errsz)
{
    FILE *f;
    char line[256];
    int lineno = 0;

    memset(p, 0, sizeof(*p));
    p->initial_state = 0;

    f = fopen(path, "r");
    if (!f) {
        snprintf(errbuf, errsz, "cannot open policy file '%s'", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        char *tok[8];
        int n = 0;

        lineno++;
        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == '#' || *s == '\n' || *s == '\0')
            continue;

        for (char *t = strtok(s, " \t\r\n"); t && n < 8; t = strtok(NULL, " \t\r\n"))
            tok[n++] = t;
        if (n == 0)
            continue;

        if (strcmp(tok[0], "state") == 0) {
            if (n != 2) {
                snprintf(errbuf, errsz, "line %d: 'state' needs exactly one name", lineno);
                fclose(f);
                return -1;
            }
            if (policy_state_index(p, tok[1]) < 0) {
                snprintf(errbuf, errsz, "line %d: too many states (max %d)",
                         lineno, POLICY_MAX_STATES);
                fclose(f);
                return -1;
            }
            continue;
        }

        /* Rule line: STATE SYSCALL allow|deny [-> NEXT] */
        if (n < 3) {
            snprintf(errbuf, errsz, "line %d: expected 'STATE SYSCALL allow|deny [-> NEXT]'",
                      lineno);
            fclose(f);
            return -1;
        }

        int state = policy_state_index(p, tok[0]);
        if (state < 0) {
            snprintf(errbuf, errsz, "line %d: too many states (max %d)",
                     lineno, POLICY_MAX_STATES);
            fclose(f);
            return -1;
        }

        int nr = policy_name_to_nr(tok[1]);
        if (nr == -1) {
            snprintf(errbuf, errsz, "line %d: unknown syscall '%s'", lineno, tok[1]);
            fclose(f);
            return -1;
        }

        enum policy_action action;
        if (strcmp(tok[2], "allow") == 0)
            action = POLICY_ALLOW;
        else if (strcmp(tok[2], "deny") == 0)
            action = POLICY_DENY;
        else {
            snprintf(errbuf, errsz, "line %d: action must be 'allow' or 'deny', got '%s'",
                     lineno, tok[2]);
            fclose(f);
            return -1;
        }

        int next_state = -1;
        if (n >= 5 && strcmp(tok[3], "->") == 0) {
            if (action == POLICY_DENY) {
                snprintf(errbuf, errsz, "line %d: 'deny' rules cannot have '-> NEXT'", lineno);
                fclose(f);
                return -1;
            }
            next_state = policy_state_index(p, tok[4]);
            if (next_state < 0) {
                snprintf(errbuf, errsz, "line %d: too many states (max %d)",
                         lineno, POLICY_MAX_STATES);
                fclose(f);
                return -1;
            }
        } else if (n >= 4) {
            snprintf(errbuf, errsz, "line %d: expected '-> NEXT' after allow/deny", lineno);
            fclose(f);
            return -1;
        }

        if (p->n_rules >= POLICY_MAX_RULES) {
            snprintf(errbuf, errsz, "too many rules (max %d)", POLICY_MAX_RULES);
            fclose(f);
            return -1;
        }
        p->rules[p->n_rules].state = state;
        p->rules[p->n_rules].nr = nr;
        p->rules[p->n_rules].action = action;
        p->rules[p->n_rules].next_state = next_state;
        p->n_rules++;
        policy_mark_syscall_used(p, nr);
    }
    fclose(f);

    if (p->n_states == 0) {
        snprintf(errbuf, errsz, "policy file declared no states (need at least 'state INIT')");
        return -1;
    }
    return 0;
}

/* Append one rule directly (used by learn mode, below, to build a
 * policy from observed behavior rather than parsing text). Returns
 * 0 on success, -1 if the rule table is full. */
static inline int policy_add_rule(struct policy *p, int state, int nr,
                                   enum policy_action action, int next_state)
{
    if (p->n_rules >= POLICY_MAX_RULES)
        return -1;
    p->rules[p->n_rules].state = state;
    p->rules[p->n_rules].nr = nr;
    p->rules[p->n_rules].action = action;
    p->rules[p->n_rules].next_state = next_state;
    p->n_rules++;
    policy_mark_syscall_used(p, nr);
    return 0;
}

/* Write a policy back out in the same text format policy_load()
 * reads — used by learn mode to save what it observed. Returns 0 on
 * success, -1 if the file couldn't be opened. */
static inline int policy_save(const struct policy *p, const char *path)
{
    FILE *f = fopen(path, "w");
    int i;

    if (!f)
        return -1;

    fprintf(f, "# Auto-generated by `supervisor --learn` — REVIEW BEFORE USE.\n");
    fprintf(f, "#\n");
    fprintf(f, "# This is a DRAFT, not a verified policy:\n");
    fprintf(f, "#   - It only allows what was actually observed during the\n");
    fprintf(f, "#     traced run. Anything legitimate that run didn't exercise\n");
    fprintf(f, "#     is missing here, and will be DENIED until you add it.\n");
    fprintf(f, "#   - Conversely, if the traced run itself did something it\n");
    fprintf(f, "#     shouldn't have, this file will wrongly ALLOW it — a\n");
    fprintf(f, "#     learned policy reflects what happened, not what SHOULD\n");
    fprintf(f, "#     be allowed. Read it before trusting it.\n");
    fprintf(f, "#   - States are named using known TCP-server-lifecycle\n");
    fprintf(f, "#     semantics (bind()->BOUND, listen()->LISTENING,\n");
    fprintf(f, "#     execve()/execveat()->INIT), not inferred generically.\n");
    fprintf(f, "#\n\n");

    for (i = 0; i < p->n_states; i++)
        fprintf(f, "state %s\n", p->state_names[i]);
    fprintf(f, "\n");

    for (i = 0; i < p->n_rules; i++) {
        const struct policy_rule *r = &p->rules[i];

        fprintf(f, "%-10s %-9s %s", p->state_names[r->state], sysname(r->nr),
                r->action == POLICY_ALLOW ? "allow" : "deny");
        if (r->action == POLICY_ALLOW && r->next_state >= 0 && r->next_state != r->state)
            fprintf(f, " -> %s", p->state_names[r->next_state]);
        fprintf(f, "\n");
    }
    fclose(f);
    return 0;
}

/* Returns 1 if a rule matched (fills *action, *next_state), 0 if no
 * rule exists for this (state, nr) — caller treats that as deny. */
static inline int policy_lookup(const struct policy *p, int state, int nr,
                                 enum policy_action *action, int *next_state)
{
    int i;

    for (i = 0; i < p->n_rules; i++) {
        if (p->rules[i].state == state && p->rules[i].nr == nr) {
            *action = p->rules[i].action;
            *next_state = p->rules[i].next_state;
            return 1;
        }
    }
    return 0;
}

static inline const char *policy_state_name(const struct policy *p, int idx)
{
    if (idx < 0 || idx >= p->n_states)
        return "?";
    return p->state_names[idx];
}

/* The default policy — expresses exactly the behavior supervisor.c
 * used to have hardcoded, now as data. Loaded when no --policy flag
 * is given, so the existing demos/tests/bench keep working unchanged. */
static inline void policy_load_builtin(struct policy *p)
{
    memset(p, 0, sizeof(*p));

    int INIT = policy_state_index(p, "INIT");
    int BOUND = policy_state_index(p, "BOUND");
    int LISTENING = policy_state_index(p, "LISTENING");
    p->initial_state = INIT;

#define RULE(st, sys, act, nxt) do { \
        p->rules[p->n_rules].state = (st); \
        p->rules[p->n_rules].nr = policy_name_to_nr(sys); \
        p->rules[p->n_rules].action = (act); \
        p->rules[p->n_rules].next_state = (nxt); \
        p->n_rules++; \
        policy_mark_syscall_used(p, policy_name_to_nr(sys)); \
    } while (0)

    RULE(INIT,      "socket",   POLICY_ALLOW, -1);
    RULE(INIT,      "bind",     POLICY_ALLOW, BOUND);
    RULE(INIT,      "connect",  POLICY_ALLOW, -1);
    RULE(INIT,      "execve",   POLICY_ALLOW, INIT);
    RULE(INIT,      "execveat", POLICY_ALLOW, INIT);

    RULE(BOUND,     "socket",   POLICY_ALLOW, -1);
    RULE(BOUND,     "bind",     POLICY_ALLOW, -1);
    RULE(BOUND,     "listen",   POLICY_ALLOW, LISTENING);
    RULE(BOUND,     "connect",  POLICY_ALLOW, -1);
    RULE(BOUND,     "execve",   POLICY_ALLOW, INIT);
    RULE(BOUND,     "execveat", POLICY_ALLOW, INIT);

    RULE(LISTENING, "socket",   POLICY_ALLOW, -1);
    RULE(LISTENING, "bind",     POLICY_ALLOW, -1);
    RULE(LISTENING, "listen",   POLICY_ALLOW, -1);
    RULE(LISTENING, "accept",   POLICY_ALLOW, -1);
    RULE(LISTENING, "accept4",  POLICY_ALLOW, -1);
    RULE(LISTENING, "connect",  POLICY_DENY, -1);
    RULE(LISTENING, "execve",   POLICY_DENY, -1);
    RULE(LISTENING, "execveat", POLICY_DENY, -1);
    /* sendto's actual legality is argument-aware (destination given
     * or not) and is decided by supervisor.c BEFORE this table is
     * even consulted — see the top-of-file comment. This line exists
     * only to get __NR_sendto into the trapped-syscall list; the
     * 'deny' value here is never actually used for the decision. */
    RULE(LISTENING, "sendto",   POLICY_DENY, -1);
    /* sendmsg, unlike sendto, IS governed by this table normally —
     * flatly denied at LISTENING, no argument check (see top of
     * file for why that's the deliberately conservative choice). */
    RULE(LISTENING, "sendmsg",  POLICY_DENY, -1);

#undef RULE
}

#endif /* POLICY_H */
