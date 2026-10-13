/*
 * Phase 1 — bad agent (same as agent.c until listen, then it cheats).
 *
 * After listen() it opens a NEW socket and calls connect().
 * A name-based seccomp filter that allows "connect" would still permit this.
 * Our later supervisor will kill it because connect after listen is illegal.
 *
 * Run:  ./attack
 * Trace: strace -f -o attack.strace ./attack
 *
 * connect() targets 127.0.0.1:9 so it fails quickly (nothing listens there).
 * We only need the syscall to APPEAR in strace, not to succeed.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 18080
#define BACKLOG 1

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

int main(void)
{
    int listen_fd;
    struct sockaddr_in addr;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        die("socket");

    int yes = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        die("setsockopt");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind");

    if (listen(listen_fd, BACKLOG) < 0)
        die("listen");

    printf("attack: listening — now doing an illegal connect()\n");
    fflush(stdout);

    /* ILLEGAL after listen: open an outgoing connection. */
    int out_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (out_fd < 0)
        die("socket(out)");

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_port = htons(9);

    if (connect(out_fd, (struct sockaddr *)&dest, sizeof(dest)) < 0)
        perror("attack: connect (expected to fail; we only need the syscall)");
    else
        printf("attack: connect unexpectedly succeeded\n");

    close(out_fd);
    close(listen_fd);
    return 0;
}
