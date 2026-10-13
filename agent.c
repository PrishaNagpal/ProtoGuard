/*
 * Phase 1 — good network agent.
 *
 * This is a tiny TCP echo server. It follows the legal protocol:
 *   socket -> bind -> listen -> accept -> read -> write -> close
 *
 * Later the supervisor will allow exactly this sequence.
 *
 * Run:  ./agent
 * Talk: nc 127.0.0.1 18080
 * Trace: strace -f -o agent.strace ./agent
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
    int listen_fd, client_fd;
    struct sockaddr_in addr;
    char buf[256];
    ssize_t n;

    /* 1. Ask the kernel for a TCP socket. Returns a file descriptor (an int). */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        die("socket");

    /* Reuse the port quickly if you restart the program. */
    int yes = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        die("setsockopt");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(PORT);

    /* 2. Attach the socket to 127.0.0.1:18080. */
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind");

    /* 3. Mark it as a listening socket. After this, a real server
     *    should only accept clients — not dial out (connect) or exec a shell. */
    if (listen(listen_fd, BACKLOG) < 0)
        die("listen");

    printf("agent: listening on 127.0.0.1:%d (waiting for one client)\n", PORT);
    fflush(stdout);

    /* 4. Block until a client connects. Returns a NEW fd for that client. */
    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0)
        die("accept");

    printf("agent: client connected\n");

    /* 5. Read one chunk, write it back (echo). */
    n = read(client_fd, buf, sizeof(buf) - 1);
    if (n < 0)
        die("read");
    if (n == 0) {
        printf("agent: client closed without sending data\n");
    } else {
        buf[n] = '\0';
        printf("agent: got %zd bytes, echoing\n", n);
        if (write(client_fd, buf, (size_t)n) < 0)
            die("write");
    }

    /* 6. Close both sockets and exit. */
    close(client_fd);
    close(listen_fd);
    printf("agent: done\n");
    return 0;
}
