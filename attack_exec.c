/*
 * Second attack: listen, then execve("/bin/true").
 * Same protocol rule as connect-after-listen — different syscall.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 18080

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

int main(void)
{
    int listen_fd;
    struct sockaddr_in addr;
    char *argv_true[] = { "/bin/true", NULL };

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
    if (listen(listen_fd, 1) < 0)
        die("listen");

    printf("attack_exec: listening — now doing an illegal execve(/bin/true)\n");
    fflush(stdout);

    execve("/bin/true", argv_true, NULL);
    die("execve");
}
