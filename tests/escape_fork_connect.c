/*
 * Escape test: a process fork()'d FROM the listening server, which
 * itself never calls listen(), then calls connect(). Under naive
 * per-process tracking this child looks like a brand new, innocent
 * process ("it never listened, so connect is fine for it").
 *
 * Expected result:
 *   no sandbox: succeeds
 *   namelist:   succeeds — THIS is the point of the bake-off
 *   supervisor: DENY + SIGKILL — the child inherits LISTENING from
 *               its real OS parent (taint propagation, see
 *               find_or_create() in supervisor.c)
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in me;
    int yes = 1;

    memset(&me, 0, sizeof(me));
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = inet_addr("127.0.0.1");
    me.sin_port = htons(18080);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    bind(lfd, (struct sockaddr *)&me, sizeof(me));
    listen(lfd, 1);
    printf("escape_fork_connect: listening, now forking a child that will connect()\n");
    fflush(stdout);

    pid_t p = fork();
    if (p == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in dest;

        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr("127.0.0.1");
        dest.sin_port = htons(9);
        int r = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
        printf("escape_fork_connect: child's connect() returned %d — if you\n"
               "see this, the child was not blocked\n", r);
        return 0;
    }
    waitpid(p, NULL, 0);
    return 0;
}
