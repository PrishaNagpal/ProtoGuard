/*
 * Escape test: execveat() after listen(), instead of execve().
 *
 * Why this matters: the original filter trapped __NR_execve but not
 * __NR_execveat, a separate syscall with the same effect (replace
 * this process image), commonly reached via fexecve()/some libc
 * exec paths, or callable directly as here.
 *
 * Expected result:
 *   no sandbox: succeeds — the process becomes /bin/true
 *   namelist:   succeeds (name-only; execveat not even on its old
 *               list) — THIS is the point of the bake-off
 *   supervisor: DENY + SIGKILL
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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
    printf("escape_execveat: listening, now attempting execveat(/bin/true)\n");
    fflush(stdout);

    int fd = open("/bin/true", O_RDONLY);
    char *av[] = { "/bin/true", NULL };

    syscall(SYS_execveat, fd, "", av, NULL, AT_EMPTY_PATH);
    printf("escape_execveat: execveat failed — if you see this, it was blocked\n");
    return 1;
}
