/*
 * Escape test: UDP sendmsg() with a destination (msg_name) after
 * listen() — sendmsg() was previously untrappable at all (trapping
 * it deadlocked the old sendmsg()-based fd handoff). The handoff was
 * redesigned to use pidfd_getfd() instead (see common.h), so
 * sendmsg() is now trapped and enforced — denied outright at
 * LISTENING, with no argument inspection (see policy.h for why that
 * is a deliberately conservative choice, unlike sendto()).
 *
 * Expected result:
 *   no sandbox: succeeds
 *   namelist:   succeeds — the point of the bake-off
 *   supervisor: DENY + SIGKILL
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
    printf("escape_sendmsg: listening, now attempting UDP sendmsg()\n");
    fflush(stdout);

    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_port = htons(9);

    struct iovec iov = { .iov_base = "x", .iov_len = 1 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dest;
    msg.msg_namelen = sizeof(dest);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    long r = sendmsg(ufd, &msg, 0);

    printf("escape_sendmsg: sendmsg() returned %ld — if you see this, it was not blocked\n", r);
    return 0;
}
