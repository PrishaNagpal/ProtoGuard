/*
 * Escape test: UDP sendto() to an arbitrary address after listen(),
 * with no connect() call at all — data exfiltration without ever
 * touching the syscall the original filter watched for.
 *
 * Expected result:
 *   no sandbox: succeeds
 *   namelist:   succeeds — THIS is the point of the bake-off
 *   supervisor: DENY + SIGKILL (sendto with a non-NULL destination
 *               address is treated the same as an outbound connect)
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
    printf("escape_sendto: listening, now attempting UDP sendto()\n");
    fflush(stdout);

    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_port = htons(9);

    long r = sendto(ufd, "x", 1, 0, (struct sockaddr *)&dest, sizeof(dest));

    printf("escape_sendto: sendto() returned %ld — if you see this, it was not blocked\n", r);
    return 0;
}
