/*
 * ui/demo_prelisten.c - a server that dials OUT before it starts listening.
 *
 * Used by the dashboard to show that a policy is just a text file:
 *   echo.policy                 -> connect() in INIT is ALLOWED  (program finishes)
 *   strict-no-outbound.policy   -> connect() in INIT is DENIED   (program is killed)
 *
 * It connects to 127.0.0.1:9 (nothing listens there, so it fails fast).
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    struct sockaddr_in t;
    memset(&t, 0, sizeof t);
    t.sin_family = AF_INET;
    t.sin_port = htons(9);
    inet_pton(AF_INET, "127.0.0.1", &t.sin_addr);

    int c = socket(AF_INET, SOCK_STREAM, 0);
    printf("prelisten: calling connect() BEFORE listen()\n");
    fflush(stdout);
    connect(c, (struct sockaddr *)&t, sizeof t);
    printf("prelisten: connect() was allowed to run, now listening\n");
    fflush(stdout);
    close(c);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(18081);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    bind(s, (struct sockaddr *)&a, sizeof a);
    listen(s, 1);
    printf("prelisten: listening, exiting cleanly\n");
    fflush(stdout);
    return 0;
}
