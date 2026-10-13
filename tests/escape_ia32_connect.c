/*
 * Escape test: connect() after listen(), issued through the ia32
 * (32-bit) syscall ABI via `int $0x80`, instead of the normal
 * 64-bit `connect()` libc call.
 *
 * Why this matters: on an x86-64 kernel, the SAME semantic call
 * ("connect this socket to that address") has a DIFFERENT syscall
 * NUMBER depending on which ABI issued it. A seccomp filter that
 * only compares seccomp_data.nr against the native __NR_connect
 * value never sees this call under its real identity — it falls
 * through to the filter's default action. This is why common.h's
 * install_filter() checks seccomp_data.arch == AUDIT_ARCH_X86_64
 * FIRST and kills the process outright on any other ABI, rather
 * than trying to enumerate every alternate syscall number.
 *
 * Expected result:
 *   no sandbox / namelist / supervisor: all KILL the process
 *   (signal 31 / SIGSYS), because common.h's arch check applies
 *   identically regardless of which program installs the filter.
 *   This attack is caught by the ARCHITECTURE check, not by the
 *   stateful protocol check — it is here to prove the arch check
 *   works, not to distinguish namelist from supervisor.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static struct sockaddr_in dest; /* static: needs a stable 32-bit-reachable address */
static unsigned int sc_args[3];

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
    printf("escape_ia32_connect: listening, now attempting ia32-ABI connect()\n");
    fflush(stdout);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest.sin_port = htons(9); /* discard port: nothing is listening, refusal is fine */

    sc_args[0] = (unsigned int)fd;
    sc_args[1] = (unsigned int)(unsigned long)&dest;
    sc_args[2] = sizeof(dest);

    long ret;
    /* ia32 socketcall(SYS_CONNECT=3, args) via int $0x80.
     * eax=102 (socketcall), ebx=3 (SYS_CONNECT), ecx=&sc_args. */
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "0"(102), "b"(3), "c"((unsigned int)(unsigned long)sc_args)
        : "memory");

    printf("escape_ia32_connect: ia32 connect() returned %ld — if you see this,\n"
           "the arch check did NOT stop the call (-111/ECONNREFUSED means it\n"
           "reached the kernel, i.e. the bypass worked)\n", ret);
    return 0;
}
