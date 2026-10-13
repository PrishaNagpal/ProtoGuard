CC = gcc
CFLAGS = -Wall -Wextra -O0 -g

.PHONY: all clean traces bench

all: agent attack attack_exec supervisor namelist

agent: agent.c
	$(CC) $(CFLAGS) -o agent agent.c

attack: attack.c
	$(CC) $(CFLAGS) -o attack attack.c

attack_exec: attack_exec.c
	$(CC) $(CFLAGS) -o attack_exec attack_exec.c

supervisor: supervisor.c common.h policy.h
	$(CC) $(CFLAGS) -o supervisor supervisor.c

namelist: namelist.c common.h
	$(CC) $(CFLAGS) -o namelist namelist.c

# Good path: start ./agent, then in another terminal: echo hi | nc 127.0.0.1 18080
# Then inspect agent.strace for socket/bind/listen/accept/read/write/close
traces: agent attack
	strace -f -o attack.strace ./attack
	@echo "wrote attack.strace — search for listen and connect"

bench: agent supervisor
	./phase8_bench.sh 40

escape-tests: agent attack attack_exec supervisor namelist
	./run_escape_tests.sh

clean:
	rm -f agent attack attack_exec supervisor namelist agent.strace attack.strace
