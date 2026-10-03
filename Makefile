# Makefile -- userspace-tcpip
#
# Two binaries are produced:
#   usstack        the stack plus its console, requires Linux and root
#   usstack-tests  the protocol test suite, which needs neither
#
# Useful targets:
#   make            build both
#   make test       build and run the test suite
#   make asan       rebuild the tests with AddressSanitizer and UBSan
#   make run        build and launch the stack (needs root)
#   make clean

CC      ?= gcc
CSTD    ?= -std=c11

WARNINGS = -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wpointer-arith -Wwrite-strings \
           -Wno-unused-parameter

OPT      ?= -O2 -g
CFLAGS   += $(CSTD) $(WARNINGS) $(OPT) -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS  +=

# The protocol core is portable and is what the tests exercise.
CORE_SRC = src/checksum.c src/ringbuf.c src/ethernet.c src/arp.c \
           src/ip.c src/icmp.c src/tcp.c src/tcp_socket.c src/net.c \
           src/log.c src/clock.c src/ping.c

# The device layer and the console are Linux-only.
LINUX_SRC = src/tun.c src/main.c

TEST_SRC = tests/main.c tests/harness.c \
           tests/test_checksum.c tests/test_ringbuf.c tests/test_ip.c \
           tests/test_arp.c tests/test_icmp.c tests/test_tcp_header.c \
           tests/test_tcp_handshake.c tests/test_tcp_teardown.c \
           tests/test_tcp_out_of_order.c tests/test_tcp_retransmit.c \
           tests/test_tcp_window.c tests/test_tcp_loopback.c

CORE_OBJ = $(CORE_SRC:.c=.o)
LINUX_OBJ = $(LINUX_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)

BIN        = usstack
TEST_BIN   = usstack-tests

# Warnings are reported but not fatal by default.  Turn them into errors with
# `make test WERROR=1` once the tree is warning-clean; enabling it immediately
# would bury the first real build failure under formatting noise.
ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

.PHONY: all test asan run clean help

all: $(BIN) $(TEST_BIN)

$(BIN): $(CORE_OBJ) $(LINUX_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_BIN): $(CORE_OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TEST_BIN)
	./$(TEST_BIN)

asan:
	$(MAKE) clean
	$(MAKE) test OPT="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	                 LDFLAGS="-fsanitize=address,undefined"

run: $(BIN)
	sudo ./$(BIN) $(ARGS)

clean:
	rm -f $(CORE_OBJ) $(LINUX_OBJ) $(TEST_OBJ) $(BIN) $(TEST_BIN)

help:
	@sed -n '1,12p' Makefile

-include $(CORE_OBJ:.o=.d) $(LINUX_OBJ:.o=.d) $(TEST_OBJ:.o=.d)
CFLAGS += -MMD -MP