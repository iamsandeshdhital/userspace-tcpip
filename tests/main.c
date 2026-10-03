/*
 * main.c -- test runner.
 *
 * The suite runs the whole protocol stack in memory, with no TUN device and no
 * privileges.  Time is virtual, so the retransmission tests are deterministic
 * rather than dependent on how fast the machine happens to be.
 */
#include "harness.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    const char *name;
    void (*fn)(void);
} test_t;

static const test_t g_tests[] = {
    { "checksum",        test_checksum },
    { "ringbuf",         test_ringbuf },
    { "ip",              test_ip },
    { "arp",             test_arp },
    { "icmp",            test_icmp },
    { "tcp-header",      test_tcp_header },
    { "tcp-handshake",   test_tcp_handshake },
    { "tcp-teardown",    test_tcp_teardown },
    { "tcp-out-of-order",test_tcp_out_of_order },
    { "tcp-retransmit",  test_tcp_retransmit },
    { "tcp-window",      test_tcp_window },
    { "tcp-loopback",    test_tcp_loopback },
};

int main(int argc, char **argv)
{
    /*
     * Warnings from the library are expected noise in a test run: many
     * tests deliberately feed the stack corrupt or hostile input.
     */
    log_set_level(LOG_LEVEL_ERROR);

    const char *filter = (argc > 1) ? argv[1] : NULL;
    int ran = 0, failed_tests = 0;
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);

    printf("userspace-tcpip test suite\n");
    printf("==========================\n\n");

    for (size_t i = 0; i < sizeof g_tests / sizeof g_tests[0]; i++) {
        if (filter && !strstr(g_tests[i].name, filter))
            continue;

        g_current_test = g_tests[i].name;
        int before = g_test_failures;
        int asserts_before = g_test_assertions;

        printf("%-18s ", g_tests[i].name);
        fflush(stdout);

        g_tests[i].fn();

        int new_failures = g_test_failures - before;
        int new_asserts = g_test_assertions - asserts_before;

        ran++;
        if (new_failures) {
            failed_tests++;
            printf("FAIL  (%d/%d checks failed)\n", new_failures, new_asserts);
        } else {
            printf("ok    (%d checks)\n", new_asserts);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (double)(t1.tv_sec - t0.tv_sec) +
                  (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    printf("\n%d test%s, %d check%s, %d failure%s in %.2fs\n",
           ran, ran == 1 ? "" : "s",
           g_test_assertions, g_test_assertions == 1 ? "" : "s",
           g_test_failures, g_test_failures == 1 ? "" : "s",
           secs);

    if (failed_tests)
        printf("\nRESULT: FAIL\n");
    else
        printf("\nRESULT: PASS\n");

    return failed_tests ? 1 : 0;
}