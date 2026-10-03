/*
 * clock.h -- monotonic millisecond clock and timer helpers.
 *
 * TCP is entirely driven by timers, so the stack never calls time() directly:
 * it asks the clock.  That indirection is what makes the retransmission tests
 * deterministic -- tests advance time by fiat instead of sleeping.
 */
#ifndef USSTACK_CLOCK_H
#define USSTACK_CLOCK_H

#include "common.h"
#include <time.h>

/* Wall-independent monotonic milliseconds since an arbitrary epoch. */
uint64_t mono_ms(void);

/* Sleep for ms milliseconds. */
void msleep(uint64_t ms);

/* clamp helper: min(a, INT32_MAX) */
static inline int clamp_timeout(int ms)
{
    return ms < 0 ? 0 : ms;
}

#endif /* USSTACK_CLOCK_H */