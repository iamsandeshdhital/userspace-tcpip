#include "clock.h"

#include <errno.h>

uint64_t mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

void msleep(uint64_t ms)
{
    struct timespec req = {
        .tv_sec  = (time_t)(ms / 1000),
        .tv_nsec = (long)((ms % 1000) * 1000000),
    };
    while (nanosleep(&req, &req) == -1 && errno == EINTR)
        ;
}