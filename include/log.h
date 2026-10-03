/*
 * log.h -- tiny levelled logger plus a packet hexdump helper.
 */
#ifndef USSTACK_LOG_H
#define USSTACK_LOG_H

#include "common.h"

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN  = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_TRACE = 4,
} log_level_t;

void log_set_level(log_level_t level);
log_level_t log_get_level(void);

/* Starts the uptime clock used in log prefixes. */
void log_init(void);
uint64_t log_uptime_ms(void);

void log_write(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_error(...) log_write(LOG_LEVEL_ERROR, __VA_ARGS__)
#define log_warn(...)  log_write(LOG_LEVEL_WARN,  __VA_ARGS__)
#define log_info(...)  log_write(LOG_LEVEL_INFO,  __VA_ARGS__)
#define log_debug(...) log_write(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define log_trace(...) log_write(LOG_LEVEL_TRACE, __VA_ARGS__)

/* Hexdump `len` bytes of `data` with the given prefix, honouring log level. */
void log_hexdump(log_level_t level, const char *prefix,
                 const void *data, size_t len);

/* Pretty-print IPv4 addresses.  `buf` must hold at least INET_ADDRSTRLEN. */
const char *ip_str(uint32_t net_order_ip, char *buf, size_t buflen);
/* "a.b.c.d:port" */
const char *endpoint_str(uint32_t net_order_ip, uint16_t host_port,
                         char *buf, size_t buflen);

#endif /* USSTACK_LOG_H */