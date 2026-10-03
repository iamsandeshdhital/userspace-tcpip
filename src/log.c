#include "log.h"
#include "clock.h"

#include <stdarg.h>
#include <stdio.h>

static log_level_t g_level = LOG_LEVEL_INFO;
static uint64_t    g_start_ms;

void log_init(void)
{
    g_start_ms = mono_ms();
}

void log_set_level(log_level_t level) { g_level = level; }
log_level_t log_get_level(void)       { return g_level; }

uint64_t log_uptime_ms(void)
{
    return mono_ms() - g_start_ms;
}

static const char *level_tag(log_level_t l)
{
    switch (l) {
    case LOG_LEVEL_ERROR: return "ERR ";
    case LOG_LEVEL_WARN:  return "WARN";
    case LOG_LEVEL_INFO:  return "INFO";
    case LOG_LEVEL_DEBUG: return "DBG ";
    case LOG_LEVEL_TRACE: return "TRC ";
    default:              return "??? ";
    }
}

void log_write(log_level_t level, const char *fmt, ...)
{
    if (level > g_level)
        return;

    uint64_t up = log_uptime_ms();
    fprintf(stderr, "[%7llu.%03llu] %s ",
            (unsigned long long)(up / 1000), (unsigned long long)(up % 1000),
            level_tag(level));

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}

void log_hexdump(log_level_t level, const char *prefix,
                 const void *data, size_t len)
{
    if (level > g_level)
        return;

    const uint8_t *p = (const uint8_t *)data;
    uint64_t up = log_uptime_ms();
    fprintf(stderr, "[%7llu.%03llu] %s %s (%zu bytes)\n",
            (unsigned long long)(up / 1000), (unsigned long long)(up % 1000),
            level_tag(level), prefix, len);

    for (size_t off = 0; off < len; off += 16) {
        fprintf(stderr, "    %04zx  ", off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < len)
                fprintf(stderr, "%02x ", p[off + i]);
            else
                fputs("   ", stderr);
            if (i == 7)
                fputs(" ", stderr);
        }
        fprintf(stderr, " |");
        for (size_t i = 0; i < 16 && off + i < len; i++) {
            uint8_t c = p[off + i];
            fputc((c >= 0x20 && c < 0x7f) ? c : '.', stderr);
        }
        fputs("|\n", stderr);
    }
}

const char *ip_str(uint32_t net_ip, char *buf, size_t buflen)
{
    if (inet_ntop(AF_INET, &net_ip, buf, (socklen_t)buflen) == NULL)
        snprintf(buf, buflen, "?.?.?.?");
    return buf;
}

const char *endpoint_str(uint32_t net_ip, uint16_t port, char *buf, size_t buflen)
{
    char ip[INET_ADDRSTRLEN];
    snprintf(buf, buflen, "%s:%u", ip_str(net_ip, ip, sizeof ip), port);
    return buf;
}