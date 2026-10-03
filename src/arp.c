#include "arp.h"
#include "clock.h"

#include <stdio.h>

void arp_init(arp_cache_t *c)
{
    memset(c, 0, sizeof *c);
}

void arp_flush(arp_cache_t *c)
{
    memset(c->table, 0, sizeof c->table);
}

void arp_insert(arp_cache_t *c, uint32_t ip, const uint8_t mac[6])
{
    /* Refresh an existing entry in place. */
    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        if (c->table[i].valid && c->table[i].ip == ip) {
            memcpy(c->table[i].mac, mac, 6);
            c->table[i].updated_ms = mono_ms();
            return;
        }
    }

    /* Otherwise take a free slot, else evict the oldest. */
    size_t victim = ARP_TABLE_SIZE;
    uint64_t oldest = UINT64_MAX;
    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        if (!c->table[i].valid) { victim = i; break; }
        if (c->table[i].updated_ms < oldest) {
            oldest = c->table[i].updated_ms;
            victim = i;
        }
    }

    c->table[victim].ip = ip;
    memcpy(c->table[victim].mac, mac, 6);
    c->table[victim].updated_ms = mono_ms();
    c->table[victim].valid = true;
}

bool arp_lookup(arp_cache_t *c, uint32_t ip, uint8_t mac_out[6])
{
    c->lookups++;
    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        if (!c->table[i].valid || c->table[i].ip != ip)
            continue;
        if (mono_ms() - c->table[i].updated_ms > ARP_ENTRY_TIMEOUT_MS) {
            c->table[i].valid = false;   /* stale entry */
            continue;
        }
        memcpy(mac_out, c->table[i].mac, 6);
        c->hits++;
        return true;
    }
    c->misses++;
    return false;
}

size_t arp_count(const arp_cache_t *c)
{
    size_t n = 0;
    for (size_t i = 0; i < ARP_TABLE_SIZE; i++)
        if (c->table[i].valid)
            n++;
    return n;
}

const arp_entry_t *arp_get(const arp_cache_t *c, size_t idx)
{
    if (idx >= ARP_TABLE_SIZE || !c->table[idx].valid)
        return NULL;
    return &c->table[idx];
}