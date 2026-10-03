/*
 * checksum.c -- Internet checksum, RFC 1071.
 *
 * The checksum is the one's complement of the one's complement sum of the
 * 16-bit words of the header (or header + pseudo-header).  Properties that
 * matter in practice:
 *
 *   - Addition is commutative and associative, so it can be done incrementally
 *     across a pseudo-header and a payload held in different buffers.
 *   - An odd-length buffer is treated as though a zero byte were appended.
 *   - Verification re-runs the sum *including* the stored checksum; a correct
 *     packet sums to 0xFFFF before complementing, i.e. to 0 after.
 *   - A checksum of 0 must be transmitted as 0xFFFF, because 0 means
 *     "no checksum" in IPv4.  csum_final() applies that substitution.
 */
#include "checksum.h"
#include "log.h"

void csum_init(csum_state_t *st)
{
    st->sum = 0;
    st->odd = 0;
}

void csum_add(csum_state_t *st, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = st->sum;

    /*
     * If a previous call left an odd byte behind, it becomes the high half of
     * the next 16-bit word and the new data supplies the low half.
     */
    if (st->odd && len) {
        sum += (uint32_t)p[0] << 8;
        p++;
        len--;
        st->odd = 0;
    }

    size_t words = len / 2;
    for (size_t i = 0; i < words; i++) {
        /* Explicit byte assembly: works regardless of host endianness and
         * buffer alignment.  Compilers turn this into a single load. */
        sum += (uint32_t)p[2 * i] << 8;
        sum += p[2 * i + 1];
    }

    /* Carry folding keeps the accumulator from overflowing. */
    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);

    st->sum = sum;

    if (len & 1) {
        /* Trailing odd byte: pad on the right with zero. */
        st->odd = p[len - 1];
    }
}

uint16_t csum_final(csum_state_t *st)
{
    uint32_t sum = st->sum;

    if (st->odd)
        sum += (uint32_t)st->odd << 8;

    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);

    uint16_t csum = (uint16_t)(~sum & 0xFFFFu);
    /* 0x0000 means "no checksum" in IPv4; 0xFFFF means the same as zero. */
    if (csum == 0x0000)
        csum = 0xFFFF;

    st->sum = 0;
    st->odd = 0;
    return csum;
}

uint16_t csum16(const void *data, size_t len)
{
    csum_state_t st;
    csum_init(&st);
    csum_add(&st, data, len);
    return csum_final(&st);
}

bool csum16_verify(const void *data, size_t len, size_t csum_off)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    size_t   i = 0;

    for (; i + 1 < len; i += 2)
        sum += ((uint32_t)p[i] << 8) | p[i + 1];

    if (i < len)
        sum += (uint32_t)p[i] << 8;

    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);

    uint16_t folded = (uint16_t)sum;
    (void)csum_off;

    /* A valid packet folds to 0xFFFF (equivalently 0 after complement). */
    return folded == 0xFFFF;
}