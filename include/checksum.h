/*
 * checksum.h -- the Internet checksum (RFC 1071).
 *
 * This is the single most common source of bugs in hand-rolled stacks, so the
 * implementation is deliberately explicit:
 *
 *   1. Sum the data as an array of 16-bit words, in *network* byte order.
 *      An odd trailing byte is padded on the right with a zero byte.
 *   2. Fold the 32-bit sum's carries back down to 16 bits.
 *   3. Complement.
 *
 * Verification is the same computation including the already-present checksum
 * field: for a valid packet the result is 0.
 */
#ifndef USSTACK_CHECKSUM_H
#define USSTACK_CHECKSUM_H

#include "common.h"

/* Incremental checksum: feed chunks in any order, then finish. */
typedef struct {
    uint32_t sum;   /* un-folded accumulator */
    uint8_t  odd;   /* pending odd trailing byte */
} csum_state_t;

void     csum_init(csum_state_t *st);
void     csum_add(csum_state_t *st, const void *data, size_t len);
/* Returns the final (complemented) 16-bit checksum in network byte order. */
uint16_t csum_final(csum_state_t *st);

/* One-shot helpers. */
uint16_t csum16(const void *data, size_t len);

/*
 * Verify an Internet checksum.
 *
 * Returns true when the stored checksum is correct, i.e. when summing the
 * buffer -- checksum field included -- folds to 0xFFFF.  `csum_off` is the
 * byte offset of the checksum field, used only for diagnostics.
 */
bool csum16_verify(const void *data, size_t len, size_t csum_off);

#endif /* USSTACK_CHECKSUM_H */