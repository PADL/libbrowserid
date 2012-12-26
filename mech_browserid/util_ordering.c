/*
 * Copyright (c) 2011, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Functions to check sequence numbers for replay and sequencing
 */

#include "gssapiP_bid.h"

#define QUEUE_LENGTH 20

typedef struct _queue {
    int do_replay;
    int do_sequence;
    int start;
    int length;
    uint64_t firstnum;
    /* Stored as deltas from firstnum.  This way, the high bit won't
       overflow unless we've actually gone through 2**n messages, or
       gotten something *way* out of sequence.  */
    uint64_t elem[QUEUE_LENGTH];
    /* All ones for 64-bit sequence numbers; 32 ones for 32-bit
       sequence numbers.  */
    uint64_t mask;
} queue;

/* rep invariant:
 *  - the queue is a circular queue.  The first element (q->elem[q->start])
 * is the oldest.  The last element is the newest.
 */

#define QSIZE(q) (sizeof((q)->elem)/sizeof((q)->elem[0]))
#define QELEM(q,i) ((q)->elem[(i)%QSIZE(q)])

static void
queue_insert(queue *q, int after, uint64_t seqnum)
{
    /* insert.  this is not the fastest way, but it's easy, and it's
       optimized for insert at end, which is the common case */
    int i;

    /* common case: at end, after == q->start+q->length-1 */

    /* move all the elements (after,last] up one slot */

    for (i = q->start + q->length - 1; i > after; i--)
        QELEM(q,i+1) = QELEM(q,i);

    /* fill in slot after+1 */

    QELEM(q,after+1) = seqnum;

    /* Either increase the length by one, or move the starting point up
       one (deleting the first element, which got bashed above), as
       appropriate. */

    if (q->length == QSIZE(q)) {
        q->start++;
        if (q->start == QSIZE(q))
            q->start = 0;
    } else {
        q->length++;
    }
}

OM_uint32
sequenceInit(OM_uint32 *minor,
             void **vqueue,
             uint64_t seqnum,
             int do_replay,
             int do_sequence,
             int wide_nums)
{
    queue *q;

    q = (queue *)GSSBID_CALLOC(1, sizeof(queue));
    if (q == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    q->do_replay = do_replay;
    q->do_sequence = do_sequence;
    q->mask = wide_nums ? ~(uint64_t)0 : 0xffffffffUL;

    q->start = 0;
    q->length = 1;
    q->firstnum = seqnum;
    q->elem[q->start] = ((uint64_t)0 - 1) & q->mask;

    *vqueue = (void *)q;

    return GSS_S_COMPLETE;
}

OM_uint32
sequenceCheck(OM_uint32 *minor,
              void **vqueue,
              uint64_t seqnum)
{
    queue *q;
    int i;
    uint64_t expected;

    *minor = 0;

    q = (queue *) (*vqueue);

    if (!q->do_replay && !q->do_sequence)
        return GSS_S_COMPLETE;

    /* All checks are done relative to the initial sequence number, to
       avoid (or at least put off) the pain of wrapping.  */
    seqnum -= q->firstnum;
    /* If we're only doing 32-bit values, adjust for that again.

       Note that this will probably be the wrong thing to if we get
       2**32 messages sent with 32-bit sequence numbers.  */
    seqnum &= q->mask;

    /* rule 1: expected sequence number */

    expected = (QELEM(q,q->start+q->length-1)+1) & q->mask;
    if (seqnum == expected) {
        queue_insert(q, q->start+q->length-1, seqnum);
        return GSS_S_COMPLETE;
    }

    /* rule 2: > expected sequence number */

    if ((seqnum > expected)) {
        queue_insert(q, q->start+q->length-1, seqnum);
        if (q->do_replay && !q->do_sequence)
            return GSS_S_COMPLETE;
        else
            return GSS_S_GAP_TOKEN;
    }

    /* rule 3: seqnum < seqnum(first) */

    if ((seqnum < QELEM(q,q->start)) &&
        /* Is top bit of whatever width we're using set?

           We used to check for greater than or equal to firstnum, but
           (1) we've since switched to compute values relative to
           firstnum, so the lowest we can have is 0, and (2) the effect
           of the original scheme was highly dependent on whether
           firstnum was close to either side of 0.  (Consider
           firstnum==0xFFFFFFFE and we miss three packets; the next
           packet is *new* but would look old.)

           This check should give us 2**31 or 2**63 messages "new", and
           just as many "old".  That's not quite right either.  */
        (seqnum & (1 + (q->mask >> 1)))
    ) {
        if (q->do_replay && !q->do_sequence)
            return GSS_S_OLD_TOKEN;
        else
            return GSS_S_UNSEQ_TOKEN;
    }

    /* rule 4+5: seqnum in [seqnum(first),seqnum(last)]  */

    else {
        if (seqnum == QELEM(q,q->start+q->length - 1))
            return GSS_S_DUPLICATE_TOKEN;

        for (i = q->start; i < q->start + q->length - 1; i++) {
            if (seqnum == QELEM(q,i))
                return GSS_S_DUPLICATE_TOKEN;
            if ((seqnum > QELEM(q,i)) && (seqnum < QELEM(q,i+1))) {
                queue_insert(q, i, seqnum);
                if (q->do_replay && !q->do_sequence)
                    return GSS_S_COMPLETE;
                else
                    return GSS_S_UNSEQ_TOKEN;
            }
        }
    }

    /* this should never happen */
    return GSS_S_FAILURE;
}

OM_uint32
sequenceFree(OM_uint32 *minor, void **vqueue)
{
    queue *q;

    q = (queue *) (*vqueue);

    GSSBID_FREE(q);

    *vqueue = NULL;

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * These support functions are for the serialization routines
 */
size_t
sequenceSize(void *vqueue GSSBID_UNUSED)
{
    return sizeof(queue);
}

OM_uint32
sequenceExternalize(OM_uint32 *minor,
                    void *vqueue,
                    unsigned char **buf,
                    size_t *lenremain)
{
    if (*lenremain < sizeof(queue)) {
        *minor = GSSBID_WRONG_SIZE;
        return GSS_S_FAILURE;
    }
    if (vqueue != NULL)
        memcpy(*buf, vqueue, sizeof(queue));
    else
        memset(*buf, 0, sizeof(queue));
    *buf += sizeof(queue);
    *lenremain -= sizeof(queue);

    return 0;
}

OM_uint32
sequenceInternalize(OM_uint32 *minor,
                    void **vqueue,
                    unsigned char **buf,
                    size_t *lenremain)
{
    void *q;

    if (*lenremain < sizeof(queue)) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    q = GSSBID_MALLOC(sizeof(queue));
    if (q == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    memcpy(q, *buf, sizeof(queue));
    *buf += sizeof(queue);
    *lenremain -= sizeof(queue);
    *vqueue = q;

    *minor = 0;
    return GSS_S_COMPLETE;
}
