/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "Debug.h"
#include "DelayPools.h"
#include "MessageBucket.h"
#include "MessageDelayPools.h"

MessageBucket::MessageBucket(const int aWriteSpeedLimit, const double anInitialBurst,
        const double aHighWatermark, MessageDelayPool *pool) : bucketSize(anInitialBurst),
    selectWaiting(false),
    prevTime(current_dtime),
    writeSpeedLimit(aWriteSpeedLimit),
    bucketSizeLimit(aHighWatermark),
    theAggregate(pool) {}

void *
MessageBucket::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (MessageBucket);
    return ::operator new (size);
}

void
MessageBucket::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (MessageBucket);
    ::operator delete (address);
}

int
MessageBucket::quota()
{
    return min(bucketSize, static_cast<double>(theAggregate->level()));
}
    
void MessageBucket::bytesIn(int qty)
{ 
    bucketSize -= qty;
    if (bucketSize < 0.0) {
        debugs(77, DBG_IMPORTANT, "drained too much"); // should not happen
        bucketSize = 0;
    }
    theAggregate->bytesIn(qty);
}

// XXX: duplicates ClientInfo::refillBucket()
void
MessageBucket::refillBucket()
{
    // all these times are in seconds, with double precision
    const double currTime = current_dtime;
    const double timePassed = currTime - prevTime;

    // Calculate allowance for the time passed. Use double to avoid
    // accumulating rounding errors for small intervals. For example, always
    // adding 1 byte instead of 1.4 results in 29% bandwidth allocation error.
    const double gain = timePassed * writeSpeedLimit;

    // XXX: Decide whether to add 'hash' field like ClientInfo::hash
    //  debugs(77,5, HERE << currTime << " clt" << (const char*)hash.key << ": " <<
    //         bucketSize << " + (" << timePassed << " * " << writeSpeedLimit <<
    //         " = " << gain << ')');

    // to further combat error accumulation during micro updates,
    // quit before updating time if we cannot add at least one byte
    if (gain < 1.0)
        return;

    prevTime = currTime;

    // for "first" connections, drain initial fat before refilling but keep
    // updating prevTime to avoid bursts after the fat is gone
    if (bucketSize > bucketSizeLimit) {
        debugs(77,4, HERE << "not refilling while draining initial fat");
        return;
    }

    bucketSize += gain;

    // obey quota limits
    if (bucketSize > bucketSizeLimit)
        bucketSize = bucketSizeLimit;
}

#endif
