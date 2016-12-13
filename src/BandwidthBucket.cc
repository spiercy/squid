/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS

#include "BandwidthBucket.h"
#include "ClientInfo.h"
#include "comm/Connection.h"
#include "Debug.h"
#include "fde.h"

extern double current_dtime;

BandwidthBucket::BandwidthBucket(const int aWriteSpeedLimit, const double anInitialBurst,
                                 const double aHighWatermark) :
    bucketSize(anInitialBurst),
    selectWaiting(false),
    writeSpeedLimit(aWriteSpeedLimit),
    bucketSizeLimit(aHighWatermark)
{
    getCurrentTime();
    /* put current time to have something sensible here */
    prevTime = current_dtime;
}

void
BandwidthBucket::refillBucket()
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

bool
BandwidthBucket::applyQuota(int &nleft, Comm::IoCallback *state)
{
    const int q = quota();
    if (!q)
        return false;
    const int nleft_corrected = min(nleft, q);
    if (nleft != nleft_corrected) {
        debugs(77, 5, state->conn << " writes only " <<
               nleft_corrected << " out of " << nleft);
        nleft = nleft_corrected;
    }
    return true;
}

void
BandwidthBucket::reduceBucket(const int len)
{
    if (len <= 0)
        return;
    bucketSize -= len;
    if (bucketSize < 0.0) {
        debugs(77, DBG_IMPORTANT, "drained too much"); // should not happen
        bucketSize = 0;
    }
}

BandwidthBucket *
BandwidthBucket::SelectBucket(fde *f)
{
    BandwidthBucket *bucket = f->writeQuotaHandler.getRaw();
    if (!bucket) {
        ClientInfo *clientInfo = f->clientInfo;
        if (clientInfo && clientInfo->writeLimitingActive)
            bucket = clientInfo;
    }
    return bucket;
}

#endif /* USE_DELAY_POOLS */

