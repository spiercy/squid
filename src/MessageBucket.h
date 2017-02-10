/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef MESSAGEBUCKET_H
#define MESSAGEBUCKET_H

#if USE_DELAY_POOLS

#include "BandwidthBucket.h"
#include "base/RefCount.h"
#include "comm/forward.h"

#include "MessageDelayPools.h"

namespace Comm
{
extern PF HandleWrite;
extern void SetSelect(int, unsigned int, PF *, void *, time_t);
}

/// Limits Squid-to-client bandwidth for each matching response
class MessageBucket : public RefCountable, public BandwidthBucket
{
    MEMPROXY_CLASS(MessageBucket);

public:
    typedef RefCount<MessageBucket> Pointer;

    MessageBucket(const int aWriteSpeedLimit, const double anInitialBurst, const double aHighWatermark, MessageDelayPool::Pointer pool);

    /* BandwidthBucket API */
    virtual int quota() override;
    virtual void scheduleWrite(Comm::IoCallback *state) override;
    virtual void reduceBucket(int len);

private:
    MessageDelayPool::Pointer theAggregate;
};

#endif /* USE_DELAY_POOLS */

#endif

