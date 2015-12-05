/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "event.h"
#include "SquidTime.h"
#include "DelaySpec.h"
#include "MessageDelayPools.h"

MessageDelayPools::MessageDelayPools(): LastUpdate(squid_curtime)
{
    Init();
}

MessageDelayPools::~MessageDelayPools()
{
    eventDelete(MessageDelayPools::Update, NULL);
    for (auto &p: pools)
        delete p;
    pools.clear();
}

MessageDelayPools *
MessageDelayPools::Instance()
{
    static MessageDelayPools pools;
    return &pools;
}

void
MessageDelayPools::Update(void *)
{
    MessageDelayPools *pools = MessageDelayPools::Instance();
    if (!pools->pools.size())
        return;

    eventAdd("MessageDelayPools::Update", MessageDelayPools::Update, NULL, 1.0, 1);

    int incr = squid_curtime - pools->LastUpdate;
    if (incr < 1)
        return;

    pools->LastUpdate = squid_curtime;

    for (auto &p: pools->toUpdate)
        p->update(incr);
}

// XXX: duplicates DelayPools::deregisterForUpdates()
void
MessageDelayPools::deregisterForUpdates(Updateable *anObject)
{
    std::vector<Updateable *>::iterator pos = toUpdate.begin();

    while (pos != toUpdate.end() && *pos != anObject) {
        ++pos;
    }

    if (pos != toUpdate.end()) {
        /* move all objects down one */
        std::vector<Updateable *>::iterator temp = pos;
        ++pos;

        while (pos != toUpdate.end()) {
            *temp = *pos;
            ++temp;
            ++pos;
        }

        toUpdate.pop_back();
    }
}

void
MessageDelayPools::Init()
{
    MessageDelayPool *pool = new MessageDelayPool(32, 32, 48, 48);
    pools.push_back(pool);
    registerForUpdates(pool);
    eventAdd("MessageDelayPools::Update", MessageDelayPools::Update, NULL, 1.0, 1);
}

MessageDelayPool::MessageDelayPool(int bucketSpeed, int64_t bucketSize,
        int aggregateSpeed, int64_t aggregateSize): bucketSpeedLimit(bucketSpeed),
    maxBucketSize(bucketSize),
    aggregateSpeedLimit(aggregateSpeed),
    maxAggregateSize(aggregateSize) {}

void
MessageDelayPool::update(int incr)
{
    DelaySpec spec;
    spec.restore_bps = aggregateSpeedLimit;
    spec.max_bytes = maxAggregateSize;
    theBucket.update(spec, incr);
}

MessageBucket::Pointer
MessageDelayPool::createBucket()
{
    return new MessageBucket(bucketSpeedLimit, bucketSpeedLimit, maxBucketSize, this);
}

#endif
