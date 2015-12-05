/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef MESSAGEDELAYPOOLS_H
#define MESSAGEDELAYPOOLS_H

#if USE_DELAY_POOLS

#include "acl/Acl.h"
#include "base/RefCount.h"
#include "DelayBucket.h"
#include "DelayPools.h"
#include "MessageBucket.h"

/// \ingroup DelayPoolsAPI
/// Represents one 'response' delay pool, creates individual response
/// buckets and performes aggregate limiting for them
class MessageDelayPool : public Updateable
{
    public:
        MessageDelayPool(int bucketSpeed, int64_t bucketSize,
                int aggregateSpeed, int64_t aggregateSize);

        virtual void update(int incr) override;
        void bytesIn(int qty) { theBucket.bytesIn(qty); }
        int level() { return theBucket.level(); }
        MessageBucket::Pointer createBucket();

    private:
        acl_access *access;
        int bucketSpeedLimit;
        int64_t maxBucketSize;
        int aggregateSpeedLimit;
        int64_t maxAggregateSize;
        DelayBucket theBucket;
};

/// \ingroup DelayPoolsAPI
/// represents all configured 'response' delay pools
class MessageDelayPools
{
    public:
        static MessageDelayPools *Instance();
        static void Update(void *);

        void Init();
        void registerForUpdates(Updateable *obj) { toUpdate.push_back(obj); }
        void deregisterForUpdates (Updateable *);

        std::vector<MessageDelayPool*> pools;

    private:
        MessageDelayPools();
        MessageDelayPools(const MessageDelayPools &);
        MessageDelayPools &operator=(const MessageDelayPools &);
        ~MessageDelayPools();
        void Stats() { } // TODO

        time_t LastUpdate;
        std::vector<Updateable *> toUpdate;
};

#endif
#endif
