/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
    MessageDelayPool(const SBuf &name, uint64_t bucketSpeed, uint64_t bucketSize,
                     uint64_t aggregateSpeed, uint64_t aggregateSize, uint16_t initial);

    virtual void update(int incr) override;
    void bytesIn(int qty) { theBucket.bytesIn(qty); }
    int level() { return theBucket.level(); }
    MessageBucket::Pointer createBucket();

    acl_access *access;
    SBuf poolName;
    uint64_t bucketSpeedLimit;
    uint64_t maxBucketSize;
    uint64_t aggregateSpeedLimit;
    uint64_t maxAggregateSize;
    uint16_t initialFillLevel;
    DelayBucket theBucket;
};

/// \ingroup DelayPoolsAPI
/// represents all configured 'response' delay pools
class MessageDelayPools
{
public:
    static MessageDelayPools *Instance();
    static void Update(void *);

    void registerForUpdates(Updateable *obj) { toUpdate.push_back(obj); }
    void deregisterForUpdates (Updateable *);
    MessageDelayPool *pool(const SBuf &name);
    void add(MessageDelayPool *pool);

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

/// represents configuration for response delay pools
class MessageDelayConfig
{
public:
    void parseResponseDelayPool();
    void parseResponseDelayPoolAccess(ConfigParser &parser);
};

#endif
#endif

