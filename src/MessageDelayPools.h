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

class MessageBucket;
typedef RefCount<MessageBucket> MessageBucketPointer;

/// \ingroup DelayPoolsAPI
/// Represents one 'response' delay pool, creates individual response
/// buckets and performes aggregate limiting for them
class MessageDelayPool : public RefCountable
{
public:
    typedef RefCount<MessageDelayPool> Pointer;

    MessageDelayPool(const SBuf &name, uint64_t bucketSpeed, uint64_t bucketSize,
                     uint64_t aggregateSpeed, uint64_t aggregateSize, uint16_t initial);
    ~MessageDelayPool();
    MessageDelayPool(const MessageDelayPool &) = delete;
    MessageDelayPool &operator=(const MessageDelayPool &) = delete;

    /// Increases the aggregate bucket level with the aggregateSpeedLimit speed.
    void refillBucket();
    /// decreases the aggregate level
    void bytesIn(int qty) { theBucket.bytesIn(qty); }
    /// current aggregate level
    int level() { return theBucket.level(); }
    /// creates an individual response bucket
    MessageBucketPointer createBucket();

    acl_access *access;
    /// the response delay pool name
    SBuf poolName;
    /// the speed limit of an individual bucket (bytes/s)
    uint64_t bucketSpeedLimit;
    /// the maximum size of an individual bucket
    uint64_t maxBucketSize;
    /// the speed limit of the aggregate bucket (bytes/s)
    uint64_t aggregateSpeedLimit;
    /// the maximum size of the aggregate bucket
    uint64_t maxAggregateSize;
    /// the initial bucket size as a percentage of maxBucketSize
    uint16_t initialFillLevel;
    /// the aggregate bucket
    DelayBucket theBucket;

private:
    /// Time the aggregate bucket level was last refilled.
    time_t lastUpdate;
};

/// \ingroup DelayPoolsAPI
/// represents all configured 'response' delay pools
class MessageDelayPools
{
public:
    MessageDelayPools(const MessageDelayPools &) = delete;
    MessageDelayPools &operator=(const MessageDelayPools &) = delete;

    static MessageDelayPools *Instance();

    /// returns a MessageDelayPool with a given name or null otherwise
    MessageDelayPool::Pointer pool(const SBuf &name);
    /// appends a single MessageDelayPool, created during configuration
    void add(MessageDelayPool *pool);
    /// memory cleanup, performing during reconfiguration
    void freePools();

    std::vector<MessageDelayPool::Pointer> pools;

private:
    MessageDelayPools(){}
    ~MessageDelayPools();
    void Stats() { } // TODO
};

/// represents configuration for response delay pools
class MessageDelayConfig
{
public:
    void parseResponseDelayPool();
    void parseResponseDelayPoolAccess(ConfigParser &parser);
    void freePools();
};

#endif
#endif

