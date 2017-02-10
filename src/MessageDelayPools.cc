/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include <algorithm>
#include <map>
#include "acl/Gadgets.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "DelaySpec.h"
#include "event.h"
#include "MessageDelayPools.h"
#include "Parsing.h"
#include "SquidTime.h"

MessageDelayPools::MessageDelayPools(): LastUpdate(squid_curtime)
{
    eventAdd("MessageDelayPools::Update", MessageDelayPools::Update, NULL, 1.0, 1);
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

MessageDelayPool *
MessageDelayPools::pool(const SBuf &name)
{
    auto it = std::find_if(pools.begin(), pools.end(),
    [&name](const MessageDelayPool *p) { return p->poolName == name; });
    return it == pools.end() ? 0 : *it;
}

void
MessageDelayPools::add(MessageDelayPool *p)
{
    const auto it = std::find_if(pools.begin(), pools.end(),
    [&p](const MessageDelayPool *mp) { return mp->poolName == p->poolName; });
    if (it != pools.end()) {
        debugs(3, DBG_CRITICAL, "Ignoring duplicate " << p->poolName << " response delay pool");
        return;
    }
    pools.push_back(p);
    registerForUpdates(p);
}

MessageDelayPool::MessageDelayPool(const SBuf &name, uint64_t bucketSpeed, uint64_t bucketSize,
                                   uint64_t aggregateSpeed, uint64_t aggregateSize, uint16_t initial):
    access(0),
    poolName(name),
    bucketSpeedLimit(bucketSpeed),
    maxBucketSize(bucketSize),
    aggregateSpeedLimit(aggregateSpeed),
    maxAggregateSize(aggregateSize),
    initialFillLevel(initial) {}

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
    return new MessageBucket(bucketSpeedLimit, bucketSpeedLimit * (initialFillLevel / 100.0), maxBucketSize, this);
}

void
MessageDelayConfig::parseResponseDelayPool()
{
    std::map<SBuf, int64_t> params = {
        {SBuf("bucket_speed_limit="), -1},
        {SBuf("max_bucket_size="), -1},
        {SBuf("aggregate_speed_limit="), -1},
        {SBuf("max_aggregate_size="), -1},
        {SBuf("initial_fill_level="), 50}
    };
    const SBuf name(ConfigParser::NextToken());
    if (name.isEmpty()) {
        debugs(3, DBG_CRITICAL, "ERROR: required parameter \"name\" for response_delay_pool option missing.");
        self_destruct();
    }
    while (const char *token = ConfigParser::NextToken()) {
        auto it = params.begin();
        for (; it != params.end(); ++it) {
            SBuf n = it->first;
            if (!strncmp(token, n.c_str(), n.length())) {
                it->second = xatoll(token + it->first.length(), 10);
                break;
            }
        }
        if (it == params.end()) {
            debugs(3, DBG_CRITICAL, "ERROR: option " << token << " is not supported for response_delay_pool.");
            self_destruct();
        }
    }
    for (const auto &p: params) {
        if (p.second == -1) {
            const SBuf failedOption = p.first.substr(0, p.first.length() - 1);
            debugs(3, DBG_CRITICAL, "ERROR: required " << failedOption << " option missing.");
            self_destruct();
        }
    }

    MessageDelayPool *pool = new MessageDelayPool(name,
            static_cast<uint64_t>(params[SBuf("bucket_speed_limit=")]),
            static_cast<uint64_t>(params[SBuf("max_bucket_size=")]),
            static_cast<uint64_t>(params[SBuf("aggregate_speed_limit=")]),
            static_cast<uint64_t>(params[SBuf("max_aggregate_size=")]),
            static_cast<uint16_t>(params[SBuf("initial_fill_level=")])
                                                 );
    MessageDelayPools::Instance()->add(pool);
}

void
MessageDelayConfig::parseResponseDelayPoolAccess(ConfigParser &parser) {
    const char *token = ConfigParser::NextToken();
    if (!token) {
        debugs(3, DBG_CRITICAL, "ERROR: required pool_name option missing");
        return;
    }
    MessageDelayPool *pool = MessageDelayPools::Instance()->pool(SBuf(token));
    if (pool)
        aclParseAccessLine("response_delay_pool_access", parser, &pool->access);
}

#endif

