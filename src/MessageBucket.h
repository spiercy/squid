/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef MESSAGEBUCKET_H
#define MESSAGEBUCKET_H

#if USE_DELAY_POOLS

#include "base/RefCount.h"
#include "comm/forward.h"
#include "comm/Connection.h"

class MessageDelayPool;

class MessageBucket : public RefCountable
{

public:
    typedef RefCount<MessageBucket> Pointer;

    MessageBucket(const int aWriteSpeedLimit, const double anInitialBurst, const double aHighWatermark, MessageDelayPool *pool);

    void *operator new(size_t);
    void operator delete (void *);
    void refillBucket();
    int quota();
    void bytesIn(int qty);

    Comm::ConnectionPointer clientConnection;
    double bucketSize; ///< how much can be written now
    bool selectWaiting; ///< is between commSetSelect and commHandleWrite

private:
    double prevTime; ///< previous time when we checked
    double writeSpeedLimit;///< Write speed limit in bytes per second, can be less than 1, if too close to zero this could result in timeouts from client
    double bucketSizeLimit;  ///< maximum bucket size
    MessageDelayPool *theAggregate;
};

#endif
#endif
