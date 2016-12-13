/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef BANDWIDTHBUCKET_H
#define BANDWIDTHBUCKET_H

#if USE_DELAY_POOLS

#include "comm/IoCallback.h"

class fde;

/// Base class for Squid-to-client bandwidth limiting
class BandwidthBucket
{
public:
    BandwidthBucket(const int aWriteSpeedLimit, const double anInitialBurst,
                    const double aHighWatermark);
    virtual ~BandwidthBucket() {}

    static BandwidthBucket *SelectBucket(fde *f);

    /// \returns the number of bytes this bucket allows to write,
    /// also considering aggregates, if any.
    virtual int quota() = 0;
    /// Adjusts nleft to not exceed the current bucket quota value,
    /// if needed.
    virtual bool applyQuota(int &nleft, Comm::IoCallback *state);
    /// Will plan another write call.
    virtual void scheduleWrite(Comm::IoCallback *state) = 0;
    /// Performs cleanup when the related file descriptor becames closed.
    virtual void onFdClosed() { selectWaiting = false; }
    /// Decreases the bucket level.
    virtual void reduceBucket(const int len);

protected:
    /// Increases the bucket level with the writeSpeedLimit speed.
    void refillBucket();

public:
    double bucketSize; ///< how much can be written now
    bool selectWaiting; ///< is between commSetSelect and commHandleWrite

protected:
    double prevTime; ///< previous time when we checked
    double writeSpeedLimit;///< Write speed limit in bytes per second, can be less than 1, if too close to zero this could result in timeouts from client
    double bucketSizeLimit;  ///< maximum bucket size
};

#endif /* USE_DELAY_POOLS */

#endif

