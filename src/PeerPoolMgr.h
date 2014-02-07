#ifndef SQUID_PEERPOOLMGR_H
#define SQUID_PEERPOOLMGR_H

#include "base/AsyncJob.h"
#include "comm/forward.h"

class CachePeer;
class CommConnectCbParams;

/// Maintains an fixed-size "standby" PconnPool for a single CachePeer.
class PeerPoolMgr: public AsyncJob
{
public:
    typedef CbcPointer<PeerPoolMgr> Pointer;

    // syncs mgr state whenever connection-related peer or pool state changes
    static void Checkpoint(const Pointer &mgr, const char *reason);

    explicit PeerPoolMgr(CachePeer *aPeer);
    virtual ~PeerPoolMgr();

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;

    bool validPeer() const;

    void checkpoint(const char *reason);
    void openNewConnection();
    void closeOldConnections(const int howMany);

    void handleOpenedConnection(const CommConnectCbParams &params);

private:
    CachePeer *peer; ///< the owner of the pool we manage
    AsyncCall::Pointer opener; ///< whether we are opening a connection
    unsigned int addrUsed; ///< counter for cycling through peer addresses

    CBDATA_CLASS2(PeerPoolMgr);
};

#endif /* SQUID_PEERPOOLMGR_H */
