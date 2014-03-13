#ifndef SQUID_PEERPOOLMGR_H
#define SQUID_PEERPOOLMGR_H

#include "base/AsyncJob.h"
#include "comm/forward.h"

class HttpRequest;
class CachePeer;
class CommConnectCbParams;

#if USE_SSL
namespace Ssl {
    class PeerConnectorAnswer;
}
#endif

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
#if USE_SSL
    void handleSecuredPeer(Ssl::PeerConnectorAnswer &answer);
    void handleSecureClosure(const CommCloseCbParams &params);
#endif
    void pushNewConnection(const Comm::ConnectionPointer &conn);

private:
    CachePeer *peer; ///< the owner of the pool we manage
    RefCount<HttpRequest> request; ///< fake HTTP request for conn opening code
    AsyncCall::Pointer opener; ///< whether we are opening a connection
    AsyncCall::Pointer securer; ///< whether we are securing a connection
    AsyncCall::Pointer closer; ///< monitors conn while we are securing it
    unsigned int addrUsed; ///< counter for cycling through peer addresses

    CBDATA_CLASS2(PeerPoolMgr);
};

#endif /* SQUID_PEERPOOLMGR_H */
