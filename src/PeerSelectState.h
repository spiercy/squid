/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_PEERSELECTSTATE_H
#define   SQUID_PEERSELECTSTATE_H

#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "base/CbcPointer.h"
#include "base/RefCount.h"
#include "comm/forward.h"
#include "hier_code.h"
#include "ip/Address.h"
#include "ipcache.h"
#include "mem/forward.h"
#include "PingData.h"

#include <vector>

class ErrorState;
class HtcpReplyData;
class HttpRequest;
typedef RefCount<HttpRequest> HttpRequestPointer;
class icp_common_t;
class StoreEntry;
class PeerSelector;

void peerSelectInit(void);

/// Interface for those who need a list of peers to forward a request to.
class PeerSelectionInitiator: public Dns::IpReceiver
{

public:
    PeerSelectionInitiator(HttpRequest *req);
    virtual ~PeerSelectionInitiator();

    /// called when a new unique destination has been found
    virtual void noteDestination(Comm::ConnectionPointer path) = 0;

    /// called when there will be no more noteDestination() calls
    /// \param error is a possible reason why no destinations were found; it is
    /// guaranteed to be nil if there was at least one noteDestination() call
    virtual void noteDestinationsEnd(ErrorState *error) = 0;

    /* Dns::IpReceiver API */
    virtual void noteIp(const Ip::Address &ip) override;
    virtual void noteIps(const Dns::CachedIps *ips, const Dns::LookupDetails &details) override;
    virtual void noteLookup(const Dns::LookupDetails &details) override;

    void notePeer(CachePeer *peer, hier_code code);

    /// \returns whether the initiator may use more destinations
    bool wantsMoreDestinations() const;

    /// whether noteDestination() and noteDestinationsEnd() calls are allowed
    bool subscribed = false;
    PeerSelector *selector;
    hier_code _peerType = HIER_NONE;
    CbcPointer<CachePeer> _peer;
    HttpRequestPointer request;
    size_t foundPaths = 0; ///< number of unique destinations identified so far
    ErrorState *lastError = nullptr;

    /* protected: */
    /// Initiates asynchronous peer selection that eventually
    /// results in zero or more noteDestination() calls and
    /// exactly one noteDestinationsEnd() call.
    void startSelectingDestinations(const AccessLogEntry::Pointer &ale, StoreEntry *entry);
    void requestNewPeer();
};

class FwdServer;

/// Finds peer (including origin server) IPs for forwarding a single request.
/// Gives PeerSelectionInitiator each found destination, in the right order.
class PeerSelector
{
    CBDATA_CLASS(PeerSelector);

public:

    class CbDialer: public CallDialer {
    public:
        typedef void (PeerSelectionInitiator::*Method)(CachePeer *, hier_code);
        CbDialer(PeerSelectionInitiator *initiator, Method method):
            forwader_(initiator), method_(method) {}
        virtual ~CbDialer() {}

        /* CallDialer API */
        virtual bool canDial(AsyncCall &call) {return forwader_.valid();}
        virtual void dial(AsyncCall &call) {(&(*forwader_)->*method_)(peer_.raw(), code_);};
        virtual void print(std::ostream &os) const {os << "A peer!";};

        CbcPointer<PeerSelectionInitiator> forwader_;
        Method method_;
        CbcPointer<CachePeer> peer_; /* NULL --> origin server */
        hier_code code_ = HIER_NONE;
    };

    explicit PeerSelector();
    ~PeerSelector();

    // Produce a URL for display identifying the transaction we are
    // trying to locate a peer for.
    const SBuf url() const;

    /// processes a newly discovered/finalized path
    // void handlePath(Comm::ConnectionPointer &path, FwdServer &fs);

    /// a single selection loop iteration: attempts to add more destinations
    void selectMore();

    void requestPeer(AsyncCall::Pointer &call);

    void addSelection(CachePeer*, const hier_code);
//    void addSelectionToHead(CachePeer*, const hier_code);

    void checkLastPeerAccess(allow_t answer);

    void checkNextPingNeighborAccess(allow_t answer);
    bool icpPingNeighbors();
    bool doIcpPing();
    void callback(CachePeer *, hier_code);

    HttpRequest *request;
    AccessLogEntry::Pointer al; ///< info for the future access.log entry
    StoreEntry *entry;

    void *peerCountMcastPeerXXX = nullptr; ///< a hack to help peerCountMcastPeersStart()
    AsyncCall::Pointer callback_;

    ping_data ping;
    std::vector<CbcPointer<CachePeer> > pingPeers;

protected:
    bool selectionAborted();

    void handlePingTimeout();
    void handleIcpReply(CachePeer*, const peer_t, icp_common_t *header);
    void handleIcpParentMiss(CachePeer*, icp_common_t*);
#if USE_HTCP
    void handleHtcpParentMiss(CachePeer*, HtcpReplyData*);
    void handleHtcpReply(CachePeer*, const peer_t, HtcpReplyData*);
#endif

    int checkNetdbDirect();
    void checkAlwaysDirectDone(const allow_t answer);
    void checkNeverDirectDone(const allow_t answer);

    void selectSomeNeighbor();
    void selectSomeNeighborReplies();
    void selectSomeDirect();
    void selectSomeParent();
    void selectAllParents();
    void selectPinned();

    void sendNextPeer();

    static IRCB HandlePingReply;
    static ACLCB CheckAlwaysDirectDone;
    static ACLCB CheckNeverDirectDone;
    static EVH HandlePingTimeout;

private:
    allow_t always_direct;
    allow_t never_direct;
    int direct;   // TODO: fold always_direct/never_direct/prefer_direct into this now that ACL can do a multi-state result.

    int foundPeers = 0;
    FwdServer *servers; ///< a linked list of (unresolved) selected peers
    FwdServer *currentServer = nullptr;
    enum {DoPreselection, DoPing, DoFinal, DoFinished} selectionState = DoPreselection;

    /*
     * Why are these Ip::Address instead of CachePeer *?  Because a
     * CachePeer structure can become invalid during the CachePeer selection
     * phase, specifically after a reconfigure.  Thus we need to lookup
     * the CachePeer * based on the address when we are finally ready to
     * reference the CachePeer structure.
     */

    Ip::Address first_parent_miss;

    Ip::Address closest_parent_miss;
    /*
     * ->hit can be CachePeer* because it should only be
     * accessed during the thread when it is set
     */
    CachePeer *hit;
    peer_t hit_type;
    ACLChecklist *acl_checklist;

    typedef CbcPointer<PeerSelectionInitiator> Initiator;
    Initiator initiator_; ///< recipient of the destinations we select; use interestedInitiator() to access

    const InstanceId<PeerSelector> id; ///< unique identification in worker log
};

#endif /* SQUID_PEERSELECTSTATE_H */

