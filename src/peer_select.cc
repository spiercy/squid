/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 44    Peer Selection Algorithm */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "base/InstanceId.h"
#include "CachePeer.h"
#include "carp.h"
#include "client_side.h"
#include "dns/LookupDetails.h"
#include "errorpage.h"
#include "event.h"
#include "FwdState.h"
#include "globals.h"
#include "hier_code.h"
#include "htcp.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "neighbors.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"

/**
 * A CachePeer which has been selected as a possible destination.
 * Listed as pointers here so as to prevent duplicates being added but will
 * be converted to a set of IP address path options before handing back out
 * to the caller.
 *
 * Certain connection flags and outgoing settings will also be looked up and
 * set based on the received request and CachePeer settings before handing back.
 */
class FwdServer
{
    MEMPROXY_CLASS(FwdServer);

public:
    FwdServer(CachePeer *p, hier_code c) :
        _peer(p),
        code(c),
        next(nullptr)
    {}

    CbcPointer<CachePeer> _peer;                /* NULL --> origin server */
    hier_code code;
    FwdServer *next;
};

static struct {
    int timeouts;
} PeerStats;

static const char *DirectStr[] = {
    "DIRECT_UNKNOWN",
    "DIRECT_NO",
    "DIRECT_MAYBE",
    "DIRECT_YES"
};

/// a helper class to report a selected destination (for debugging)
class PeerSelectionDumper
{
public:
    PeerSelectionDumper(const PeerSelector * const aSelector, const CachePeer * const aPeer, const hier_code aCode):
        selector(aSelector), peer(aPeer), code(aCode) {}

    const PeerSelector * const selector; ///< selection parameters
    const CachePeer * const peer; ///< successful selection info
    const hier_code code; ///< selection algorithm
};

CBDATA_CLASS_INIT(PeerSelector);

/// prints PeerSelectionDumper (for debugging)
static std::ostream &
operator <<(std::ostream &os, const PeerSelectionDumper &fsd)
{
    os << hier_code_str[fsd.code];

    if (fsd.peer)
        os << '/' << fsd.peer->host;
    else if (fsd.selector) // useful for DIRECT and gone PINNED destinations
        os << '#' << fsd.selector->request->url.host();

    return os;
}

PeerSelector::~PeerSelector()
{
    debugs(44, 5, "destructing");
    while (servers) {
        FwdServer *next = servers->next;
        delete servers;
        servers = next;
    }

    if (entry) {
        debugs(44, 3, entry->url());

        if (entry->ping_status == PING_WAITING)
            eventDelete(HandlePingTimeout, this);

        entry->ping_status = PING_DONE;
    }

    if (acl_checklist) {
        debugs(44, DBG_IMPORTANT, "BUG: peer selector gone while waiting for a slow ACL");
        delete acl_checklist;
    }

    HTTPMSGUNLOCK(request);

    if (entry) {
        assert(entry->ping_status != PING_WAITING);
        entry->unlock("peerSelect");
        entry = NULL;
    }
}

bool
PeerSelector::icpPingNeighbors()
{
    assert(entry);
    assert(direct != DIRECT_YES);

    if (pingPeers.size() > 0)
        return true;

    if (entry->ping_status != PING_NONE)
        return false;

    debugs(44, 3, entry->url());

    if (!request->flags.hierarchical && direct != DIRECT_NO)
        return false;

    if (EBIT_TEST(entry->flags, KEY_PRIVATE) && !neighbors_do_private_keys)
        if (direct != DIRECT_NO)
            return false;

    getNeighbors(request, pingPeers);

    debugs(44, 3, "counted " << pingPeers.size() << "candidate neighbors");

    return pingPeers.size() > 0;
}

static void
peerSelect(PeerSelectionInitiator *initiator,
           HttpRequest * request,
           AccessLogEntry::Pointer const &al,
           StoreEntry * entry
    )
{
    if (entry)
        debugs(44, 3, *entry << ' ' << entry->url());
    else
        debugs(44, 3, request->method);

    const auto selector = new PeerSelector();

    selector->request = request;
    HTTPMSGLOCK(selector->request);
    selector->al = al;

    selector->entry = entry;

#if USE_CACHE_DIGESTS

    request->hier.peer_select_start = current_time;

#endif

    if (selector->entry)
        selector->entry->lock("peerSelect");

    initiator->selector = selector;
    initiator->requestNewPeer();
}

PeerSelectionInitiator::PeerSelectionInitiator(HttpRequest *req):
    request(req)
{}

PeerSelectionInitiator::~PeerSelectionInitiator()
{
    delete lastError;
    delete selector;
}

void
PeerSelectionInitiator::notePeer(CachePeer *peer, hier_code code)
{
    if (peer == nullptr && code == HIER_NONE) {
        PeerSelectionInitiator::subscribed = false;
        if (lastError && foundPaths) {
            // nobody cares about errors if we found destinations despite them
            debugs(44, 3, "forgetting the last error");
            delete lastError;
            lastError = nullptr;
        }
        // May kill our self:
        noteDestinationsEnd(lastError);
        return;
    }

    _peer = peer;
    _peerType = code;
    if (code == ORIGINAL_DST) {
        assert(_peer == nullptr);
        if (request->clientConnectionManager.valid()) {
            // construct a "result" adding the ORIGINAL_DST to the set instead of DIRECT
            Comm::ConnectionPointer p = new Comm::Connection();
            p->remote = request->clientConnectionManager->clientConnection->local;
            p->peerType = ORIGINAL_DST;
            // check for a configured outgoing address for this destination...
            getOutgoingAddress(request.getRaw(), p);
            ++foundPaths;
            noteDestination(p);
            return;
        }
        requestNewPeer();//nothing to send continue to the next Peer
        return;
    }

    const char *host = _peer.valid() ? _peer->host : request->url.host();
    debugs(44, 2, "Find IP destination for: " << request->url << "' via " << host);
    Dns::nbgethostbyname(host, this);
}

bool
PeerSelectionInitiator::wantsMoreDestinations() const
{
    const auto maxCount = Config.forward_max_tries;
    return maxCount >= 0 && foundPaths <
           static_cast<std::make_unsigned<decltype(maxCount)>::type>(maxCount);
}


void
PeerSelectionInitiator::noteIp(const Ip::Address &ip)
{
    if (_peer.raw() && !_peer.valid()) //Peer gone, abort?
        return;

    // for TPROXY spoofing, we must skip unusable addresses
    if (request->flags.spoofClientIp && !(_peer.valid() && _peer->options.no_tproxy) ) {
        if (ip.isIPv4() != request->client_addr.isIPv4())
            return; // cannot spoof the client address on this link
    }

    Comm::ConnectionPointer path = new Comm::Connection();
    path->remote = ip;
    if (_peer.valid()) {
        path->remote.port(_peer.valid() ? _peer->http_port : request->url.port());
        path->peerType = _peerType;
        path->setPeer(_peer.get());
    } else
        path->remote.port(request->url.port());

    // check for a configured outgoing address for this destination...
    getOutgoingAddress(request.getRaw(), path);
    ++foundPaths;
    noteDestination(path);
}

void
PeerSelectionInitiator::noteIps(const Dns::CachedIps *ips, const Dns::LookupDetails &details)
{
    if (!ips) {
        debugs(17, 3, "Unknown host: " << (_peer.valid() ? _peer->host : request->url.host()));
        // discard any previous error.
        if (_peerType == HIER_DIRECT) {
            assert(!_peer.raw());
            delete lastError;
            lastError = new ErrorState(ERR_DNS_FAIL, Http::scServiceUnavailable, request.getRaw());
            lastError->dnsError = details.error;
            requestNewPeer();//nothing to send continue to the next Peer
        }
    }
}

void
PeerSelectionInitiator::noteLookup(const Dns::LookupDetails &details)
{
    request->recordLookup(details);
}

void
PeerSelectionInitiator::startSelectingDestinations(const AccessLogEntry::Pointer &ale, StoreEntry *entry)
{
    subscribed = true;
    peerSelect(this, request.getRaw(), ale, entry);
    // and wait for noteDestination() and/or noteDestinationsEnd() calls
}

void
PeerSelectionInitiator::requestNewPeer()
{
    if (subscribed && wantsMoreDestinations() && selector) {
        typedef PeerSelector::CbDialer Dialer;
        AsyncCall::Pointer call = asyncCall(44, 5, "PeerSelectionInitiator::notePeer",
                                            Dialer(this, &PeerSelectionInitiator::notePeer));

        selector->requestPeer(call);
        return;
    }
    notePeer(nullptr, HIER_NONE);
}

void
PeerSelector::checkNeverDirectDone(const allow_t answer)
{
    acl_checklist = nullptr;
    debugs(44, 3, answer);
    never_direct = answer;
    switch (answer) {
    case ACCESS_ALLOWED:
        /** if never_direct says YES, do that. */
        direct = DIRECT_NO;
        debugs(44, 3, "direct = " << DirectStr[direct] << " (never_direct allow)");
        break;
    case ACCESS_DENIED: // not relevant.
    case ACCESS_DUNNO:  // not relevant.
        break;
    case ACCESS_AUTH_REQUIRED:
        debugs(44, DBG_IMPORTANT, "WARNING: never_direct resulted in " << answer << ". Username ACLs are not reliable here.");
        break;
    }
    selectMore();
}

void
PeerSelector::CheckNeverDirectDone(allow_t answer, void *data)
{
    static_cast<PeerSelector*>(data)->checkNeverDirectDone(answer);
}

void
PeerSelector::checkAlwaysDirectDone(const allow_t answer)
{
    acl_checklist = nullptr;
    debugs(44, 3, answer);
    always_direct = answer;
    switch (answer) {
    case ACCESS_ALLOWED:
        /** if always_direct says YES, do that. */
        direct = DIRECT_YES;
        debugs(44, 3, "direct = " << DirectStr[direct] << " (always_direct allow)");
        break;
    case ACCESS_DENIED: // not relevant.
    case ACCESS_DUNNO:  // not relevant.
        break;
    case ACCESS_AUTH_REQUIRED:
        debugs(44, DBG_IMPORTANT, "WARNING: always_direct resulted in " << answer << ". Username ACLs are not reliable here.");
        break;
    }
    selectMore();
}

void
PeerSelector::CheckAlwaysDirectDone(allow_t answer, void *data)
{
    static_cast<PeerSelector*>(data)->checkAlwaysDirectDone(answer);
}

/// \returns true (after destroying "this") if the peer initiator is gone
/// \returns false (without side effects) otherwise
bool
PeerSelector::selectionAborted()
{
    if (callback_ && !callback_->canceled())
        return false;

    debugs(44, 3, "Aborting peer selection: Initiator gone or lost interest.");
    return true;
}

static void
checkLastPeerAccessWrapper(allow_t answer, void *data)
{
    PeerSelector *selector = static_cast<PeerSelector *>(data);
    selector->checkLastPeerAccess(answer);
}

void
PeerSelector::checkLastPeerAccess(allow_t answer)
{
    FwdServer *fs = servers;
    assert(fs);
    bool peerGone = fs->_peer.raw() && ! fs->_peer.valid();

    if (answer.denied() || peerGone) {
        currentServer = currentServer->next;
        selectMore();
        return;
    }

    if (fs->_peer.valid()) {
        if (fs->code == CD_PARENT_HIT || fs->code == CD_SIBLING_HIT || fs->code == CLOSEST_PARENT) {
#if USE_CACHE_DIGESTS
            if (fs->code == CD_PARENT_HIT || fs->code == CD_SIBLING_HIT) {
                // Will overwrite previous state:
                peerNoteDigestLookup(request, fs->_peer.get(), LOOKUP_HIT);
                // If none selected and digestLookup not updates the default values
                // in request->hier should be enough.
            }
#endif
            // Do not ping for peers if any of the above peer types succeed
            if (entry && entry->ping_status == PING_NONE)
                entry->ping_status = PING_DONE;
        } else if (fs->code == WEIGHTED_ROUNDROBIN_PARENT && fs->_peer->options.weighted_roundrobin)
            updateWeightedRoundRobinParent(fs->_peer.get(), request);
        else if (fs->code == ROUNDROBIN_PARENT && fs->_peer->options.roundrobin)
            updateRoundRobinParent(fs->_peer.get());
    }

    if (callback_ != nullptr) {
        callback(fs->_peer.get(), fs->code);
        currentServer = currentServer->next;
    }
}

void
PeerSelector::sendNextPeer()
{
    if (selectionAborted())
        return;

    if (callback_ == nullptr)
        return; //a New peer is not requested

    if (currentServer == nullptr) {
        // Done with peers
        ping.stop = current_time;
        request->hier.ping = ping; // final result

        if (callback_ != nullptr) {
            callback(nullptr, HIER_NONE);
        }
        return;
    }

    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we must use only the original client destination when going DIRECT
    // on intercepted traffic which failed Host verification
    const HttpRequest *req = request;
    const bool isIntercepted = !req->flags.redirected &&
        (req->flags.intercepted || req->flags.interceptTproxy);
    const bool useOriginalDst = Config.onoff.client_dst_passthru || !req->flags.hostVerified;
    const bool choseDirect = currentServer && currentServer->code == HIER_DIRECT;
    if (isIntercepted && useOriginalDst && choseDirect) {
        callback(nullptr, ORIGINAL_DST);

        currentServer = currentServer->next;
        return;
    }

    // Exclude from acl check pinged servers, because checked
    // before pinged
    bool checked = currentServer->code == PARENT_HIT ||
        currentServer->code == SIBLING_HIT ||
        currentServer->code == CLOSEST_PARENT_MISS ||
        currentServer->code == FIRST_PARENT_MISS;
    bool needsAclCheck = !checked && currentServer->_peer.valid() && currentServer->_peer->access;
    if (needsAclCheck) {
        ACLFilledChecklist *checklist = new ACLFilledChecklist(currentServer->_peer->access, request, NULL);
        checklist->nonBlockingCheck(checkLastPeerAccessWrapper, this);
    } else
        checkLastPeerAccess(ACCESS_ALLOWED);
}

int
PeerSelector::checkNetdbDirect()
{
#if USE_ICMP
    CachePeer *p;
    int myrtt;
    int myhops;

    if (direct == DIRECT_NO)
        return 0;

    /* base lookup on RTT and Hops if ICMP NetDB is enabled. */

    myrtt = netdbHostRtt(request->url.host());
    debugs(44, 3, "MY RTT = " << myrtt << " msec");
    debugs(44, 3, "minimum_direct_rtt = " << Config.minDirectRtt << " msec");

    if (myrtt && myrtt <= Config.minDirectRtt)
        return 1;

    myhops = netdbHostHops(request->url.host());

    debugs(44, 3, "MY hops = " << myhops);
    debugs(44, 3, "minimum_direct_hops = " << Config.minDirectHops);

    if (myhops && myhops <= Config.minDirectHops)
        return 1;

    p = whichPeer(closest_parent_miss);

    if (p == NULL)
        return 0;

    debugs(44, 3, "closest_parent_miss RTT = " << ping.p_rtt << " msec");

    if (myrtt && myrtt <= ping.p_rtt)
        return 1;

#endif /* USE_ICMP */

    return 0;
}

void
PeerSelector::selectMore()
{
    if (selectionAborted())
        return;

    if (currentServer)
        sendNextPeer();

    debugs(44, 3, request->method << ' ' << request->url.host());

    /** If we don't know whether DIRECT is permitted ... */
    if (direct == DIRECT_UNKNOWN) {
        if (always_direct == ACCESS_DUNNO) {
            debugs(44, 3, "direct = " << DirectStr[direct] << " (always_direct to be checked)");
            /** check always_direct; */
            ACLFilledChecklist *ch = new ACLFilledChecklist(Config.accessList.AlwaysDirect, request, NULL);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request, nullptr);
            acl_checklist->nonBlockingCheck(CheckAlwaysDirectDone, this);
            return;
        } else if (never_direct == ACCESS_DUNNO) {
            debugs(44, 3, "direct = " << DirectStr[direct] << " (never_direct to be checked)");
            /** check never_direct; */
            ACLFilledChecklist *ch = new ACLFilledChecklist(Config.accessList.NeverDirect, request, NULL);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request, nullptr);
            acl_checklist->nonBlockingCheck(CheckNeverDirectDone, this);
            return;
        } else if (request->flags.noDirect) {
            /** if we are accelerating, direct is not an option. */
            direct = DIRECT_NO;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (forced non-direct)");
        } else if (request->flags.loopDetected) {
            /** if we are in a forwarding-loop, direct is not an option. */
            direct = DIRECT_YES;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (forwarding loop detected)");
        } else if (checkNetdbDirect()) {
            direct = DIRECT_YES;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (checkNetdbDirect)");
        } else {
            direct = DIRECT_MAYBE;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (default)");
        }

        debugs(44, 3, "direct = " << DirectStr[direct]);
    }

    if (selectionState == DoPreselection) {
        if (!entry || entry->ping_status == PING_NONE)
            selectPinned();

        if (entry && entry->ping_status == PING_NONE)
            selectSomeNeighbor();

        selectionState = DoPing;
        if (currentServer) {
            sendNextPeer();
            return;
        }
    }

    if (selectionState == DoPing) {
        if (entry) {
            if (entry->ping_status == PING_NONE && doIcpPing())
                return;

            selectionState = DoFinal;

            if (entry->ping_status == PING_WAITING) {
                selectSomeNeighborReplies();
                entry->ping_status = PING_DONE;
                // Continue resolving requests
                sendNextPeer();
                return;
            }
        }
    }

    if (selectionState == DoFinal) {

        switch (direct) {

        case DIRECT_YES:
            selectSomeDirect();
            break;

        case DIRECT_NO:
            selectSomeParent();
            selectAllParents();
            break;

        default:

            if (Config.onoff.prefer_direct)
                selectSomeDirect();

            if (request->flags.hierarchical || !Config.onoff.nonhierarchical_direct) {
                selectSomeParent();
                selectAllParents();
            }

            if (!Config.onoff.prefer_direct)
                selectSomeDirect();

            break;
        }
        selectionState = DoFinished;
    }
    // end peer selection; start resolving selected peers
    sendNextPeer();
}

void
PeerSelector::requestPeer(AsyncCall::Pointer &call)
{
    assert(callback_ == nullptr);
    callback_ = call;
    selectMore();
}

bool peerAllowedToUse(const CachePeer *, PeerSelector*);

/// Selects a pinned connection if it exists, is valid, and is allowed.
void
PeerSelector::selectPinned()
{
    // TODO: Avoid all repeated calls. Relying on PING_DONE is not enough.
    if (!request->pinnedConnection())
        return;
    CachePeer *pear = request->pinnedConnection()->pinnedPeer();
    if (Comm::IsConnOpen(request->pinnedConnection()->validatePinnedConnection(request, pear))) {
        const bool usePinned = pear ? peerAllowedToUse(pear, this) : (direct != DIRECT_NO);
        //TODO: we must check for acls. Check if addSelection adds to the list which does it.
        if (usePinned) {
            addSelection(pear, PINNED);
            if (entry)
                entry->ping_status = PING_DONE; // skip ICP
        }
    }
    // If the pinned connection is prohibited (for this request) or gone, then
    // the initiator must decide whether it is OK to open a new one instead.
}

/**
 * Selects a neighbor (parent or sibling) based on one of the
 * following methods:
 *      Cache Digests
 *      CARP
 *      ICMP Netdb RTT estimates
 *      ICP/HTCP queries
 */
void
PeerSelector::selectSomeNeighbor()
{
    assert(entry->ping_status == PING_NONE);

    if (direct == DIRECT_YES) {
        entry->ping_status = PING_DONE;
        return;
    }

#if USE_CACHE_DIGESTS
    neighborsDigestSelect(this);
#endif
    netdbClosestParent(this, request);
}

static void
checkNextPingNeighborAccessWrapper(allow_t answer, void *data)
{
    PeerSelector *selector = static_cast<PeerSelector *>(data);
    selector->checkNextPingNeighborAccess(answer);
}

void
PeerSelector::checkNextPingNeighborAccess(allow_t answer)
{
    if (CachePeer *p = pingPeers.front().valid()) {
        pingPeers.erase(pingPeers.begin());
        if (neighborUdpPing(p, ping.reqnum, request, entry, HandlePingReply, this)) {
            ++ping.n_sent;
            entry->ping_status = PING_WAITING;

            if (p->type == PEER_MULTICAST) {
                ping.n_replies_expected += p->mcast.n_replies_expected;
                ping.n_mcast_replies_expect += p->mcast.n_replies_expected;
                ping.mcast_rtt += (p->stats.rtt * p->mcast.n_replies_expected);
            } else if (neighborUp(p)) {
                /* its alive, expect a reply from it */
                ++ping.n_replies_expected;
                if (neighborType(p, request->url) == PEER_PARENT) {
                    ++ping.n_parent_replies_expect;
                    ping.parent_rtt += p->stats.rtt;
                } else {
                    ++ping.n_sibling_replies_expect;
                    ping.sibling_rtt += p->stats.rtt;
                }
            }
        }
    }

    if (!doIcpPing()) {
        if (ping.n_sent == 0) {
            debugs(44, DBG_CRITICAL, "WARNING: neighborsUdpPing returned 0");
            selectMore();
            return;
        }

        debugs(44, 3, ping.n_replies_expected <<
               " ICP replies expected, RTT " << ping.timeout <<
               " msec");
        if (ping.n_replies_expected > 0) {
            /*
             * If there is a configured timeout, use it
             */
            if (Config.Timeout.icp_query)
                ping.timeout = Config.Timeout.icp_query;
            else {
                if (ping.n_replies_expected > 0) {
                    if (ping.n_parent_replies_expect)
                        ping.timeout = 2 * ping.parent_rtt / ping.n_parent_replies_expect;
                    else if (ping.n_mcast_replies_expect)
                        ping.timeout = 2 * ping.mcast_rtt / ping.n_mcast_replies_expect;
                    else
                        ping.timeout = 2 * ping.sibling_rtt / ping.n_sibling_replies_expect;
                } else
                    ping.timeout = 2000;    /* 2 seconds */

                if (Config.Timeout.icp_query_max)
                    if (ping.timeout > Config.Timeout.icp_query_max)
                        ping.timeout = Config.Timeout.icp_query_max;

                if (ping.timeout < Config.Timeout.icp_query_min)
                    ping.timeout = Config.Timeout.icp_query_min;
            }

            eventAdd("PeerSelector::HandlePingTimeout",
                     HandlePingTimeout,
                     this,
                     0.001 * ping.timeout,
                     0);
        }
    }
}

bool
PeerSelector::doIcpPing()
{
    if (icpPingNeighbors()) {
        debugs(44, 3, "Doing ICP pings");
        while (!pingPeers.front().valid())
            pingPeers.erase(pingPeers.begin());

        if (pingPeers.size()) {
            CachePeer *p = pingPeers.front().get();
            if (ping.start.tv_sec == 0) {
                ping.start = current_time;
                ping.reqnum = icpSetCacheKey((const cache_key *)entry->key);

                MemObject *mem = entry->mem_obj;
                assert(entry->swap_status == SWAPOUT_NONE);
                mem->start_ping = current_time;
                mem->ping_reply_callback = HandlePingReply;
                mem->ircb_data = this;
            }
            if (p->access) {
                ACLFilledChecklist *checklist = new ACLFilledChecklist(p->access, request, NULL);
                checklist->nonBlockingCheck(checkNextPingNeighborAccessWrapper, this);
            } else
                checkNextPingNeighborAccess(ACCESS_ALLOWED);
            return true;
        }
    }

    entry->ping_status = PING_DONE;
    return false;
}

/// Selects a neighbor (parent or sibling) based on ICP/HTCP replies.
void
PeerSelector::selectSomeNeighborReplies()
{
    CachePeer *p = NULL;
    hier_code code = HIER_NONE;
    assert(entry->ping_status == PING_WAITING);
    assert(direct != DIRECT_YES);

    if (checkNetdbDirect()) {
        code = CLOSEST_DIRECT;
        addSelection(nullptr, code);
        return;
    }

    if ((p = hit)) {
        code = hit_type == PEER_PARENT ? PARENT_HIT : SIBLING_HIT;
    } else {
        if (!closest_parent_miss.isAnyAddr()) {
            p = whichPeer(closest_parent_miss);
            code = CLOSEST_PARENT_MISS;
        } else if (!first_parent_miss.isAnyAddr()) {
            p = whichPeer(first_parent_miss);
            code = FIRST_PARENT_MISS;
        }
    }
    if (p && code != HIER_NONE) {
        addSelection(p, code);
    }
}

/// Adds a "direct" entry if the request can be forwarded to the origin server.
void
PeerSelector::selectSomeDirect()
{
    if (direct == DIRECT_NO)
        return;

    /* WAIS is not implemented natively */
    if (request->url.getScheme() == AnyP::PROTO_WAIS)
        return;

    addSelection(nullptr, HIER_DIRECT);
}

void
PeerSelector::selectSomeParent()
{
    debugs(44, 3, request->method << ' ' << request->url.host());

    if (direct == DIRECT_YES)
        return;

    peerSourceHashSelectParent(this);
#if USE_AUTH
    peerUserHashSelectParent(this);
#endif
    carpSelectParent(this);

    getRoundRobinParent(this);

    getWeightedRoundRobinParent(this);

    getFirstUpParent(this);

    getDefaultParent(this);
}

/// Adds alive parents. Used as a last resort for never_direct.
void
PeerSelector::selectAllParents()
{
    CachePeer *p;
    /* Add all alive parents */

    for (p = Config.peers; p; p = p->next) {
        /* XXX: neighbors.c lacks a public interface for enumerating
         * parents to a request so we have to dig some here..
         */

        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, this))
            continue;

        addSelection(p, ANY_OLD_PARENT);
    }

    /* XXX: should add dead parents here, but it is currently
     * not possible to find out which parents are dead or which
     * simply are not configured to handle the request.
     */
    /* Add default parent as a last resort */
    retrieveDefaultParentsGroup(this);
}

void
PeerSelector::handlePingTimeout()
{
    debugs(44, 3, url());

    if (entry)
        entry->ping_status = PING_DONE;

    if (selectionAborted())
        return;

    ++PeerStats.timeouts;
    ping.timedout = 1;
    selectMore();
}

void
PeerSelector::HandlePingTimeout(void *data)
{
    static_cast<PeerSelector*>(data)->handlePingTimeout();
}

void
peerSelectInit(void)
{
    memset(&PeerStats, '\0', sizeof(PeerStats));
}

void
PeerSelector::handleIcpParentMiss(CachePeer *p, icp_common_t *header)
{
    int rtt;

#if USE_ICMP
    if (Config.onoff.query_icmp) {
        if (header->flags & ICP_FLAG_SRC_RTT) {
            rtt = header->pad & 0xFFFF;
            int hops = (header->pad >> 16) & 0xFFFF;

            if (rtt > 0 && rtt < 0xFFFF)
                netdbUpdatePeer(request->url, p, rtt, hops);

            if (rtt && (ping.p_rtt == 0 || rtt < ping.p_rtt)) {
                closest_parent_miss = p->in_addr;
                ping.p_rtt = rtt;
            }
        }
    }
#endif /* USE_ICMP */

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (!closest_parent_miss.isAnyAddr())
        return;

    rtt = (tvSubMsec(ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (first_parent_miss.isAnyAddr() || rtt < ping.w_rtt) {
        first_parent_miss = p->in_addr;
        ping.w_rtt = rtt;
    }
}

void
PeerSelector::handleIcpReply(CachePeer *p, const peer_t type, icp_common_t *header)
{
    icp_opcode op = header->getOpCode();
    debugs(44, 3, icp_opcode_str[op] << ' ' << url());
#if USE_CACHE_DIGESTS && 0
    /* do cd lookup to count false misses */

    if (p && request)
        peerNoteDigestLookup(request, p,
                             peerDigestLookup(p, this));

#endif

    ++ping.n_recv;

    if (op == ICP_MISS || op == ICP_DECHO) {
        if (type == PEER_PARENT)
            handleIcpParentMiss(p, header);
    } else if (op == ICP_HIT) {
        hit = p;
        hit_type = type;
        selectMore();
        return;
    }

    if (ping.n_recv < ping.n_replies_expected)
        return;

    selectMore();
}

#if USE_HTCP
void
PeerSelector::handleHtcpReply(CachePeer *p, const peer_t type, HtcpReplyData *htcp)
{
    debugs(44, 3, (htcp->hit ? "HIT" : "MISS") << ' ' << url());
    ++ping.n_recv;

    if (htcp->hit) {
        hit = p;
        hit_type = type;
        selectMore();
        return;
    }

    if (type == PEER_PARENT)
        handleHtcpParentMiss(p, htcp);

    if (ping.n_recv < ping.n_replies_expected)
        return;

    selectMore();
}

void
PeerSelector::handleHtcpParentMiss(CachePeer *p, HtcpReplyData *htcp)
{
    int rtt;

#if USE_ICMP
    if (Config.onoff.query_icmp) {
        if (htcp->cto.rtt > 0) {
            rtt = (int) htcp->cto.rtt * 1000;
            int hops = (int) htcp->cto.hops * 1000;
            netdbUpdatePeer(request->url, p, rtt, hops);

            if (rtt && (ping.p_rtt == 0 || rtt < ping.p_rtt)) {
                closest_parent_miss = p->in_addr;
                ping.p_rtt = rtt;
            }
        }
    }
#endif /* USE_ICMP */

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (!closest_parent_miss.isAnyAddr())
        return;

    rtt = (tvSubMsec(ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (first_parent_miss.isAnyAddr() || rtt < ping.w_rtt) {
        first_parent_miss = p->in_addr;
        ping.w_rtt = rtt;
    }
}

#endif

void
PeerSelector::HandlePingReply(CachePeer * p, peer_t type, AnyP::ProtocolType proto, void *pingdata, void *data)
{
    if (proto == AnyP::PROTO_ICP)
        static_cast<PeerSelector*>(data)->handleIcpReply(p, type, static_cast<icp_common_t*>(pingdata));

#if USE_HTCP

    else if (proto == AnyP::PROTO_HTCP)
        static_cast<PeerSelector*>(data)->handleHtcpReply(p, type, static_cast<HtcpReplyData*>(pingdata));

#endif

    else
        debugs(44, DBG_IMPORTANT, "ERROR: ignoring an ICP reply with unknown protocol " << proto);
}

void
PeerSelector::addSelection(CachePeer *peer, const hier_code code)
{
    // Find the end of the servers list. Bail on a duplicate destination.
    auto **serversTail = &servers;
    while (const auto server = *serversTail) {
        // There can be at most one PINNED destination.
        // Non-PINNED destinations are uniquely identified by their CachePeer
        // (even though a DIRECT destination might match a cache_peer address).
        const bool duplicate = (server->code == PINNED) ?
                               (code == PINNED) : (server->_peer == peer);
        if (duplicate) {
            debugs(44, 3, "skipping " << PeerSelectionDumper(this, peer, code) <<
                   "; have " << PeerSelectionDumper(this, server->_peer.get(), server->code));
            return;
        }
        serversTail = &server->next;
    }

    debugs(44, 3, "adding " << PeerSelectionDumper(this, peer, code));
    *serversTail = new FwdServer(peer, code);

    if (currentServer == nullptr)
        currentServer = *serversTail;
}

PeerSelector::PeerSelector():
    request(nullptr),
    entry (NULL),
    always_direct(Config.accessList.AlwaysDirect?ACCESS_DUNNO:ACCESS_DENIED),
    never_direct(Config.accessList.NeverDirect?ACCESS_DUNNO:ACCESS_DENIED),
    direct(DIRECT_UNKNOWN),
    servers (NULL),
    first_parent_miss(),
    closest_parent_miss(),
    hit(NULL),
    hit_type(PEER_NONE),
    acl_checklist (NULL)
{
    ; // no local defaults.
}

const SBuf
PeerSelector::url() const
{
    if (entry)
        return SBuf(entry->url());

    if (request)
        return request->effectiveRequestUri();

    static const SBuf noUrl("[no URL]");
    return noUrl;
}

void
PeerSelector::callback(CachePeer *peer, const hier_code code)
{
    request->hier.ping = ping;

    if (code == HIER_NONE)
        debugs(44, 2, id << " found all " << foundPeers << " peers for " << url());
    else
        debugs(44, 2, id << " found peer " << (peer ? peer->name : "direct") << ", " << foundPeers << " peer for " << url());
    debugs(44, 2, "  always_direct = " << always_direct);
    debugs(44, 2, "   never_direct = " << never_direct);
    debugs(44, 2, "       timedout = " << ping.timedout);

    assert(callback_);
    CbDialer *dialer = dynamic_cast<CbDialer*>(callback_->getDialer());
    dialer->peer_ = peer;
    dialer->code_ = code;
    ScheduleCallHere(callback_);
    callback_ = nullptr;
    if (code != HIER_NONE)
        ++foundPeers;
}

InstanceIdDefinitions(PeerSelector, "PeerSelector");

ping_data::ping_data() :
    reqnum(0),
    n_sent(0),
    n_recv(0),
    n_mcast_replies_expect(0),
    n_parent_replies_expect(0),
    n_sibling_replies_expect(0),
    n_replies_expected(0),
    timeout(0),
    mcast_rtt(0),
    parent_rtt(0),
    sibling_rtt(0),
    timedout(0),
    w_rtt(0),
    p_rtt(0)
{
    start.tv_sec = 0;
    start.tv_usec = 0;
    stop.tv_sec = 0;
    stop.tv_usec = 0;
}

