#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "base/RunnersRegistry.h"
#include "CachePeer.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "Debug.h"
#include "fd.h"
#include "FwdState.h"
#include "globals.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(PeerPoolMgr);

PeerPoolMgr::PeerPoolMgr(CachePeer *aPeer): AsyncJob("PeerPoolMgr"),
        peer(cbdataReference(aPeer)),
        opener(),
        addrUsed(0)
{
}

PeerPoolMgr::~PeerPoolMgr()
{
    cbdataReferenceDone(peer);
}

void
PeerPoolMgr::start()
{
    AsyncJob::start();
    checkpoint("peer initialized");
}

void
PeerPoolMgr::swanSong()
{
    AsyncJob::swanSong();
}

/// whether the peer is still out there and in a valid state we can safely use
bool
PeerPoolMgr::validPeer() const {
    return peer && cbdataReferenceValid(peer) && peer->standby.pool;
}

bool
PeerPoolMgr::doneAll() const
{
    return !(validPeer() && peer->standby.limit) && AsyncJob::doneAll();
}

/// Comm::ConnOpener calls this when done opening a connection for us
void
PeerPoolMgr::handleOpenedConnection(const CommConnectCbParams &params)
{
    opener = NULL;

    if (!validPeer()) {
        debugs(48, 3, "peer gone");
        if (params.conn != NULL)
            params.conn->close();
        return;
    }

    if (params.flag != COMM_OK) {
        /* it might have been a timeout with a partially open link */
        if (params.conn != NULL)
            params.conn->close();
        peerConnectFailed(peer);
        checkpoint("conn opening failure"); // may retry
        return;
    }

    Must(params.conn != NULL);

    // TODO: Handle SSL peers.

    peer->standby.pool->push(params.conn, NULL /* domain */);
    // push() will trigger a checkpoint()
}

/// starts the process of opening a new standby connection (if possible)
void
PeerPoolMgr::openNewConnection()
{
    // KISS: Do nothing else when we are already doing something.
    if (opener != NULL || shutting_down) {
        debugs(48, 7, "busy: " << opener << '|' << shutting_down);
        return; // there will be another checkpoint when we are done opening
    }

    // Do not talk to a peer until it is ready.
    if (!neighborUp(peer)) // provides debugging
        return; // there will be another checkpoint when peer is up

    // Do not violate peer limits.
    if (!peerCanOpenMore(peer)) { // provides debugging
        peer->standby.waitingForClose = true; // may already be true
        return; // there will be another checkpoint when a peer conn closes
    }

    // Do not violate global restrictions.
    if (fdUsageHigh()) {
        debugs(48, 7, "overwhelmed");
        peer->standby.waitingForClose = true; // may already be true
        // There will be another checkpoint when a peer conn closes OR when
        // a future pop() fails due to an empty pool. See PconnPool::pop().
        return;
    }

    peer->standby.waitingForClose = false;

    Comm::ConnectionPointer conn = new Comm::Connection;
    Must(peer->n_addresses); // guaranteed by neighborUp() above
    // cycle through all available IP addresses
    conn->remote = peer->addresses[addrUsed++ % peer->n_addresses];
    conn->remote.port(peer->http_port);
    conn->peerType = STANDBY_POOL; // should be reset by peerSelect()
    conn->setPeer(peer);
    getOutgoingAddress(NULL /* request */, conn);
    GetMarkingsToServer(NULL /* request */, *conn);

    const int ctimeout = peer->connect_timeout > 0 ?
                         peer->connect_timeout : Config.Timeout.peer_connect;
    typedef CommCbMemFunT<PeerPoolMgr, CommConnectCbParams> Dialer;
    opener = JobCallback(48, 5, Dialer, this, PeerPoolMgr::handleOpenedConnection);
    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, opener, ctimeout);
    AsyncJob::Start(cs);
}

void
PeerPoolMgr::closeOldConnections(const int howMany)
{
    debugs(48, 8, howMany);
    peer->standby.pool->closeN(howMany);
}

void
PeerPoolMgr::checkpoint(const char *reason)
{
    if (!validPeer()) {
        debugs(48, 3, reason << " and peer gone");
        return; // nothing to do after our owner dies; the job will quit
    }

    const int count = peer->standby.pool->count();
    const int limit = peer->standby.limit;
    debugs(48, 7, reason << " with " << count << " ? " << limit);

    if (count < limit)
        openNewConnection();
    else if (count > limit)
        closeOldConnections(count - limit);
}

void
PeerPoolMgr::Checkpoint(const Pointer &mgr, const char *reason)
{
    CallJobHere1(48, 5, mgr, PeerPoolMgr, checkpoint, reason);
}

/// launches PeerPoolMgrs for peers configured with standby.limit
class PeerPoolMgrsRr: public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void run(const RunnerRegistry &r) { sync(r); }
    virtual void sync(const RunnerRegistry &r);
};

RunnerRegistrationEntry(rrAfterConfig, PeerPoolMgrsRr);

void
PeerPoolMgrsRr::sync(const RunnerRegistry &)
{
    for (CachePeer *p = Config.peers; p; p = p->next) {
        // On reconfigure, Squid deletes the old config (and old peers in it),
        // so should always be dealing with a brand new configuration.
        assert(!p->standby.mgr);
        assert(!p->standby.pool);
        if (p->standby.limit) {
            p->standby.mgr = new PeerPoolMgr(p);
            p->standby.pool = new PconnPool(p->name, p->standby.mgr);
            AsyncJob::Start(p->standby.mgr.get());
        }
    }
}
