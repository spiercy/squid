#include "squid.h"
#include "CachePeer.h"
#include "FwdState.h"
#include "HappyConnOpener.h"
#include "HttpRequest.h"
#include "ip/QosConfig.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(HappyConnOpener);

static PconnPool *fwdPconnPool = new PconnPool("server-peers", NULL);

int HappyConnOpener::SpareConnects = 0;
double HappyConnOpener::LastSpareAttempt = 0;

/// Manages a queue of HappyConnOpeners objects waiting the preconditions
/// to be satisfied in order to start an attempt for a new spare connection
class HappyConnQueue {
public:
    /// Schedule the next check for starting new connection attempts
    void scheduleConnectorsListCheck();

    /// \return pointer to the first valid connector in queue or nil
    //const HappyConnOpener::Pointer &frontOpener();
    void kickSparesLimitQueue();

    AsyncCall::Pointer queueASpareConnection(HappyConnOpener::Pointer happy);

    /// The time period after which the next spare connection can be started
    /// It takes in account the happy_eyeballs_connect_gap and the
    /// happy_eyeballs_connect_timeout.
    double spareMayStartAfter(const HappyConnOpener::Pointer &happy) const;

    ///< \return true if the happy_eyeballs_connect_timeout precondition
    /// satisfied
    bool primaryConnectTooSlow(const HappyConnOpener::Pointer &happy) const;

    /// The configured connect_limit per worker basis
    static int ConnectLimit();

    /// The configured connect_gap per worker basis
    static int ConnectGap();

    /// True if the system preconditions for starting a new spare connection
    /// which defined by happy_eyeballs_connect_limit configuration parameter
    /// is satisfied.
    static bool GapRule();

    /// True if the system preconditions for starting a new spare connection
    /// which defined by happy_eyeballs_connect_gap configuration parameter
    /// is satisfied
    static bool ConnectionsLimitRule();

    /// Event which checks for the next spare connection
    static void SpareConnectionAttempt(void *data);

    /// The list of connectors waiting to start a new spare connection attempt
    /// when system and current request preconditions satisfied.
    std::list<AsyncCall::Pointer> waitingForSpareQueue;
    std::list<AsyncCall::Pointer> sparesLimitQueue;

    bool waitEvent = false;
};

HappyConnQueue HappyQueue;

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer)
{
    return os << answer.conn << ", " << answer.ioStatus << ", " << answer.xerrno << ", " << (answer.reused ? "reused" : "new");
}

HappyConnOpener::HappyConnOpener(const CandidatePaths::Pointer &destinations, const AsyncCall::Pointer &aCall, const time_t fwdStart, int tries):
    AsyncJob("HappyConnOpener"),
    useTos(0),
    useNfmark(0),
    callback_(aCall),
    dests_(destinations),
    allowPconn_(true),
    retriable_(true),
    sparePermitted(false),
    host_(nullptr),
    fwdStart_(fwdStart),
    maxTries(tries),
    n_tries(0)
{
    assert(dynamic_cast<HappyConnOpener::CbDialer *>(callback_->getDialer()));
}

HappyConnOpener::~HappyConnOpener()
{
    safe_free(host_);
    debugs(17,5, "destroyed");
}

void
HappyConnOpener::setHost(const char *h)
{
    safe_free(host_);
    if (h)
        host_ = xstrdup(h);
}

void
HappyConnOpener::start()
{
    debugs(17, 8, "Start connecting");
    checkForNewConnection();
}

bool
HappyConnOpener::doneAll() const
{
    if (!callback_ || callback_->canceled())
        return AsyncJob::doneAll();
    return false;
}

void
HappyConnOpener::swanSong()
{
    debugs(17,5, "HappyConnOpener::swanSong: Job finished, cleanup");
    if (callback_) {
        callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "unexpected end");
    }

    // TODO: These call cancellations should not be needed.
    if (waitingForSparePermission)
        waitingForSparePermission->cancel("HappyConnOpener object destructed");

    if (master.path) {
        if (master.connector)
            master.connector->cancel("HappyConnOpener object destructed");
        master.connector = nullptr;
        master.path = nullptr;
    }

    if (!spare.path) {
        if (spare.connector)
            spare.connector->cancel("HappyConnOpener object destructed");
        spare.connector = nullptr;
        spare.path = nullptr;
    }

    AsyncJob::swanSong();
}

void
HappyConnOpener::callCallback(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno, bool reused, const char *msg)
{
    if (callback_ && !callback_->canceled()) {
        HappyConnOpener::CbDialer *cd = dynamic_cast<HappyConnOpener::CbDialer *>(callback_->getDialer());
        cd->answer_.conn = conn;
        cd->answer_.host = nullptr;
        cd->answer_.ioStatus = err;
        cd->answer_.xerrno = xerrno;
        cd->answer_.status = msg;
        cd->answer_.n_tries = n_tries;
        cd->answer_.reused = reused;
        ScheduleCallHere(callback_);
    }
    callback_ = nullptr;
}

void
HappyConnOpener::noteCandidatesChange()
{
    assert(dests_);
    debugs(17, 7, "destinations: " << dests_->size() << " finalized: " << dests_->destinationsFinalized);
    checkForNewConnection();
}

// XXX: Rename pconn into something that does not clash with "persistent connection"
void
HappyConnOpener::startConnecting(PendingConnection &pconn, Comm::ConnectionPointer &dest)
{
    Must(!pconn.path);
    Must(!pconn.connector);

    // Use pconn to avoid opening a new connection.
    Comm::ConnectionPointer temp;
    if (allowPconn_)
        temp = PconnPop(dest, (dest->getPeer() ? nullptr : host_), retriable_);

    const bool openedPconn = Comm::IsConnOpen(temp);

    // if we found an open persistent connection to use. use it.
    if (openedPconn) {
        pconn.path = temp;
        pconn.connector = nullptr;
        ++n_tries;
        callCallback(temp, Comm::OK, 0, true, "reusing pconn");
        return;
    }

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    //GetMarkingsToServer(request, *dest);
    dest->tos = useTos;
    dest->nfmark = useNfmark;

    dest->local.port(0);
    ++n_tries;

    typedef CommCbMemFunT<HappyConnOpener, CommConnectCbParams> Dialer;
    AsyncCall::Pointer callConnect = JobCallback(48, 5, Dialer, this, HappyConnOpener::connectDone);
    const time_t connTimeout = dest->connectTimeout(fwdStart_);
    Comm::ConnOpener *cs = new Comm::ConnOpener(dest, callConnect, connTimeout);
    if (!dest->getPeer())
        cs->setHost(host_);

    pconn.path = dest;
    pconn.connector = callConnect;

    lastAttemptTime = current_dtime;
    AsyncJob::Start(cs);
}

void
HappyConnOpener::connectDone(const CommConnectCbParams &params)
{
    Must(params.conn);
    const bool itWasMaster = (params.conn == master.path);
    const bool itWasSpare = (params.conn == spare.path);
    Must(itWasMaster != itWasSpare);
    const char *what = itWasMaster ? "master connection" : "spare connection";

    if (itWasMaster) {
        master.path = nullptr;
        master.connector = nullptr;
    } else {
        spare.path = nullptr;
        spare.connector = nullptr;
        --SpareConnects;
        HappyQueue.kickSparesLimitQueue();
    }

    if (params.flag == Comm::OK) {
        callCallback(params.conn, Comm::OK, 0, false, what);
        return;
    }

    debugs(17, 8, what << " failed: " << params.conn);
    if (const auto peer = params.conn->getPeer())
        peerConnectFailed(peer);
    params.conn->close(); // TODO: Comm::ConnOpener should do this instead.
    lastFailure = params.conn;

    // XXX: Some of this logic is wrong: If a master connection failed, and we
    // do not have any spare paths to try, but we do have another master-family,
    // same-peer path to try, then we should do another master attempt while
    // still waiting for spare addresses. More related concerns below.
    // Test case: a4.down4.up4.a6.happy.test

    // TODO: When the first connection has failed, switch to
    // one-connection-at-a-time no-wait mode, alternating families.

    if (itWasMaster) {
        if (spare.connector) {
            // adjust spare connection accounting since we are going to convert
            // this spare connection attempt into a master connection attempt
            --SpareConnects;
            HappyQueue.kickSparesLimitQueue();
        }

        std::swap(master, spare); // use spare (if any) as the new master

        // We do not want to also transfer the current wait (or permission) to
        // speed up the future spare attempt because the same-family attempt has
        // just failed. Most likely, this family is not working.

        // XXX: However, this only works well if there are spare-family
        // addresses to try immediately. If we have only failed-family addresses
        // (for the same peer), then this clearing will only delay future spare
        // attempts. TODO: We should remember which family failed and give the
        // other family a priority when its same-peer addresses arrive.
        if (waitingForSparePermission) {
            assert(!spare.path); // paranoid; the swap above guarantees this
            waitingForSparePermission->cancel("master failure");
            waitingForSparePermission = nullptr;
        }
        sparePermitted = false;
    } else {
        Must(!waitingForSparePermission);
        Must(sparePermitted);
        // the master (if any) may continue its connection attempt
        // and/or we may try to open another spare
    }

    checkForNewConnection();
}

/// \returns usable master path (if possible) or nil (on failures)
/// reports permanent failures to the job initiator
Comm::ConnectionPointer
HappyConnOpener::extractMasterCandidatePath()
{
    if (!dests_->empty()) {
        const auto dest = dests_->popFirst();
        Must(dest);
        return dest;
    }

    if (!dests_->destinationsFinalized)
        return Comm::ConnectionPointer(); // may get one later

    /* permanent failure */
    callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "Found no usable destinations");
    return Comm::ConnectionPointer();
}

/// returns usable spare path (if possible) or nil (on temporary failures)
/// no failures can be permanent -- there is an ongoing master attempt
Comm::ConnectionPointer
HappyConnOpener::extractSpareCandidatePath()
{
    Must(master);
    return dests_->popIfDifferentFamily(*master.path); // may return nil
}

void
HappyConnOpener::checkForNewConnection()
{
    assert(dests_); // TODO: remove this and others
    debugs(17, 7, "destinations: " << dests_->size() << " finalized: " << dests_->destinationsFinalized);

    if (lastFailure)
        return ensureRecoveryConnection();

    if (!master)
        return ensureMasterConnection();

    if (!spare)
        return ensureSpareConnection();
}

/// called when we were allowed to open one spare connection
void
HappyConnOpener::noteSpareAllowed()
{
    waitingForSparePermission = nullptr;
    sparePermitted = true;
    checkForNewConnection();
}

/**
 * Decide where details need to be gathered to correctly describe a persistent connection.
 * What is needed:
 *  -  the address/port details about this link
 *  -  domain name of server at other end of this link (either peer or requested host)
 */
void
HappyConnOpener::PconnPush(Comm::ConnectionPointer &conn, const char *domain)
{
    if (conn->getPeer()) {
        fwdPconnPool->push(conn, NULL);
    } else {
        fwdPconnPool->push(conn, domain);
    }
}

Comm::ConnectionPointer
HappyConnOpener::PconnPop(const Comm::ConnectionPointer &dest, const char *domain, bool retriable)
{
    // always call shared pool first because we need to close an idle
    // connection there if we have to use a standby connection.
    Comm::ConnectionPointer conn = fwdPconnPool->pop(dest, domain, retriable);
    if (!Comm::IsConnOpen(conn)) {
        // either there was no pconn to pop or this is not a retriable xaction
        if (CachePeer *peer = dest->getPeer()) {
            if (peer->standby.pool)
                conn = peer->standby.pool->pop(dest, domain, true);
        }
    }
    return conn; // open, closed, or nil
}

void
HappyConnOpener::ConnectionClosed(const Comm::ConnectionPointer &conn)
{
    fwdPconnPool->noteUses(fd_table[conn->fd].pconn.uses);
}

/// if possible, starts to recover from the past connection attempt failure
/// otherwise, either waits for more candidates or ends the job, as appropriate
void
HappyConnOpener::ensureRecoveryConnection()
{
    Must(lastFailure);
    if (spare)
        return; // already have two concurrent connections

    if (master && CandidatePaths::ConnectionFamily(*master.path) != CandidatePaths::ConnectionFamily(*lastFailure))
        return; // master connection may provide recovery from the last failure

    if (dests_->empty()) {
        if (dests_->destinationsFinalized && !master)
            callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "All destinations failed");
        // else wait for master and/or more same-peer path(s)
        return;
    }

    auto dest = dests_->popIfDifferentFamily(*lastFailure);

    if (!dest) {
        // Earlier check guarantees that a set master uses the failed family,
        // and we do not want to open a concurrent failed family connection.
        if (master)
            return;
        dest = dests_->popIfSamePeer(lastFailure->getPeer());
    }

    if (!dest) {
        // We are done with the same-peer paths (that all failed) because
        // there are other peer paths present already (dests_ is not empty).
        // Forget the peer-specific failure and move on to another peer.
        lastFailure = nullptr;
        return ensureMasterConnection();
    }

    debugs(17, 8, "to " << *dest);
    auto &recovery = master ? spare : master;
    startConnecting(recovery, dest);
    // XXX: Honor inter-spare gap if using spare.
    // XXX: Increment SpareConnects if using spare.
}

/// if possible, starts a master connection attempt
/// otherwise, either waits for more candidates or ends the job, as appropriate
void
HappyConnOpener::ensureMasterConnection()
{
    Must(!master);
    Must(!spare); // or that spare should have become master
    Must(!lastFailure); // or we should still be recovering the failed peer

    auto dest = extractMasterCandidatePath();
    if (!dest)
        return; // extractMasterCandidatePath() handles extraction failures

    debugs(17, 8, "to " << *dest);
    startConnecting(master, dest);

    // We may already be waiting for (or even have a permission to) open a spare
    // connection. This happens if a master connection fails while there is
    // another same-family, same-peer path available and no spare paths
    // available. We do not restart the wait (or forget the permission): Waiting
    // avoids overspending resources when the master IP family works well. Since
    // we just opened an N+1st master connection, it is the master family that
    // is failing. TODO: Should we cancel the wait (and grant permission) then?
    // Test case: a4.down4.up4.a6.happy.test

    if (sparePermitted) {
        debugs(17, 7, "already have a spare permission");
        return;
    }

    if (waitingForSparePermission) {
        debugs(17, 7, "already waiting for spare permission: " << waitingForSparePermission);
        return;
    }

    // TODO: Find a way to move this check into HappyQueue?
    if (dests_->empty() && dests_->destinationsFinalized) {
        debugs(17, 7, "no spare paths expected");
        return; // this is not a failure -- we are master-connecting
    }

    waitingForSparePermission = HappyQueue.queueASpareConnection(HappyConnOpener::Pointer(this));
}

/// if possible, starts a spare connection attempt
/// otherwise, waits for more candidates and/or spare connection allowance
void
HappyConnOpener::ensureSpareConnection()
{
    Must(master); // or we should be starting a master connection instead
    Must(!spare); // only one spare at a time
    Must(!lastFailure); // or we should still be recovering the failed peer

    // TODO: Cancel wait if no spare candidates are going to be available?

    if (!sparePermitted)
        return; // honor spare connection gap and other limits

    Must(!waitingForSparePermission);

    auto dest = extractSpareCandidatePath();
    if (!dest)
        return;

    debugs(17, 8, "to " << *dest);
    startConnecting(spare, dest);

    // TODO: Check (and explain) why only the new attempts should count.
    if (spare.connector != nullptr) { // this is a new connection attempt
        ++SpareConnects;
        LastSpareAttempt = current_dtime;
    }
}

AsyncCall::Pointer
HappyConnQueue::queueASpareConnection(HappyConnOpener::Pointer happy)
{
    if (ConnectLimit() == 0) {
        debugs(17, 8, "Spare connections are disabled");
        static AsyncCall::Pointer nil;
        return nil;
    }

    bool needsSpareNow = primaryConnectTooSlow(happy);
    bool gapRuleOK = GapRule();
    bool connectionsLimitRuleOK = ConnectionsLimitRule();
    bool startSpareNow = happy->sparesBlockedOnCandidatePaths ||
                         (needsSpareNow && gapRuleOK && connectionsLimitRuleOK);

    typedef NullaryMemFunT<HappyConnOpener> Dialer;
    AsyncCall::Pointer call = JobCallback(17, 5, Dialer, happy, HappyConnOpener::noteSpareAllowed);
    if (startSpareNow) {
        ScheduleCallHere(call);
        return call;
    }

    if (needsSpareNow && gapRuleOK /*&& !connectionsLimitRuleOK*/) {
        debugs(17, 8, "A new attempt should start as soon as possible");
        sparesLimitQueue.push_back(call);
    } else {
        debugs(17, 8, "Schedule a new attempt for later");
        waitingForSpareQueue.push_back(call);
        if (!waitEvent) // if we add the first element
            scheduleConnectorsListCheck(); // Restart queue run
    }

    return call;
}

bool
HappyConnQueue::ConnectionsLimitRule()
{
    int limit = ConnectLimit();
    return (limit < 0 || HappyConnOpener::SpareConnects < limit);
}

bool
HappyConnQueue::GapRule()
{
    return (HappyConnOpener::LastSpareAttempt <= current_dtime - (double)ConnectGap()/1000.0);
}

int
HappyConnQueue::ConnectGap()
{
    if (Config.happyEyeballs.connect_gap < 0) // no explicit configuration
        return 5; // ms per worker

    // keep opening rate in check despite the lack of SMP sharing
    return Config.happyEyeballs.connect_gap * Config.workers;
}

int
HappyConnQueue::ConnectLimit()
{
    if (Config.happyEyeballs.connect_limit <= 0)
        return Config.happyEyeballs.connect_limit;

    int limit = Config.happyEyeballs.connect_limit / Config.workers;
    return (limit == 0 ? 1 : limit);
}

double
HappyConnQueue::spareMayStartAfter(const HappyConnOpener::Pointer &happy) const
{
    double nextAttemptTime = happy->lastAttemptTime + (double)Config.happyEyeballs.connect_timeout/1000.0;
    double mgap = (double)ConnectGap()/1000.0;
    double fromLastTry = (current_dtime - HappyConnOpener::LastSpareAttempt);
    double remainGap = mgap > fromLastTry ? mgap - fromLastTry : 0.0 ;
    double startAfter = nextAttemptTime > current_dtime ?
                        max(nextAttemptTime - current_dtime, remainGap) : remainGap;
    return startAfter;
}

bool
HappyConnQueue::primaryConnectTooSlow(const HappyConnOpener::Pointer &happy) const
{
    double nextAttemptTime = happy->lastAttemptTime + (double)Config.happyEyeballs.connect_timeout/1000.0;
    return (nextAttemptTime <= current_dtime);
}

void
HappyConnQueue::SpareConnectionAttempt(void *data)
{
    HappyConnQueue *queue = static_cast<HappyConnQueue *>(data);
    queue->waitEvent = false;
    queue->scheduleConnectorsListCheck();
}

void
HappyConnQueue::scheduleConnectorsListCheck()
{
    while(!waitingForSpareQueue.empty()) {
        AsyncCall::Pointer call = waitingForSpareQueue.front();
        if (call->canceled()) {
            waitingForSpareQueue.pop_front();
            continue;
        }

        NullaryMemFunT<HappyConnOpener> *dialer = dynamic_cast<NullaryMemFunT<HappyConnOpener> *>(call->getDialer());
        assert(dialer);
        const auto he = dialer->job;
        if (!he.valid()){
            waitingForSpareQueue.pop_front();
            continue;
        }

        double startAfter = spareMayStartAfter(he);

        debugs(17, 8, "A new spare connection should start after: " << startAfter << " ms");
        if (startAfter > 0.0) {
            eventAdd("HappyConnQueue::SpareConnectionAttempt", HappyConnQueue::SpareConnectionAttempt, this, startAfter, 1, false);
            waitEvent = true;
            return; //abort here
        }

        if (ConnectionsLimitRule())
            ScheduleCallHere(call);
        else // Move to sparesLimit queue to start spare connection when a spare connection is closed
            sparesLimitQueue.push_back(call);
        waitingForSpareQueue.pop_front();
    }
}

void
HappyConnQueue::kickSparesLimitQueue()
{
    while (!sparesLimitQueue.empty() && ConnectionsLimitRule()) {
        AsyncCall::Pointer call = sparesLimitQueue.front();
        if (!call->canceled()) {
            ScheduleCallHere(call);
        }
        sparesLimitQueue.pop_front();
    }
}
