/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FORWARD_H
#define SQUID_FORWARD_H

#include "base/RefCount.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "err_type.h"
#include "fde.h"
#include "HappyConnOpener.h"
#include "http/StatusCode.h"
#include "ip/Address.h"
#include "PeerSelectState.h"
#include "security/forward.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

/* forward decls */

class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class PconnPool;
typedef RefCount<PconnPool> PconnPoolPointer;
class ErrorState;
class HttpRequest;

#if USE_OPENSSL
namespace Ssl
{
class ErrorDetail;
class CertValidationResponse;
};
#endif

/**
 * Returns the TOS value that we should be setting on the connection
 * to the server, based on the ACL.
 */
tos_t GetTosToServer(HttpRequest * request);

/**
 * Returns the Netfilter mark value that we should be setting on the
 * connection to the server, based on the ACL.
 */
nfmark_t GetNfmarkToServer(HttpRequest * request);

/// Sets initial TOS value and Netfilter for the future outgoing connection.
void GetMarkingsToServer(HttpRequest * request, Comm::Connection &conn);

/// Holds the list with candidate connection paths for a host
class CandidatePaths: public RefCountable
{
public:
    typedef RefCount<CandidatePaths> Pointer;
    CandidatePaths();

    /// Add the path to the top of candidate paths. Normally used
    /// to retry a failed connection.
    void retryPath(const Comm::ConnectionPointer &);

    /// Add a new path to the end of candidate paths.
    void newPath(const Comm::ConnectionPointer &);

    /// Whether the list is empty
    bool empty() {return paths_.empty();}

    /// extracts and returns the first queued address
    Comm::ConnectionPointer extractFront();

    /// extracts and returns the first same-peer same-family address
    /// \returns nil if it cannot find the requested address
    Comm::ConnectionPointer extractPrime(const Comm::Connection &currentPeer);
    /// extracts and returns the first same-peer different-family address
    /// \returns nil if it cannot find the requested address
    Comm::ConnectionPointer extractSpare(const Comm::Connection &currentPeer);

    /// whether peer-related spare addresses are (or may become) known
    bool doneWithSpare(const Comm::Connection &currentPeer) const;

    /// whether peer-related addresses are (or may become) known
    bool doneWithPeer(const Comm::Connection &currentPeer) const;

    /// the current number of candidate paths
    int size() {return paths_.size();}

    /// The protocol family of the given path, AF_INET or AF_INET6
    static int ConnectionFamily(const Comm::Connection &conn);

    ///< whether all of the available candidate paths received from DNS
    bool destinationsFinalized;

private:
    Comm::ConnectionList::const_iterator findSpareOrNextPeer(const Comm::Connection &currentPeer) const;
    Comm::ConnectionPointer extractFound(const char *description, const Comm::ConnectionList::const_iterator &found);

    Comm::ConnectionList paths_;
};


class HelperReply;
class FwdState: public RefCountable, public PeerSelectionInitiator
{
    CBDATA_CHILD(FwdState);

public:
    typedef RefCount<FwdState> Pointer;
    virtual ~FwdState();
    static void initModule();

    /// Initiates request forwarding to a peer or origin server.
    static void Start(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    /// Same as Start() but no master xaction info (AccessLogEntry) available.
    static void fwdStart(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *);
    /// time left to finish the whole forwarding process (which started at fwdStart)
    static time_t ForwardTimeout(const time_t fwdStart);
    /// Whether there is still time to re-try after a previous connection failure.
    /// \param fwdStart The start time of the peer selection/connection process.
    static bool EnoughTimeToReForward(const time_t fwdStart);

    /// This is the real beginning of server connection. Call it whenever
    /// the forwarding server destination has changed and a new one needs to be opened.
    /// Produces the cannot-forward error on fail if no better error exists.
    void useDestinations();

    void fail(ErrorState *err);
    void unregister(Comm::ConnectionPointer &conn);
    void unregister(int fd);
    void complete();
    void handleUnregisteredServerEnd();
    int reforward();
    bool reforwardableStatus(const Http::StatusCode s) const;
    void serverClosed(int fd);
    void connectStart();
    void connectDone(const Comm::ConnectionPointer & conn, Comm::Flag status, int xerrno);
    bool checkRetry();
    bool checkRetriable();
    void dispatch();

    void pconnPush(Comm::ConnectionPointer & conn, const char *domain);

    bool dontRetry() { return flags.dont_retry; }

    void dontRetry(bool val) { flags.dont_retry = val; }

    /** return a ConnectionPointer to the current server connection (may or may not be open) */
    Comm::ConnectionPointer const & serverConnection() const { return serverConn; };

    /// Callback called by HappyConnOpener object when a connection is
    /// established, or when all available candidate paths exceed.
    void noteConnection(const HappyConnOpener::Answer &cd);

    HttpRequest *httpRequest() {return request;}

private:
    // hidden for safer management of self; use static fwdStart
    FwdState(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    void start(Pointer aSelf);
    void stopAndDestroy(const char *reason);

    /* PeerSelectionInitiator API */
    virtual void noteDestination(Comm::ConnectionPointer conn) override;
    virtual void noteDestinationsEnd(ErrorState *selectionError) override;

#if STRICT_ORIGINAL_DST
    void selectPeerForIntercepted();
#endif
    static void logReplyStatus(int tries, const Http::StatusCode status);
    void doneWithRetries();
    void completed();
    void retryOrBail();

    void usePinned();

    /// whether a pinned to-peer connection can be replaced with another one
    /// (in order to retry or reforward a failed request)
    bool pinnedCanRetry() const;

    ErrorState *makeConnectingError(const err_type type) const;
    void connectedToPeer(Security::EncryptorAnswer &answer);
    static void RegisterWithCacheManager(void);

    /// stops monitoring server connection for closure and updates pconn stats
    void closeServerConnection(const char *reason);

    void syncWithServerConn(const char *host);
    void syncHierNote(const Comm::ConnectionPointer &server, const char *host);

    /// whether we have used up all permitted forwarding attempts
    bool exhaustedTries() const;

    void handlePinned(CachePeer *); ///< Handle pinned connections

    /// whether we are waiting for HappyConnOpener
    /// same as calls.connector but may differ from connOpener.valid()
    bool opening() const { return connOpener.set(); }

    /// Whether there is at least one more candidate path available
    bool hasCandidatePath() {return destinations_ && !destinations_->empty();}

public:
    StoreEntry *entry;
    HttpRequest *request;
    AccessLogEntryPointer al; ///< info for the future access.log entry

    static void abort(void*);

private:
    Pointer self;
    ErrorState *err;
    Comm::ConnectionPointer clientConn;        ///< a possibly open connection to the client.
    time_t start_t;
    int n_tries; ///< the number of forwarding attempts so far

    // AsyncCalls which we set and may need cancelling.
    struct {
        AsyncCall::Pointer connector;  ///< a call linking us to the ConnOpener producing serverConn.
    } calls;

    struct {
        bool connected_okay; ///< TCP link ever opened properly. This affects retry of POST,PUT,CONNECT,etc
        bool dont_retry;
        bool forward_completed;
        bool destinationsFound; ///< At least one candidate path found
    } flags;

     /// The active HappyConnOpener object or nil
    HappyConnOpener::Pointer connOpener;
    CandidatePaths::Pointer destinations_; ///< The available candidate paths
    Comm::ConnectionPointer serverConn; ///< a successfully opened connection to a server.

    AsyncCall::Pointer closeHandler; ///< The serverConn close handler

    /// possible pconn race states
    typedef enum { raceImpossible, racePossible, raceHappened } PconnRace;
    PconnRace pconnRace; ///< current pconn race state
};

void getOutgoingAddress(HttpRequest * request, Comm::ConnectionPointer conn);

#endif /* SQUID_FORWARD_H */

