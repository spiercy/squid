/*
 * DEBUG: section 17    Request Forwarding
 *
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "CachePeer.h"
#include "comm/Loops.h"
#include "errorpage.h"
#include "fde.h"
#include "globals.h"
#include "HttpRequest.h"
#include "neighbors.h"
#include "ssl/ErrorDetail.h"
#include "ssl/PeerConnector.h"
#include "ssl/support.h"
#include "SquidConfig.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, PeerConnector);

Ssl::PeerConnector::PeerConnector(
    HttpRequest *aRequest,
    const Comm::ConnectionPointer &aServerConn,
    AsyncCall::Pointer &aCallback):
    AsyncJob("Ssl::PeerConnector"),
    request(aRequest),
    serverConn(aServerConn),
    callback(aCallback)
{
}

Ssl::PeerConnector::~PeerConnector()
{
}

bool Ssl::PeerConnector::doneAll() const
{
    return (!callback || callback->canceled()) && AsyncJob::doneAll();
}

/// Preps connection and SSL state. Calls negotiate().
void
Ssl::PeerConnector::start()
{
    AsyncJob::start();

    monitorSocket();
    initializeSsl();
    negotiateSsl();
}

/// Sets up TCP socket-related notification callbacks if things go wrong.
void
Ssl::PeerConnector::monitorSocket()
{
    // const int fd = serverConnection()->fd;
    // XXX: watch for connection closures; quit on closures via mustStop()
}

/// Initializes SSL state. Used to be FwdState::initiateSSL().
void
Ssl::PeerConnector::initializeSsl()
{
    SSL *ssl;
    SSL_CTX *sslContext = NULL;
    const CachePeer *peer = serverConnection()->getPeer();
    const int fd = serverConnection()->fd;

    if (peer) {
        assert(peer->use_ssl);
        sslContext = peer->sslContext;
    } else {
        sslContext = Config.ssl_client.sslContext;
    }

    assert(sslContext);

    if ((ssl = SSL_new(sslContext)) == NULL) {
        ErrorState *anErr = new ErrorState(ERR_SOCKET_FAILURE, Http::scInternalServerError, request.getRaw());
        anErr->xerrno = errno;
        debugs(17, DBG_IMPORTANT, "Error allocating SSL handle: " << ERR_error_string(ERR_get_error(), NULL));
        bail(anErr);
        return;
    }

    SSL_set_fd(ssl, fd);

    if (peer) {
        if (peer->ssldomain)
            SSL_set_ex_data(ssl, ssl_ex_index_server, peer->ssldomain);

#if NOT_YET

        else if (peer->name)
            SSL_set_ex_data(ssl, ssl_ex_index_server, peer->name);

#endif

        else
            SSL_set_ex_data(ssl, ssl_ex_index_server, peer->host);

        if (peer->sslSession)
            SSL_set_session(ssl, peer->sslSession);

    } else {
        SSL_set_ex_data(ssl, ssl_ex_index_server, (void*)request->GetHost());

        // We need to set SNI TLS extension only in the case we are
        // connecting direct to origin server
        Ssl::setClientSNI(ssl, request->GetHost());
    }

    // Create the ACL check list now, while we have access to more info.
    // The list is used in ssl_verify_cb() and is freed in ssl_free().
    if (acl_access *acl = Config.ssl_client.cert_error) {
        ACLFilledChecklist *check = new ACLFilledChecklist(acl, request.getRaw(), dash_str);
        // check->fd(fd); XXX: need client FD here
        SSL_set_ex_data(ssl, ssl_ex_index_cert_error_check, check);
    }

    fd_table[fd].ssl = ssl;
    fd_table[fd].read_method = &ssl_read_method;
    fd_table[fd].write_method = &ssl_write_method;
    negotiateSsl();
}

/// Performs a single secure connection negotiation step.
/// Used to be FwdState::negotiateSSL().
void
Ssl::PeerConnector::negotiateSsl()
{
    const int fd = serverConnection()->fd;
    SSL *ssl = fd_table[fd].ssl;
    const int result = SSL_connect(ssl);
    if (result <= 0) {
        handleNegotiateError(result);
        return; // we might be gone by now
    }

    if (serverConnection()->getPeer() && !SSL_session_reused(ssl)) {
        if (serverConnection()->getPeer()->sslSession)
            SSL_SESSION_free(serverConnection()->getPeer()->sslSession);

        serverConnection()->getPeer()->sslSession = SSL_get1_session(ssl);
    }

    callBack();
}

/// A wrapper for Comm::SetSelect() notifications.
void
Ssl::PeerConnector::NegotiateSsl(int, void *data)
{
    PeerConnector *pc = static_cast<PeerConnector*>(data);
    // Use job calls to add done() checks and other job logic/protections.
    CallJobHere(17, 7, pc, Ssl::PeerConnector, negotiateSsl);
}

void
Ssl::PeerConnector::handleNegotiateError(const int ret)
{
    const int fd = serverConnection()->fd;
    unsigned long ssl_lib_error = SSL_ERROR_NONE;
    SSL *ssl = fd_table[fd].ssl;
    int ssl_error = SSL_get_error(ssl, ret);

#ifdef EPROTO
        int sysErrNo = EPROTO;
#else
        int sysErrNo = EACCES;
#endif

        switch (ssl_error) {

        case SSL_ERROR_WANT_READ:
            Comm::SetSelect(fd, COMM_SELECT_READ, &NegotiateSsl, this, 0);
            return;

        case SSL_ERROR_WANT_WRITE:
            Comm::SetSelect(fd, COMM_SELECT_WRITE, &NegotiateSsl, this, 0);
            return;

        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL:
            ssl_lib_error = ERR_get_error();

            // store/report errno when ssl_error is SSL_ERROR_SYSCALL, ssl_lib_error is 0, and ret is -1
            if (ssl_error == SSL_ERROR_SYSCALL && ret == -1 && ssl_lib_error == 0)
                sysErrNo = errno;

            debugs(17, DBG_IMPORTANT, "Error negotiating SSL on FD " << fd <<
                   ": " << ERR_error_string(ssl_lib_error, NULL) << " (" <<
                   ssl_error << "/" << ret << "/" << errno << ")");

            break; // proceed to the general error handling code

        default:
            break; // no special error handling for all other errors
        }

    ErrorState *const anErr = ErrorState::NewForwarding(ERR_SECURE_CONNECT_FAIL, request.getRaw());
    anErr->xerrno = sysErrNo;

    Ssl::ErrorDetail *errFromFailure = (Ssl::ErrorDetail *)SSL_get_ex_data(ssl, ssl_ex_index_ssl_error_detail);
    if (errFromFailure != NULL) {
        // The errFromFailure is attached to the ssl object
        // and will be released when ssl object destroyed.
        // Copy errFromFailure to a new Ssl::ErrorDetail object
        anErr->detail = new Ssl::ErrorDetail(*errFromFailure);
    } else {
        // server_cert can be NULL here
        X509 *server_cert = SSL_get_peer_certificate(ssl);
        anErr->detail = new Ssl::ErrorDetail(SQUID_ERR_SSL_HANDSHAKE, server_cert, NULL);
        X509_free(server_cert);
    }

    if (ssl_lib_error != SSL_ERROR_NONE)
        anErr->detail->setLibError(ssl_lib_error);

    bail(anErr);
}

void
Ssl::PeerConnector::bail(ErrorState *error)
{
    Must(error); // or the recepient will not know there was a problem

    // XXX: forward.cc calls peerConnectSucceeded() after an OK TCP connect but
    // we call peerConnectFailed() if SSL failed afterwards. Is that OK?
    // It is not clear whether we should call peerConnectSucceeded/Failed()
    // based on TCP results, SSL results, or both. And the code is probably not
    // consistent in this aspect across tunnelling and forwarding modules.
    if (CachePeer *p = serverConnection()->getPeer())
        peerConnectFailed(p);

    CbDialer *dialer = dynamic_cast<CbDialer*>(callback->getDialer());
    Must(dialer);
    dialer->arg2 = error;

    callBack();
    // Our job is done. The callabck recepient will probably close the failed
    // peer connection and try another peer or go direct (if possible). We
    // can close the connection ourselves (our error notification would reach
    // the recepient before the fd-closure notification), but we would rather
    // minimize the number of fd-closure notifications and let the recepient
    // manage the TCP state of the connection.
}

void
Ssl::PeerConnector::callBack()
{
    ScheduleCallHere(callback);
    callback = NULL; // this should make done() true
}


void
Ssl::PeerConnector::swanSong()
{
    // XXX: unregister fd-closure monitoring and CommSetSelect interest, if any
    AsyncJob::swanSong();
    assert(!callback); // paranoid: we have not left the caller waiting
}

const char *
Ssl::PeerConnector::status() const
{
    static MemBuf buf;
    buf.reset();

    // TODO: redesign AsyncJob::status() API to avoid this
    // id and stop reason reporting duplication.
    buf.append(" [", 2);
    if (stopReason != NULL) {
        buf.Printf("Stopped, reason:");
        buf.Printf("%s",stopReason);
    }
    if (serverConn != NULL)
        buf.Printf(" FD %d", serverConn->fd);
    buf.Printf(" %s%u]", id.Prefix, id.value);
    buf.terminate();

    return buf.content();
}
