/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_SSL_PEER_CONNECTOR_H
#define SQUID_SSL_PEER_CONNECTOR_H

#include "base/AsyncJob.h"
#include "base/AsyncCbdataCalls.h"
#include <iosfwd>
//#include "HttpMsg.h"
//#include "CommCalls.h"

class HttpRequest;
class ErrorState;

namespace Ssl {

/// PeerConnector results (supplied via a callback).
/// The connection to peer was secured if and only if the error member is nil.
class PeerConnectorAnswer {
public:
    ~PeerConnectorAnswer(); ///< deletes error if it is still set
    Comm::ConnectionPointer conn; ///< peer connection (secured on success)

    /// answer recepients must clear the error member in order to keep its info
    /// XXX: We should refcount ErrorState instead of cbdata-protecting it.
    CbcPointer<ErrorState> error; ///< problem details (nil on success)
};

/**
   Connects Squid client-side to an SSL peer (cache_peer ... ssl).
   Used by TunnelStateData, FwdState, and PeerPoolMgr to start talking to an
   SSL peer.

   The caller receives a call back with PeerConnectorAnswer. If answer.error
   is not nil, then there was an error and the SSL connection to the SSL peer
   was not fully established. The error object is suitable for error response
   generation.

   The caller must monitor the connection for closure because this
   job will not inform the caller about such events.

   The caller must monitor the overall connection establishment timeout and
   close the connection on timeouts. This is probably better than having
   dedicated (or none at all!) timeouts for peer selection, DNS lookup,
   TCP handshake, SSL handshake, etc. Some steps may have their own timeout,
   but not all steps should be forced to have theirs. XXX: Neither tunnel.cc
   nor forward.cc have a "overall connection establishment" timeout. We need
   to change their code so that they start monitoring earlier and close on
   timeouts. This change may need to be discussed on squid-dev.

   This job never closes the connection, even on errors. If a 3rd-party
   closes the connection, this job simply quits without informing the caller.
*/ 
class PeerConnector: virtual public AsyncJob
{
public:
    /// Callback dialier API to allow PeerConnector to set the answer.
    class CbDialer {
    public:
        virtual ~CbDialer() {}
        /// gives PeerConnector access to the in-dialer answer
        virtual PeerConnectorAnswer &answer() = 0;
    };

    typedef RefCount<HttpRequest> HttpRequestPointer;

public:
    PeerConnector(HttpRequestPointer &aRequest,
                  const Comm::ConnectionPointer &aServerConn,
                  AsyncCall::Pointer &aCallback);
    virtual ~PeerConnector();

protected:
    // AsyncJob API
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

    void monitorSocket();
    void initializeSsl();
    void negotiateSsl();
    void handleNegotiateError(const int result);

private:
    PeerConnector(const PeerConnector &); // not implemented
    PeerConnector &operator =(const PeerConnector &); // not implemented

    /// mimics FwdState to minimize changes to FwdState::initiate/negotiateSsl
    Comm::ConnectionPointer const &serverConnection() const { return serverConn; }

    void bail(ErrorState *error);
    void callBack();

    static void NegotiateSsl(int fd, void *data);

    HttpRequestPointer request; ///< peer connection trigger or cause
    Comm::ConnectionPointer serverConn; ///< TCP connection to the peer
    AsyncCall::Pointer callback; ///< we call this with the results

    CBDATA_CLASS2(PeerConnector);
};

} // namespace Ssl

std::ostream &operator <<(std::ostream &os, const Ssl::PeerConnectorAnswer &a);

#endif /* SQUID_PEER_CONNECTOR_H */
