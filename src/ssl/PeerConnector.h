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
//#include "HttpMsg.h"
//#include "CommCalls.h"

class HttpRequest;
class ErrorState;
class TunnelStateData; // XXX: remove after generalizing CbDialer

typedef RefCount<HttpRequest> HttpRequestPointer;

namespace Ssl {

/**
   Connects Squid client-side to an SSL peer (cache_peer ... ssl).
   Used by tunnel.cc and forward.cc to start talking to an SSL peer.

   The caller receives a call back. If the second/error argument of
   the call is not nil, then there was an error and the SSL connection to the
   SSL peer was not fully established. The error should be returned to the
   HTTP client if no other peers can be used.

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

    /// Ssl::PeerConnector result delivery API.
    class User {
    public:
        virtual ~User() {}

        virtual void *toCbdata() = 0; // the user must be cbdata-protected

        /// PeerConnector calls this upon completion. Error is nil on success.
        virtual void noteSslPeerConnect(CbcPointer<ErrorState> &error) = 0;
    };

    /// Ssl::PeerConnector result delivery API.
    /// Currently based on BinaryCbdataDialer<> but can be generalized.
    /// The second artument is nil if no errors were encountered.
    typedef BinaryCbdataDialer<TunnelStateData, ErrorState> CbDialer;

public:
    PeerConnector(HttpRequest *aRequest,
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

#endif /* SQUID_PEER_CONNECTOR_H */
