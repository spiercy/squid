/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 15    Neighbor Routines */

#ifndef SQUID_NEIGHBORS_H_
#define SQUID_NEIGHBORS_H_

#include "enums.h"
#include "ICP.h"
#include "lookup_t.h"
#include "typedefs.h" //for IRCB

class HttpRequest;
class HttpRequestMethod;
class CachePeer;
class StoreEntry;
class URL;
class ps_state;

CachePeer *getFirstPeer(void);
CachePeer *getFirstUpParent(ps_state *);
CachePeer *getNextPeer(CachePeer *);
CachePeer *getSingleParent(ps_state *);
int neighborsCount(ps_state *);
int neighborsUdpPing(HttpRequest *,
                     StoreEntry *,
                     IRCB * callback,
                     ps_state *ps,
                     int *exprep,
                     int *timeout);
void neighborAddAcl(const char *, const char *);

void neighborsUdpAck(const cache_key *, icp_common_t *, const Ip::Address &);
void neighborAdd(const char *, const char *, int, int, int, int, int);
void neighbors_init(void);
#if USE_HTCP
void neighborsHtcpClear(StoreEntry *, const char *, HttpRequest *, const HttpRequestMethod &, htcp_clr_reason);
#endif
CachePeer *peerFindByName(const char *);
CachePeer *peerFindByNameAndPort(const char *, unsigned short);
CachePeer *getDefaultParent(ps_state*);
CachePeer *getRoundRobinParent(ps_state*);
CachePeer *getWeightedRoundRobinParent(ps_state*);
void peerClearRRStart(void);
void peerClearRR(void);
lookup_t peerDigestLookup(CachePeer * p, HttpRequest * request);
CachePeer *neighborsDigestSelect(HttpRequest * request);
void peerNoteDigestLookup(HttpRequest * request, CachePeer * p, lookup_t lookup);
void peerNoteDigestGone(CachePeer * p);
int neighborUp(const CachePeer * e);
const char *neighborTypeStr(const CachePeer * e);
peer_t neighborType(const CachePeer *, const URL &);
void peerConnectFailed(CachePeer *);
void peerConnectSucceded(CachePeer *);
void dump_peer_options(StoreEntry *, CachePeer *);
int peerHTTPOkay(const CachePeer *, ps_state *);

// TODO: Consider moving this method to CachePeer class.
/// \returns the effective connect timeout for the given peer
time_t peerConnectTimeout(const CachePeer *peer);

/// \returns max(1, timeout)
time_t positiveTimeout(const time_t timeout);

/// Whether we can open new connections to the peer (e.g., despite max-conn)
bool peerCanOpenMore(const CachePeer *p);
/// Whether the peer has idle or standby connections that can be used now
bool peerHasConnAvailable(const CachePeer *p);
/// Notifies peer of an associated connection closure.
void peerConnClosed(CachePeer *p);

CachePeer *whichPeer(const Ip::Address &from);

#endif /* SQUID_NEIGHBORS_H_ */

