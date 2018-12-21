/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_PROXYP_FORWARD_H
#define _SQUID_SRC_PROXYP_FORWARD_H

class SBuf;

namespace ProxyProtocol
{

class Message;

typedef RefCount<Message> MessagePointer;

/// Parses a PROXY protocol message from the buffer, determining
/// the protocol version (v1 or v2) by the signature.
/// Throws on error.
/// \returns the parsed message or nil pointer if more data is needed
MessagePointer Parse(SBuf &);

}


#endif /* _SQUID_SRC_PROXYP_FORWARD_H */

