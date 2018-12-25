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
class Parsed;

typedef RefCount<Message> MessagePointer;

/// Parses a PROXY protocol message from the buffer, determining
/// the protocol version (v1 or v2) by the signature.
/// Throws on error or insufficient input.
/// \returns the successfully parsed message
Parsed Parse(const SBuf &);

/// Parses PROXY protocol header type from the buffer.
uint32_t HeaderNameToHeaderType(const SBuf &headerStr);

}

#endif /* _SQUID_SRC_PROXYP_FORWARD_H */

