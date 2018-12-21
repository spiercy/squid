/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PROXYPROTOCOL_H
#define SQUID_PROXYPROTOCOL_H

#include "sbuf/SBuf.h"

// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
namespace ProxyProtocol {
namespace Two {

typedef enum {
    htUnknown = 0,

    // The PROXY protocol specs lists these TLV types as already registered.
    htAlpn = 0x01, // PP2_TYPE_ALPN
    htAuthority = 0x02, // PP2_TYPE_AUTHORITY
    htCrc32c = 0x03, // PP2_TYPE_CRC32C
    htNoop = 0x04, // PP2_TYPE_NOOP
    htSsl = 0x20, // PP2_TYPE_SSL
    htSslVersion = 0x21, // PP2_SUBTYPE_SSL_VERSION
    htSslCn = 0x22, // PP2_SUBTYPE_SSL_CN
    htSslCipher = 0x23, // PP2_SUBTYPE_SSL_CIPHER
    htSslSigAlg = 0x24, // PP2_SUBTYPE_SSL_SIG_ALG
    htSslKeyAlg = 0x25, // PP2_SUBTYPE_SSL_KEY_ALG
    htNetns = 0x30, // PP2_TYPE_NETNS

    // IDs for PROXY protocol message pseudo-headers.
    // Larger than 255 to avoid clashes with possible TLV type IDs.
    htPseudoVersion = 0x101,
    htPseudoCommand = 0x102,
    htPseudoSrcAddr = 0x103,
    htPseudoDstAddr = 0x104,
    htPseudoSrcPort = 0x105,
    htPseudoDstPort = 0x106
} HeaderType;

/// PROXY protocol 'command' field value
typedef enum {
    cmdLocal = 0,
    cmdProxy = 0x01
} Command;

typedef enum {
    /// corresponds to a local connection or an unsupported protocol family
    afUnspecified = 0,
    afInet = 0x1,
    afInet6 = 0x2,
    afUnix = 0x3
} AddressFamily;

typedef enum {
    tpUnspec = 0,
    tpStream = 0x1,
    tpDgram = 0x2
} TransportProtocol;

/// a single Type-Length-Value (TLV) block from PROXY protocol specs
class Tlv
{
    public:
        Tlv(const uint8_t t, const SBuf &val) : value(val), type(t) {}

        SBuf value;
        uint8_t type;
};

} // namespace Two

} // namespace ProxyProtocol

#endif

