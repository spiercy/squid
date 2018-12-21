/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PROXYPROTOCOL_H
#define SQUID_PROXYPROTOCOL_H

#include "base/RefCount.h"
#include "ip/Address.h"
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

/// parsed PROXY protocol v1 or v2 message
class Message: public RefCountable
{
    public:
        typedef RefCount<Message> Pointer;
        typedef std::vector<Two::Tlv> Tlvs;
        typedef std::map<SBuf, Two::HeaderType> FieldMap;

        Message(const char *ver, const uint8_t cmd = Two::cmdProxy);

        /// HTTP header-like string representation of the parsed message.
        /// The returned string has several mandatory lines for the protocol
        /// version, command addresses and ports:
        /// :version: version CRLF
        /// :command: command CRLF
        /// :src_addr: srcAddr CRLF
        /// :dst_addr: dstAddr CRLF
        /// :src_port: srcPort CRLF
        /// :dst_port: dstPort CRLF
        /// and may also contain several optional lines for each parsed TLV:
        /// type: value CRLF
        SBuf getAll(const char sep) const;

        /// \returns a delimiter-separated list of values of TLVs of the given type
        SBuf getValues(const uint32_t headerType, const char delimiter = ',') const;

        /// Searches for the first key-value pair occurrence within the
        /// value for the provided TLV type. Assumes that the TLV value
        /// is a list of delimiter-separated items and the items are
        /// pairs separated by '='.
        /// \returns the value of the found pair or an empty string.
        SBuf getElem(const uint32_t headerType, const char *member, const char delimiter) const;

        /// the version of the parsed message
        const char *version() const { return version_; }

        /// whether source and destination addresses are valid addresses of the original "client" connection
        bool hasForwardedAddresses() const { return !localConnection() && hasAddresses(); }

        /// marks the message as lacking address information
        void ignoreAddresses() { ignoreAddresses_ = true; }

        /// whether the message relays address information (including LOCAL connections)
        bool hasAddresses() const { return !ignoreAddresses_; }

        /// a mapping between pseudo header names and ids
        static FieldMap PseudoHeaderFields;

        /// source address of the client connection
        Ip::Address sourceAddress;
        /// intended destination address of the client connection
        Ip::Address destinationAddress;
        /// empty in v1 messages and when ignored in v2 messages
        Tlvs tlvs;

    private:
        /// Whether the connection over PROXY protocol is 'cmdLocal'.
        /// Such connections are established without being relayed.
        /// Received addresses and TLVs are discarded in this mode.
        bool localConnection() const { return command_ == Two::cmdLocal; }

        /// PROXY protocol version of the message, either "1.0" or "2.0".
        const char *version_;

        /// for v2 messages: the command field
        /// for v1 messages: Two::cmdProxy
        Two::Command command_;

        /// true if the message relays no address information
        bool ignoreAddresses_;
};

/// Parses PROXY protocol header type from the buffer.
void HeaderNameToHeaderType(const SBuf &headerStr, uint32_t &headerType);

/// Parses a PROXY protocol message from the buffer, determining
/// the protocol version (v1 or v2) by the signature.
/// Throws on error.
/// \returns the parsed message or nil pointer if more data is needed
Message::Pointer Parse(SBuf &);

} // namespace ProxyProtocol

#endif

