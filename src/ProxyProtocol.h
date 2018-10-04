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
    // TLV types defined by the PROXY protocol specs
    PP2_TYPE_UNKNOWN = 0,
    PP2_TYPE_ALPN = 0x01,
    PP2_TYPE_AUTHORITY = 0x02,
    PP2_TYPE_CRC32C = 0x03,
    PP2_TYPE_NOOP = 0x04,
    PP2_TYPE_SSL = 0x20,
    PP2_SUBTYPE_SSL_VERSION = 0x21,
    PP2_SUBTYPE_SSL_CN = 0x22,
    PP2_SUBTYPE_SSL_CIPHER = 0x23,
    PP2_SUBTYPE_SSL_SIG_ALG = 0x24,
    PP2_SUBTYPE_SSL_KEY_ALG = 0x25,
    PP2_TYPE_NETNS = 0x30,

    // IDs for PROXY message pseudo-headers.
    // Larger than 255 to avoid clashes with possible TLV type IDs.
    PP2_PSEUDO_VERSION = 0x101,
    PP2_PSEUDO_COMMAND = 0x102,
    PP2_PSEUDO_SRC_ADDR = 0x103,
    PP2_PSEUDO_DST_ADDR = 0x104,
    PP2_PSEUDO_SRC_PORT = 0x105,
    PP2_PSEUDO_DST_PORT = 0x106
} HeaderType;

/// PROXY protocol 'command' field value
typedef enum {
    LOCAL = 0,
    PROXY = 0x01
} CommandType;

typedef enum {
    PP2_AF_UNSPEC = 0,
    PP2_AF_INET = 0x1,
    PP2_AF_INET6 = 0x2,
    PP2_AF_UNIX = 0x3
} AddressFamily;

typedef enum {
    PP2_UNSPEC = 0,
    PP2_STREAM = 0x1,
    PP2_DGRAM = 0x2
} TransportProtocol;

class Tlv
{
    public:
        Tlv(const uint8_t t, const SBuf &val) : type(t), value(val) {}

        uint8_t type;
        SBuf value;
};

} // namespace Two

/// parsed PROXY protocol v1 or v2 message
class Message : public RefCountable
{
    public:
        typedef RefCount<Message> Pointer;
        typedef std::vector<Two::Tlv> Tlvs;
        typedef std::map<SBuf, Two::HeaderType> FieldMap;

        Message(const char *ver, const uint8_t cmd = Two::PROXY);



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

        /// \returns the value for the provided TLV type.
        /// All values for different TLVs having the same type are concatenated with ','.
        SBuf getValues(const uint32_t headerType, const char sep = ',') const;

        /// Searches for the first key-value pair occurrence within the
        /// value for the provided TLV type. Assumes that the TLV value
        /// is a list of items separated by 'del' and the items are
        /// pairs separated by '='.
        /// \returns the value of the found pair or an empty string.
        SBuf getElem(const uint32_t headerType, const char *member, const char sep) const;

        /// the version of the parsed message
        const char *version() const { return version_; }

        /// unusable messages are valid but should be discarded
        bool usable() const { return !localConnection() && supported_; }

        /// mark the (valid) message as unsupported by the PROXY protocol
        void unsupported() { supported_ = false; }

        /// a mapping bettween pseudo header names and ids
        static FieldMap PseudoHeaderFields;

        /// Parsed IPv4 or IPv6 source address
        Ip::Address srcIpAddr;
        /// Parsed IPv4 or IPv6 destination address
        Ip::Address dstIpAddr;
        /// parsed PROXY v2 TLVs array
        Tlvs tlvs;

    private:
        /// Whether the connection over PROXY protocol is 'LOCAL'.
        /// Such connections are established without being relayed.
        /// Received addresses and TLVs are discarded in this mode.
        bool localConnection() const { return command_ == Two::LOCAL; }

        /// PROXY protocol version of the message, either "1.0" or "2.0".
        const char *version_;

        /// parsed PROXY v2 command
        Two::CommandType command_;

        /// Whether the message INET protocol and adress family are
        /// supported by the PROXY protocol.
        bool supported_;
};

/// Parses PROXY protocol header type from the buffer.
void ParseProxyProtocolHeaderType(const SBuf &headerStr, uint32_t &headerType);

/// Parses a PROXY protocol message from the buffer, determining
/// the protocol version (v1 or v2) by the signature.
/// Throws on error.
/// \returns the parsed message or nil pointer if more data is needed
Message::Pointer Parse(SBuf &);

} // namespace ProxyProtocol

#endif

