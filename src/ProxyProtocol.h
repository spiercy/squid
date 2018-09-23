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
    PP2_TYPE_NETNS = 0x30
} HeaderType;

class Tlv
{
    public:
        Tlv(const uint8_t t);

        uint8_t type;
        SBuf value;
};

/// parsed PROXY protocol v2 message, which is an array of TLVs
class Message : public RefCountable
{
    public:
        typedef RefCount<Message> Pointer;
        typedef std::vector<Tlv> Tlvs;

        /// HTTP header-like string representation of the whole message.
        /// \returns a string consisting of lines:
        /// type: value CRLF
        /// All values for different TLVs having the same type are concatenated with ','
        /// and returned within the same line.
        SBuf getAll(const char sep) const;

        /// \returns the value for the provided TLV type
        /// All values for different TLVs having the same type are concatenated with ','.
        SBuf getValue(const uint8_t type, const char sep) const;

        /// Searches for the first key-value pair occurrence within the
        /// value for the provided TLV type. Assumes that the TLV value
        /// is a list of items separated by 'del' and the items are
        /// pairs separated by '='.
        /// \returns the value of the found pair or an empty string.
        SBuf getElem(const uint8_t type, const char *member, const char sep) const;

        /// parsed TLVs array
        Tlvs tlvs;
};

} // namespace Two

/// Extracts PROXY protocol message from the I/O buffer.
/// Works with both v1 and v2 protocol versions.
class Parser
{
    public:
        /// Parses a PROXY protocol message from the buffer, determining
        /// the protocol version (v1 or v2) by the signature.
        bool parse(const SBuf &aBuf);

        /// the unprocessed data
        const SBuf &remaining() const { return buf_; }

        /// Parsed IPv4 or IPv6 source address
        Ip::Address srcIpAddr;
        /// Parsed IPv4 or IPv6 destination address
        Ip::Address dstIpAddr;
        /// parsed PROXY protocol v2 TLVs
        Two::Message::Pointer v2Message;
        /// PROXY protocol version of the parsed message, either "1.0" or "2.0".
        const char *version = nullptr;

    private:
        bool parseV1();
        bool parseV2();

        /// bytes remaining to be parsed
        SBuf buf_;
};

} // namespace ProxyProtocol

#endif

