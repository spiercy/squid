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

// unused yet
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

/// PROXY protocol 'command' field value
typedef enum {
    LOCAL = 0,
    PROXY = 0x01
} CommandType;

class Tlv
{
    public:
        Tlv(const uint8_t t, const SBuf &val) : type(t), value(val) {}

        uint8_t type;
        SBuf value;
};

} // namespace Two

void parseProxyProtocolHeaderType(char const *str, uint8_t *tlvType = 0, uint8_t *headerType = 0);
/// parsed PROXY protocol v1 or v2 message
class Message : public RefCountable
{
    public:
        typedef RefCount<Message> Pointer;

        Message(const char *ver, const uint16_t len) : version_(ver), command(Two::PROXY), length_(len) {}

        /// Parsed IPv4 or IPv6 source address
        Ip::Address srcIpAddr;
        /// Parsed IPv4 or IPv6 destination address
        Ip::Address dstIpAddr;

        bool healthCheck() const { return command == Two::LOCAL; }

        /* PROXY v2 related */

        typedef std::vector<Two::Tlv> Tlvs;

        /// HTTP header-like string representation of the parsed message.
        /// The returned string has two mandatory lines for the protocol
        /// version and command:
        /// :version: version CRLF
        /// :command: command CRLF
        /// and may also contain several optional lines for each parsed TLV:
        /// type: value CRLF
        SBuf getAll(const char sep) const;

        /// \returns the value for the provided TLV type.
        /// All values for different TLVs having the same type are concatenated with ','.
        SBuf getValues(const char *typeStr, const char sep) const;

        /// Searches for the first key-value pair occurrence within the
        /// value for the provided TLV type. Assumes that the TLV value
        /// is a list of items separated by 'del' and the items are
        /// pairs separated by '='.
        /// \returns the value of the found pair or an empty string.
        SBuf getElem(const char *typeStr, const char *member, const char sep) const;

        uint8_t length() const { return length_; }

        const char *version() const { return version_; }
        /// parsed PROXY v2 TLVs array
        Tlvs tlvs;

    private:
        /// PROXY protocol version of the message, either "1.0" or "2.0".
        const char *version_;
        /// parsed PROXY v2 command
        Two::CommandType command;

        uint16_t length_;
};

/// used for logging common (TLV-unrelated) fields
typedef enum {
    Version = 1, ///< PROXY protocol version
    Command = 2 ///< PROXY protocol header command
} ExtraHeaderType;

/// Parses a PROXY protocol message from the buffer, determining
/// the protocol version (v1 or v2) by the signature.
/// Throws on error.
/// \returns the parsed message or nil pointer if more data is needed
Message::Pointer Parse(const SBuf &);

} // namespace ProxyProtocol

#endif

