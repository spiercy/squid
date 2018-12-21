/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PROXYP_MESSAGE_H
#define SQUID_PROXYP_MESSAGE_H

#include "base/RefCount.h"
#include "ip/Address.h"
#include "proxyp/Protocol.h"
#include "sbuf/SBuf.h"

namespace ProxyProtocol {

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

        /// whether both source and destination addresses have tcpVersion
        bool hasMatchingTcpVersion(const SBuf &tcpVersion);

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

} // namespace ProxyProtocol

#endif

