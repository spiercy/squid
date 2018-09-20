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

        HeaderType type;
        SBuf value;
};

class Message : public RefCountable
{
    public:
        typedef RefCount<Message> Pointer;
        typedef std::vector<Tlv> Tlvs;

        SBuf getAll(const char sep);
        SBuf getType(const HeaderType t, const char sep);
        SBuf getElem(const HeaderType t, const char sep, const char elemSep);
        Tlvs tlvs;
};

} // namespace Two

class Parser
{
    public:
        bool parse(const SBuf &aBuf);

        const SBuf &remaining() const { return buf_; }

        Ip::Address srcIpAddr;
        Ip::Address dstIpAddr;
        Two::Message::Pointer v2Message;
        const char *version = nullptr;

    private:
        bool parseV1();
        bool parseV2();

        /// bytes remaining to be parsed
        SBuf buf_;
};

} // namespace ProxyProtocol

#endif

