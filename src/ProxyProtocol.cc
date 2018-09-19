/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "parser/BinaryTokenizer.h"
#include "parser/Tokenizer.h"
#include "ProxyProtocol.h"

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

/// magic octet prefix for PROXY protocol version 1
static const SBuf Proxy1p0magic("PROXY ", 6);

/// magic octet prefix for PROXY protocol version 2
static const SBuf Proxy2p0magic("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);

bool
ProxyProtocol::Parser::parse(const SBuf &aBuf)
{
    buf_ = aBuf;
    // detect and parse PROXY/2.0 protocol header
    if (buf_.startsWith(Proxy2p0magic)) {
        version = "2.0";
        return parseV2();
    }

    // detect and parse PROXY/1.0 protocol header
    if (buf_.startsWith(Proxy1p0magic)) {
        version = "1.0";
        return parseV1();
    }

    // detect and terminate other protocols
    if (buf_.length() >= Proxy2p0magic.length()) {
        // PROXY/1.0 magic is shorter, so we know that
        // the input does not start with any PROXY magic
        throw TexcHere("PROXY protocol error: invalid header");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse yet.
    return false;
}

bool
ProxyProtocol::Parser::parseV1()
{
    ::Parser::Tokenizer tok(buf_);
    tok.skip(Proxy1p0magic);

    // skip to first LF (assumes it is part of CRLF)
    static const CharacterSet lineContent = CharacterSet::LF.complement("non-LF");
    SBuf line;
    if (tok.prefix(line, lineContent, 107-Proxy1p0magic.length())) {
        if (tok.skip('\n')) {
            // found valid header
            buf_ = tok.remaining();
            // reset the tokenizer to work on found line only.
            tok.reset(line);
        } else
            return false; // no LF yet

    } else // protocol error only if there are more than 107 bytes prefix header
        throw TexcHere(buf_.length() > 107 ? "PROXY/1.0 error: missing CRLF" : nullptr);

    static const SBuf unknown("UNKNOWN"), tcpName("TCP");
    if (tok.skip(tcpName)) {

        // skip TCP/IP version number
        static const CharacterSet tcpVersions("TCP-version","46");
        if (!tok.skipOne(tcpVersions))
            throw TexcHere("PROXY/1.0 error: missing TCP version");

        // skip SP after protocol version
        if (!tok.skip(' '))
            throw TexcHere("PROXY/1.0 error: missing SP");

        SBuf ipa, ipb;
        int64_t porta, portb;
        static const CharacterSet ipChars = CharacterSet("IP Address",".:") + CharacterSet::HEXDIG;

        // parse:  src-IP SP dst-IP SP src-port SP dst-port CR
        // leave the LF until later.
        const bool correct = tok.prefix(ipa, ipChars) && tok.skip(' ') &&
                             tok.prefix(ipb, ipChars) && tok.skip(' ') &&
                             tok.int64(porta) && tok.skip(' ') &&
                             tok.int64(portb) &&
                             tok.skip('\r');
        if (!correct)
            throw TexcHere("PROXY/1.0 error: invalid syntax");

        if (!srcIpAddr.GetHostByName(ipa.c_str()))
            throw TexcHere("PROXY/1.0 error: invalid src-IP address");

        if (!dstIpAddr.GetHostByName(ipb.c_str()))
            throw TexcHere("PROXY/1.0 error: invalid dst-IP address");

        if (porta > 0 && porta <= 0xFFFF) // max uint16_t
            srcIpAddr.port(static_cast<uint16_t>(porta));
        else
            throw TexcHere("PROXY/1.0 error: invalid src port");

        if (portb > 0 && portb <= 0xFFFF) // max uint16_t
            dstIpAddr.port(static_cast<uint16_t>(portb));
        else
            throw TexcHere("PROXY/1.0 error: invalid dst port");

        return true;

    } else if (tok.skip(unknown)) {
        // found valid but unusable header
        return true;

    } else
        throw TexcHere("PROXY/1.0 error: invalid protocol family");

    return false;
}

ProxyProtocol::Two::Tlv::Tlv(const uint8_t t) : type(ProxyProtocol::Two::HeaderType(t))
{
    switch(type) {
        case PP2_TYPE_ALPN:
        case PP2_TYPE_AUTHORITY:
        case PP2_TYPE_CRC32C:
        case PP2_TYPE_NOOP:
        case PP2_TYPE_SSL:
        case PP2_SUBTYPE_SSL_VERSION:
        case PP2_SUBTYPE_SSL_CN:
        case PP2_SUBTYPE_SSL_CIPHER:
        case PP2_SUBTYPE_SSL_SIG_ALG:
        case PP2_SUBTYPE_SSL_KEY_ALG:
        case PP2_TYPE_NETNS:
            break;
        default:
            throw TexcHere("PROXY/2.0 error: invalid pp2_tlv type");
    }
}

bool
ProxyProtocol::Parser::parseV2()
{
    static const SBuf::size_type prefixLen = Proxy2p0magic.length();
    static const SBuf::size_type mandatoryHeaderLen = prefixLen + 4;

    if (buf_.length() < mandatoryHeaderLen)
        return false; // need more bytes

    ::Parser::BinaryTokenizer tok(buf_);
    tok.skip(prefixLen, "prefix");

    const uint8_t rawVersion = tok.uint8("version");
    if ((rawVersion & 0xF0) != 0x20) // version == 2 is mandatory
        throw TexcHere("PROXY/2.0 error: invalid version");

    const char command = (rawVersion & 0x0F);
    if ((command & 0xFE) != 0x00) // values other than 0x0-0x1 are invalid
        throw TexcHere("PROXY/2.0 error: invalid command");

    char rawFamily = tok.uint8("family");

    const char family = (rawFamily & 0xF0) >> 4;
    if (family > 0x3) // values other than 0x0-0x3 are invalid
        throw TexcHere("PROXY/2.0 error: invalid family");

    const char proto = (rawFamily & 0x0F);
    if (proto > 0x2) // values other than 0x0-0x2 are invalid
        throw TexcHere("PROXY/2.0 error: invalid protocol type");

    const uint16_t headerLen = tok.uint16("length") + mandatoryHeaderLen;

    if (buf_.length() < headerLen)
        return false; // need more bytes

    // LOCAL connections do nothing with the extras
    if (command == 0x00/* LOCAL*/)
        return true;

    union pax {
        struct {        /* for TCP/UDP over IPv4, len = 12 */
            struct in_addr src_addr;
            struct in_addr dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ipv4_addr;
        struct {        /* for TCP/UDP over IPv6, len = 36 */
            struct in6_addr src_addr;
            struct in6_addr dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ipv6_addr;
        struct {        /* for AF_UNIX sockets, len = 216 */
            uint8_t src_addr[108];
            uint8_t dst_addr[108];
        } unix_addr;
    };

    switch (family) {

    case 0x1:  { // IPv4
        pax ipu;
        const SBuf rawAddr = tok.area(sizeof(pax::ipv4_addr), "ipv4_addr");
        memcpy(&ipu, rawAddr.rawContent(), rawAddr.length());

        dstIpAddr = ipu.ipv4_addr.dst_addr;
        dstIpAddr.port(ntohs(ipu.ipv4_addr.dst_port));
        srcIpAddr = ipu.ipv4_addr.src_addr;
        srcIpAddr.port(ntohs(ipu.ipv4_addr.src_port));
        break;
    }

    case 0x2:  { // IPv6
        pax ipu;
        const SBuf rawAddr = tok.area(sizeof(pax::ipv6_addr), "ipv6_addr");
        memcpy(&ipu, rawAddr.rawContent(), rawAddr.length());

        dstIpAddr = ipu.ipv6_addr.dst_addr;
        dstIpAddr.port(ntohs(ipu.ipv6_addr.dst_port));
        srcIpAddr = ipu.ipv6_addr.src_addr;
        srcIpAddr.port(ntohs(ipu.ipv6_addr.src_port));
        break;
    }

    case 0x3:  { // TODO: add support for AF_UNIX sockets.
        tok.skip(sizeof(pax::unix_addr), "unix_addr");
        break;
    }

    default: {
        // the invalid family, we have checked already
        assert(0);
        break;
    }
    }

    while (tok.parsed() < headerLen) { 
        assert(!tok.atEnd());
        if (!v2Message)
            v2Message = new ProxyProtocol::Two::Message;
        ProxyProtocol::Two::Tlv tlv(tok.uint8("pp2_tlv::type"));
        const uint16_t valueLen = tok.uint16("pp2_tlv::length");
        if (tok.parsed() + valueLen > headerLen)
            throw TexcHere("PROXY/2.0 error: invalid pp2_tlv length");
        tlv.value = tok.area(valueLen, "pp2_tlv::value");
        v2Message->tlvs.emplace_back(tlv);
    }
    buf_.consume(headerLen);
    return true;
}

