/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include <algorithm>
#include "parser/BinaryTokenizer.h"
#include "parser/Tokenizer.h"
#include "ProxyProtocol.h"
#include "sbuf/StringConvert.h"
#include "sbuf/Stream.h"
#include "SquidString.h"
#include "StrList.h"

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

void
parseProxyProtocolHeaderType(char const *str, uint8_t *headerType, uint8_t *extraHeaderType)
{
    if (strncmp(str, ":version", 8) == 0) {
        if (extraHeaderType)
            *extraHeaderType = ProxyProtocol::Version;
    } else if (strncmp(str, ":command", 8) == 0) {
        if (extraHeaderType)
            *extraHeaderType = ProxyProtocol::Command;
    } else {
        Parser::Tokenizer ptok = Parser::Tokenizer(SBuf(str));
        int64_t tlvType = 0;
        if (!ptok.int64(tlvType, 10, false, 3))
            throw TexcHere(ToSBuf("Cannot parse PROXY protocol TLV type. Expecting a decimal integer but got ", str));
        if (tlvType > UINT8_MAX)
            throw TexcHere(ToSBuf("Cannot parse PROXY protocol TLV type. Expecting a positive integer less than ",
                        UINT8_MAX, " but got ", tlvType));
        if (headerType)
            *headerType = static_cast<uint8_t>(tlvType);
    }
}

SBuf
ProxyProtocol::Message::getAll(const char sep) const
{
    SBuf result;
    result.appendf(":version: %s\r\n", version);
    result.appendf(":command: %d\r\n", command);
    for (const auto &tlv: tlvs) {
        result.appendf("%d: ", tlv.type);
        result.append(tlv.value);
        result.append("\r\n");
    }
    return result;
}

SBuf
ProxyProtocol::Message::getValues(const char *typeStr, const char sep) const
{
    SBuf result;
    uint8_t headerType = 0;
    uint8_t extraHeaderType = 0;

    parseProxyProtocolHeaderType(typeStr, &headerType, &extraHeaderType);

    if (extraHeaderType == Version)
        result.append(version_);
    else if (extraHeaderType == Command)
        result.appendf("%d", command);
    else {
        for (const auto &m: tlvs) {
            if (m.type == headerType) {
                if (!result.isEmpty())
                    result.append(sep);
                result.append(m.value);
            }
        }
    }
    return result;
}

SBuf
ProxyProtocol::Message::getElem(const char *typeStr, const char *member, const char sep) const
{
    String result = SBufToString(getValues(typeStr, sep));
    return getListMember(result, member, sep);
}

/// parses PROXY protocol v1 message from the buffer
static ProxyProtocol::Message::Pointer
ParseV1(const SBuf &buf)
{
    ::Parser::Tokenizer tok(buf);
    tok.skip(Proxy1p0magic);

    // skip to first LF (assumes it is part of CRLF)
    static const CharacterSet lineContent = CharacterSet::LF.complement("non-LF");
    SBuf line;
    Message::Pointer message;
    if (tok.prefix(line, lineContent, 107-Proxy1p0magic.length())) {
        if (tok.skip('\n')) {
            // found valid header
            message = new Message("1.0", tok.parsedSize());
            // reset the tokenizer to work on found line only.
            tok.reset(line);
        } else
            return message; // no LF yet

    } else // protocol error only if there are more than 107 bytes prefix header
        throw TexcHere(buf.length() > 107 ? "PROXY/1.0 error: missing CRLF" : nullptr);

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

        if (!message->srcIpAddr.GetHostByName(ipa.c_str()))
            throw TexcHere("PROXY/1.0 error: invalid src-IP address");

        if (!message->dstIpAddr.GetHostByName(ipb.c_str()))
            throw TexcHere("PROXY/1.0 error: invalid dst-IP address");

        if (porta > 0 && porta <= 0xFFFF) // max uint16_t
            message->srcIpAddr.port(static_cast<uint16_t>(porta));
        else
            throw TexcHere("PROXY/1.0 error: invalid src port");

        if (portb > 0 && portb <= 0xFFFF) // max uint16_t
            message->dstIpAddr.port(static_cast<uint16_t>(portb));
        else
            throw TexcHere("PROXY/1.0 error: invalid dst port");

    } else if (tok.skip(unknown)) {
        // found valid but unusable header
    } else
        throw TexcHere("PROXY/1.0 error: invalid protocol family");

    return message;
}

static ProxyProtocol::Message::Pointer
ParseV2()
{
    static const SBuf::size_type prefixLen = Proxy2p0magic.length();
    static const SBuf::size_type mandatoryHeaderLen = prefixLen + 4;

    Message::Pointer message;

    if (buf.length() < mandatoryHeaderLen)
        return message; // need more bytes

    ::Parser::BinaryTokenizer tok(buf);
    tok.skip(prefixLen, "prefix");

    const uint8_t rawVersion = tok.uint8("version");
    if ((rawVersion & 0xF0) != 0x20) // version == 2 is mandatory
        throw TexcHere("PROXY/2.0 error: invalid version");

    command = (rawVersion & 0x0F);
    if ((command & 0xFE) != 0x00) // values other than 0x0-0x1 are invalid
        throw TexcHere("PROXY/2.0 error: invalid command");

    debugs(88, 3, "parsed pp2_tlv command " << type);

    const uint8_t rawFamily = tok.uint8("family");

    const uint8_t family = (rawFamily & 0xF0) >> 4;
    if (family > 0x3) // values other than 0x0-0x3 are invalid
        throw TexcHere("PROXY/2.0 error: invalid family");

    const uint8_t proto = (rawFamily & 0x0F);
    if (proto > 0x2) // values other than 0x0-0x2 are invalid
        throw TexcHere("PROXY/2.0 error: invalid protocol type");

    uint16_t headerLen = tok.uint16("length");
    if (headerLen > UINT16_MAX - mandatoryHeaderLen)
        throw TexcHere(ToSBuf("PROXY/2.0 error: an invalid header length: expecting an integer less than "
                UINT16_MAX - mandatoryHeaderLen, " but got ", headerLen));

    headerLen += mandatoryHeaderLen;

    if (buf.length() < headerLen)
        return message; // need more bytes

    message = new Message("2.0", headerLen);

    // LOCAL connections do nothing with the extras
    if (command == Two::LOCAL)
        return message;

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
        message->srcIpAddr = tok.addrV4("src_addr IPv4");
        message->dstIpAddr = tok.addrV4("dst_addr IPv4");
        message->srcIpAddr.port(tok.uint16("src_port"));
        message->dstIpAddr.port(tok.uint16("dst_port"));
        break;
    }

    case 0x2:  { // IPv6
        message->srcIpAddr = tok.addrV6("src_addr IPv6");
        message->dstIpAddr = tok.addrV6("dst_addr IPv6");
        message->srcIpAddr.port(tok.uint16("src_port"));
        message->dstIpAddr.port(tok.uint16("dst_port"));
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
        const auto type = tok.uint8("pp2_tlv::type");
        debugs(88, 3, "parsed pp2_tlv type " << type);
        const uint16_t valueLen = tok.uint16("pp2_tlv::length");
        if (tok.parsed() + valueLen > headerLen)
            throw TexcHere("PROXY/2.0 error: an invalid pp2_tlv length and (or) the header length");
        message->tlvs.emplace_back(type, tok.area(valueLen, "pp2_tlv::value"));
    }
    return message;
}

ProxyProtocol::Message::Pointer
ProxyProtocol::Parse(const SBuf buf)
{
    // detect and parse PROXY/2.0 protocol header
    if (buf.startsWith(Proxy2p0magic)) {
        return ParseV2(buf);
    }

    // detect and parse PROXY/1.0 protocol header
    if (buf.startsWith(Proxy1p0magic)) {
        return ParseV1(buf);
    }

    // detect and terminate other protocols
    if (buf.length() >= Proxy2p0magic.length()) {
        // PROXY/1.0 magic is shorter, so we know that
        // the input does not start with any PROXY magic
        throw TexcHere("PROXY protocol error: invalid header");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse yet.
    return nullptr;
}

