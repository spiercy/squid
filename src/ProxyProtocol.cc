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
#include "SquidConfig.h"
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

ProxyProtocol::Message::FieldMap ProxyProtocol::Message::PseudoHeaderFields = {
    { SBuf(":version"), ProxyProtocol::Two::PP2_PSEUDO_VERSION },
    { SBuf(":command"), ProxyProtocol::Two::PP2_PSEUDO_COMMAND },
    { SBuf(":src_addr"), ProxyProtocol::Two::PP2_PSEUDO_SRC_ADDR },
    { SBuf(":dst_addr"), ProxyProtocol::Two::PP2_PSEUDO_DST_ADDR },
    { SBuf(":src_port"), ProxyProtocol::Two::PP2_PSEUDO_SRC_PORT },
    { SBuf(":dst_port"), ProxyProtocol::Two::PP2_PSEUDO_DST_PORT }
};

/// magic octet prefix for PROXY protocol version 2
static const SBuf Proxy2p0magic("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);

ProxyProtocol::Message::Message(const char *ver, const uint8_t cmd)
    : protoSupported(true), version_(ver), command_(Two::CommandType(cmd)) {}

SBuf
ProxyProtocol::Message::getAll(const char sep) const
{
    SBufStream result;
    for (const auto &p: PseudoHeaderFields)
        result << p.first << ": " << getValues(p.second) << "\r\n";
    // cannot re-use Message::getValues(): need the original TLVs layout
    for (const auto &tlv: tlvs)
        result << tlv.type << ": " << tlv.value << "\r\n";
    return result.buf();
}

SBuf
ProxyProtocol::Message::getValues(const uint32_t headerType, const char sep) const
{
    SBufStream result;
    char ipBuf[MAX_IPSTRLEN];

    if (headerType == Two::PP2_PSEUDO_VERSION) {
        result << version_;
    } else if (headerType == Two::PP2_PSEUDO_COMMAND) {
        result << command_;
    } else if (headerType == Two::PP2_PSEUDO_SRC_ADDR) {
        auto logAddr = srcIpAddr;
        (void)logAddr.applyClientMask(Config.Addrs.client_netmask);
        result << logAddr.toStr(ipBuf, MAX_IPSTRLEN);
    } else if (headerType == Two::PP2_PSEUDO_DST_ADDR) {
        result << dstIpAddr.toStr(ipBuf, MAX_IPSTRLEN);
    } else if (headerType == Two::PP2_PSEUDO_SRC_PORT) {
        result << srcIpAddr.port();
    } else if (headerType == Two::PP2_PSEUDO_DST_PORT) {
        result << dstIpAddr.port();
    } else {
        for (const auto &m: tlvs) {
            if (m.type == headerType) {
                if (result.tellp())
                    result << sep;
                result << m.value;
            }
        }
    }
    return result.buf();
}

SBuf
ProxyProtocol::Message::getElem(const uint32_t headerType, const char *member, const char sep) const
{
    String result = SBufToString(getValues(headerType, sep));
    return getListMember(result, member, sep);
}

/// parses PROXY protocol v1 message from the buffer
static ProxyProtocol::Message::Pointer
ParseV1(SBuf &buf)
{
    ::Parser::Tokenizer tok(buf);
    tok.skip(Proxy1p0magic);

    if (tok.atEnd())
        throw ::Parser::BinaryTokenizer::InsufficientInput();

    static const SBuf::size_type maxMessageLength = 107; // including CRLF
    static const CharacterSet lineContent = CharacterSet::CR.complement().rename("non-CR");
    SBuf line;
    // CR position must not exceed (maxMessageLength - 1)
    if (!tok.prefix(line, lineContent, (maxMessageLength - 1) - Proxy1p0magic.length())) {
        // CRLF at a zero position
        throw TexcHere("Empty PROXY/1.0 message");
    }

    ProxyProtocol::Message::Pointer message;

    if (!tok.skip('\r') || !tok.skip('\n')) {
        // no CRLF within maxMessageLength in the input buffer
        if (tok.parsedSize() < maxMessageLength - 1)
            throw ::Parser::BinaryTokenizer::InsufficientInput();
        else
            throw TexcHere(ToSBuf("PROXY/1.0 error: missing CRLF in the first ", maxMessageLength, " bytes"));
    }

    // found valid header
    message = new ProxyProtocol::Message("1.0");

    static const SBuf unknown("UNKNOWN");
    static const SBuf tcpName("TCP");
    ::Parser::Tokenizer contentTok(line);

    if (contentTok.skip(tcpName)) {

        // skip TCP/IP version number
        static const CharacterSet tcpVersions("TCP-version","46");
        if (!contentTok.skipOne(tcpVersions))
            throw TexcHere("PROXY/1.0 error: missing TCP version");

        // skip SP after protocol version
        if (!contentTok.skip(' '))
            throw TexcHere("PROXY/1.0 error: missing SP");

        SBuf ipa, ipb;
        int64_t porta, portb;
        static const CharacterSet ipChars = CharacterSet("IP Address",".:") + CharacterSet::HEXDIG;

        // parse:  src-IP SP dst-IP SP src-port SP dst-port
        const bool correct = contentTok.prefix(ipa, ipChars) && contentTok.skip(' ') &&
                             contentTok.prefix(ipb, ipChars) && contentTok.skip(' ') &&
                             contentTok.int64(porta) && contentTok.skip(' ') &&
                             contentTok.int64(portb);
        if (!correct || !contentTok.atEnd())
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

    } else if (contentTok.skip(unknown)) {
        // found valid but unusable header
        // discard the rest of the line
        message->protoSupported = false;
    } else
        throw TexcHere("PROXY/1.0 error: invalid INET protocol or family");

    buf.consume(tok.parsedSize());
    return message;
}

static ProxyProtocol::Message::Pointer
ParseV2(SBuf &buf)
{
    static const SBuf::size_type magicLength = Proxy2p0magic.length();
    static const SBuf::size_type minMessageLength = magicLength + 4;

    ProxyProtocol::Message::Pointer message;

    ::Parser::BinaryTokenizer tok(buf, true);
    tok.skip(magicLength, "magic");

    const auto versionAndCommand = tok.uint8("version and command");

    const auto version = (versionAndCommand & 0xF0) >> 4;
    if (version != 2) // version == 2 is mandatory
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid version ", version));

    const auto command = (versionAndCommand & 0x0F);
    if ((command & 0xFE) != 0x00) // values other than 0x0-0x1 are invalid
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid command ", command));

    debugs(88, 3, "parsed pp2_tlv command " << command);

    const auto familyAndProto = tok.uint8("family and proto");

    const auto family = (familyAndProto & 0xF0) >> 4;
    if (family > 0x3) // values other than 0x0-0x3 are invalid
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid address family ", family));

    const auto proto = (familyAndProto & 0x0F);
    if (proto > 0x2) // values other than 0x0-0x2 are invalid
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid transport protocol ", proto));

    // the header length field contains the number following bytes beyond this field
    auto headerLen = tok.uint16("header length");

    if (headerLen > std::numeric_limits<uint16_t>::max() - minMessageLength)
        throw TexcHere(ToSBuf("PROXY/2.0 error: an invalid header length: expecting an integer less than ",
                    std::numeric_limits<uint16_t>::max() - minMessageLength, " but got ", headerLen));

    // the total message length, including the magic bytes
    headerLen += minMessageLength;

    message = new ProxyProtocol::Message("2.0", command);

    message->protoSupported = (proto != 0);

    if (message->localConnection()) {
        // discard the protocol block
        // TODO: parse TLVs
        buf.consume(headerLen);
        return message;
    }

    switch (family) {

    case 0x1:  { // IPv4
        message->srcIpAddr = tok.inV4("src_addr IPv4");
        message->dstIpAddr = tok.inV4("dst_addr IPv4");
        message->srcIpAddr.port(tok.uint16("src_port"));
        message->dstIpAddr.port(tok.uint16("dst_port"));
        break;
    }

    case 0x2:  { // IPv6
        message->srcIpAddr = tok.inV6("src_addr IPv6");
        message->dstIpAddr = tok.inV6("dst_addr IPv6");
        message->srcIpAddr.port(tok.uint16("src_port"));
        message->dstIpAddr.port(tok.uint16("dst_port"));
        break;
    }

    case 0x3:  { // TODO: add support for AF_UNIX sockets.
        // for AF_UNIX sockets the address block length is 216
        tok.skip(216, "unix_addr");
        break;
    }

    default: {
        // the invalid family, we have checked already
        assert(0);
        break;
    }
    }

    ::Parser::BinaryTokenizer tlvTok(tok.area(headerLen - tok.parsed(), "TLV list"));
    while (!tlvTok.atEnd()) {
        const auto type = tlvTok.uint8("pp2_tlv::type");
        debugs(88, 3, "parsed pp2_tlv type: " << type);
        message->tlvs.emplace_back(type, tlvTok.pstring16("pp2_tlv length and value"));
    }

    buf.consume(tok.parsed());
    return message;
}

void
ProxyProtocol::ParseProxyProtocolHeaderType(const SBuf &headerStr, uint32_t &headerType)
{
    const auto it = ProxyProtocol::Message::PseudoHeaderFields.find(headerStr);
    if (it != ProxyProtocol::Message::PseudoHeaderFields.end()) {
        headerType = it->second;
    } else {
        Parser::Tokenizer ptok = Parser::Tokenizer(headerStr);
        int64_t tlvType = 0;
        if (!ptok.int64(tlvType, 10, false))
            throw TexcHere(ToSBuf("Cannot parse PROXY protocol TLV type. Expecting a positive decimal integer but got ", headerStr));
        if (tlvType > std::numeric_limits<uint8_t>::max())
            throw TexcHere(ToSBuf("Cannot parse PROXY protocol TLV type. Expecting an integer less than ",
                       std::numeric_limits<uint8_t>::max(), " but got ", tlvType));
        headerType = static_cast<uint32_t>(tlvType);
    }
}

ProxyProtocol::Message::Pointer
ProxyProtocol::Parse(SBuf &buf)
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
        throw TexcHere("PROXY protocol error: invalid magic");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse yet
    throw ::Parser::BinaryTokenizer::InsufficientInput();
}

