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
#include "proxyp/ProxyProtocol.h"
#include "sbuf/StringConvert.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "StrList.h"

#include <algorithm>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

namespace ProxyProtocol {
    namespace One {
        /// magic octet prefix for PROXY protocol version 1
        static const SBuf Magic("PROXY ", 6);
        /// extracts PROXY protocol v1 message from the given buffer
        static Message::Pointer Parse(SBuf &buf);
    }

    namespace Two {
        /// magic octet prefix for PROXY protocol version 2
        static const SBuf Magic("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
        /// extracts PROXY protocol v2 message from the given buffer
        static Message::Pointer Parse(SBuf &buf);
    }
}

ProxyProtocol::Message::FieldMap ProxyProtocol::Message::PseudoHeaderFields = {
    { SBuf(":version"), ProxyProtocol::Two::htPseudoVersion },
    { SBuf(":command"), ProxyProtocol::Two::htPseudoCommand },
    { SBuf(":src_addr"), ProxyProtocol::Two::htPseudoSrcAddr },
    { SBuf(":dst_addr"), ProxyProtocol::Two::htPseudoDstAddr },
    { SBuf(":src_port"), ProxyProtocol::Two::htPseudoSrcPort },
    { SBuf(":dst_port"), ProxyProtocol::Two::htPseudoDstPort }
};

ProxyProtocol::Message::Message(const char *ver, const uint8_t cmd):
                               version_(ver),
                               command_(Two::Command(cmd)),
                               ignoreAddresses_(false)
{}

SBuf
ProxyProtocol::Message::getAll(const char sep) const
{
    SBufStream result;
    for (const auto &p: PseudoHeaderFields)
        result << p.first << ": " << getValues(p.second) << "\r\n";
    // cannot reuse Message::getValues(): need the original TLVs layout
    for (const auto &tlv: tlvs)
        result << tlv.type << ": " << tlv.value << "\r\n";
    return result.buf();
}

SBuf
ProxyProtocol::Message::getValues(const uint32_t headerType, const char sep) const
{
    SBufStream result;
    char ipBuf[MAX_IPSTRLEN];

    if (headerType == Two::htPseudoVersion) {
        result << version_;
    } else if (headerType == Two::htPseudoCommand) {
        result << command_;
    } else if (headerType == Two::htPseudoSrcAddr) {
        if (!ignoreAddresses_) {
            auto logAddr = sourceAddress;
            (void)logAddr.applyClientMask(Config.Addrs.client_netmask);
            result << logAddr.toStr(ipBuf, sizeof(ipBuf));
        }
    } else if (headerType == Two::htPseudoDstAddr) {
        if (!ignoreAddresses_)
            result << destinationAddress.toStr(ipBuf, sizeof(ipBuf));
    } else if (headerType == Two::htPseudoSrcPort) {
        if (!ignoreAddresses_)
            result << sourceAddress.port();
    } else if (headerType == Two::htPseudoDstPort) {
        if (!ignoreAddresses_)
            result << destinationAddress.port();
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
    const auto whole = SBufToString(getValues(headerType, sep));
    return getListMember(whole, member, sep);
}

void
v1ExtractIp(::Parser::Tokenizer &tok, Ip::Address &addr)
{
    static const CharacterSet ipChars = CharacterSet("IP Address",".:") + CharacterSet::HEXDIG;

    SBuf ip;

    if (!tok.prefix(ip, ipChars))
        throw TexcHere("PROXY/1.0 error: malformed IP address");

    if (!tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: garbage after IP address");

    if (!addr.GetHostByName(ip.c_str()))
        throw TexcHere("PROXY/1.0 error: invalid IP address");

}

void
v1ExtractPort(::Parser::Tokenizer &tok, Ip::Address &addr, const bool trailingSpace)
{
    int64_t port;

    if (!tok.int64(port, 10, false))
        throw TexcHere("PROXY/1.0 error: malformed port");

    if (trailingSpace && !tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: garbage after port");

    if (port > std::numeric_limits<uint16_t>::max())
        throw TexcHere("PROXY/1.0 error: invalid port");

    addr.port(static_cast<uint16_t>(port));
}

/// parses PROXY protocol v1 message from the buffer
static ProxyProtocol::Message::Pointer
ProxyProtocol::One::Parse(SBuf &buf)
{
    ::Parser::Tokenizer tok(buf);
    tok.skip(ProxyProtocol::One::Magic);


    static const SBuf::size_type maxMessageLength = 107; // including CRLF
    static const SBuf::size_type maxInteriorLength = maxMessageLength - 2;
    static const auto interiorChars = CharacterSet::CR.complement().rename("non-CR");
    SBuf interior;

    if (!(tok.prefix(interior, interiorChars, maxInteriorLength - ProxyProtocol::One::Magic.length()) &&
                tok.skip('\r') &&
                tok.skip('\n'))) {
        if (tok.atEnd())
            throw ::Parser::BinaryTokenizer::InsufficientInput();
        else if (interior.isEmpty())
            throw TexcHere("Empty PROXY/1.0 message");
        else
            throw TexcHere(ToSBuf("PROXY/1.0 error: missing CRLF in the first ", maxMessageLength, " bytes"));
    }

    // found valid header
    ProxyProtocol::Message::Pointer message = new ProxyProtocol::Message("1.0");

    static const SBuf protoUnknown("UNKNOWN");
    static const SBuf protoTcp("TCP");
    ::Parser::Tokenizer interiorTok(interior);

    if (interiorTok.skip(protoTcp)) {

        // skip TCP/IP version number
        static const CharacterSet tcpVersions("TCP-version","46");

        SBuf parsedTcpVersion;

        if (!interiorTok.prefix(parsedTcpVersion, tcpVersions, 1))
            throw TexcHere("PROXY/1.0 error: missing or invalid TCP version");

        //if (!interiorTok.skipOne(tcpVersions))

        if (!interiorTok.skip(' '))
            throw TexcHere("PROXY/1.0 error: missing SP after the TCP version");

        // parse: src-IP SP dst-IP SP src-port SP dst-port
        v1ExtractIp(interiorTok, message->sourceAddress);
        v1ExtractIp(interiorTok, message->destinationAddress);

        if (!((parsedTcpVersion.cmp("4") == 0 && message->sourceAddress.isIPv4() && message->destinationAddress.isIPv4()) ||
             (parsedTcpVersion.cmp("6") == 0 && message->sourceAddress.isIPv6() && message->destinationAddress.isIPv6())))
            throw TexcHere("PROXY/1.0 error: TCP version and IP address family mismatch");

        v1ExtractPort(interiorTok, message->sourceAddress, true);
        v1ExtractPort(interiorTok, message->destinationAddress, false);

    } else if (interiorTok.skip(protoUnknown)) {
        // discard the rest of the line
        message->ignoreAddresses();
    } else
        throw TexcHere("PROXY/1.0 error: invalid INET protocol or family");

    buf.consume(tok.parsedSize());
    return message;
}

static ProxyProtocol::Message::Pointer
ProxyProtocol::Two::Parse(SBuf &buf)
{
    static const SBuf::size_type magicLength = ProxyProtocol::Two::Magic.length();

    ProxyProtocol::Message::Pointer message;

    ::Parser::BinaryTokenizer tokMessage(buf, true);
    tokMessage.skip(magicLength, "magic");

    const auto versionAndCommand = tokMessage.uint8("version and command");

    const auto version = (versionAndCommand & 0xF0) >> 4;
    if (version != 2) // version == 2 is mandatory
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid version ", version));

    const auto command = (versionAndCommand & 0x0F);
    if (command > ProxyProtocol::Two::cmdProxy)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid command ", command));

    debugs(88, 3, "parsed pp2_tlv command " << command);

    const auto familyAndProto = tokMessage.uint8("family and proto");

    const auto family = (familyAndProto & 0xF0) >> 4;
    if (family > ProxyProtocol::Two::afUnix)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid address family ", family));

    const auto proto = (familyAndProto & 0x0F);
    if (proto > ProxyProtocol::Two::tpDgram)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid transport protocol ", proto));

    // the header length field contains the number following bytes beyond this field
    auto headerLen = tokMessage.uint16("header length");

    const auto header = tokMessage.area(headerLen, "header");

    message = new ProxyProtocol::Message("2.0", command);

    if (proto == ProxyProtocol::Two::tpUnspec || family == ProxyProtocol::Two::afUnspecified)
        message->ignoreAddresses();

    if (!message->hasForwardedAddresses()) {
        // TODO: parse TLVs for local connections
        // discard the whole PROXY protocol message
        buf.consume(tokMessage.parsed());
        return message;
    }

    ::Parser::BinaryTokenizer tokHeader(header, "TLV list");

    switch (family) {

    case ProxyProtocol::Two::afInet: {
        message->sourceAddress = tokHeader.inet4("src_addr IPv4");
        message->destinationAddress = tokHeader.inet4("dst_addr IPv4");
        message->sourceAddress.port(tokHeader.uint16("src_port"));
        message->destinationAddress.port(tokHeader.uint16("dst_port"));
        break;
    }

    case ProxyProtocol::Two::afInet6: {
        message->sourceAddress = tokHeader.inet6("src_addr IPv6");
        message->destinationAddress = tokHeader.inet6("dst_addr IPv6");
        message->sourceAddress.port(tokHeader.uint16("src_port"));
        message->destinationAddress.port(tokHeader.uint16("dst_port"));
        break;
    }

    case ProxyProtocol::Two::afUnix: { // TODO: add support
        // the address block length is 216 bytes
        tokHeader.skip(216, "unix_addr");
        break;
    }

    default: {
        // unreachable code: we have checked family validity already
        Must(false);
        break;
    }
    }

    while (!tokHeader.atEnd()) {
        const auto type = tokHeader.uint8("pp2_tlv::type");
        message->tlvs.emplace_back(type, tokHeader.pstring16("pp2_tlv length and value"));
    }

    buf.consume(tokMessage.parsed());
    return message;
}

void
ProxyProtocol::HeaderNameToHeaderType(const SBuf &headerStr, uint32_t &headerType)
{
    const auto it = ProxyProtocol::Message::PseudoHeaderFields.find(headerStr);
    if (it != ProxyProtocol::Message::PseudoHeaderFields.end()) {
        headerType = it->second;
    } else {
        Parser::Tokenizer ptok(headerStr);
        int64_t tlvType = 0;
        if (!ptok.int64(tlvType, 10, false))
            throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type. Expecting a positive decimal integer but got ", headerStr));
        if (tlvType > std::numeric_limits<uint8_t>::max())
            throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type. Expecting an integer less than ",
                       std::numeric_limits<uint8_t>::max(), " but got ", tlvType));
        headerType = static_cast<uint32_t>(tlvType);
    }
}

ProxyProtocol::Message::Pointer
ProxyProtocol::Parse(SBuf &buf)
{
    // detect and parse PROXY/2.0 protocol header
    if (buf.startsWith(ProxyProtocol::Two::Magic)) {
        return Two::Parse(buf);
    }

    // detect and parse PROXY/1.0 protocol header
    if (buf.startsWith(ProxyProtocol::One::Magic)) {
        return One::Parse(buf);
    }

    // detect and terminate other protocols
    if (buf.length() >= ProxyProtocol::Two::Magic.length()) {
        // PROXY/1.0 magic is shorter, so we know that
        // the input does not start with any PROXY magic
        throw TexcHere("PROXY protocol error: invalid magic");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse yet
    throw ::Parser::BinaryTokenizer::InsufficientInput();
}

