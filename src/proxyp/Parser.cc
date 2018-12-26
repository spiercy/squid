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
#include "proxyp/forward.h"
#include "proxyp/Message.h"
#include "proxyp/Protocol.h"
#include "sbuf/Stream.h"

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
static const SBuf Magic("PROXY", 5);
/// extracts PROXY protocol v1 message from the given buffer
static Parsed Parse(const SBuf &buf);

static void extractIp(Parser::Tokenizer &tok, Ip::Address &addr);
static void extractPort(Parser::Tokenizer &tok, Ip::Address &addr, const bool trailingSpace);
static void parseAddresses(Parser::Tokenizer &tok, MessagePointer &message);
}

namespace Two {
/// magic octet prefix for PROXY protocol version 2
static const SBuf Magic("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
/// extracts PROXY protocol v2 message from the given buffer
static Parsed Parse(const SBuf &buf);

static void parseAddresses(const uint8_t family, Parser::BinaryTokenizer &tok, MessagePointer &message);
static void parseTLVs(Parser::BinaryTokenizer &tok, MessagePointer &message);
}
}

void
ProxyProtocol::One::extractIp(Parser::Tokenizer &tok, Ip::Address &addr)
{
    static const auto ipChars = CharacterSet("IP Address",".:") + CharacterSet::HEXDIG;

    SBuf ip;

    if (!tok.prefix(ip, ipChars))
        throw TexcHere("PROXY/1.0 error: malformed IP address");

    if (!tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: garbage after IP address");

    if (!addr.GetHostByName(ip.c_str()))
        throw TexcHere("PROXY/1.0 error: invalid IP address");

}

void
ProxyProtocol::One::extractPort(Parser::Tokenizer &tok, Ip::Address &addr, const bool trailingSpace)
{
    int64_t port = -1;

    if (!tok.int64(port, 10, false))
        throw TexcHere("PROXY/1.0 error: malformed port");

    if (trailingSpace && !tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: garbage after port");

    if (port > std::numeric_limits<uint16_t>::max())
        throw TexcHere("PROXY/1.0 error: invalid port");

    addr.port(static_cast<uint16_t>(port));
}

void
ProxyProtocol::One::parseAddresses(Parser::Tokenizer &tok, MessagePointer &message)
{
    static const CharacterSet tcpVersions("TCP-version","46");
    SBuf parsedTcpVersion;

    if (!tok.prefix(parsedTcpVersion, tcpVersions, 1))
        throw TexcHere("PROXY/1.0 error: missing or invalid TCP version");

    if (!tok.skip(' '))
        throw TexcHere("PROXY/1.0 error: missing SP after the TCP version");

    // parse: src-IP SP dst-IP SP src-port SP dst-port
    extractIp(tok, message->sourceAddress);
    extractIp(tok, message->destinationAddress);

    if (!message->hasMatchingTcpVersion(parsedTcpVersion))
        throw TexcHere("PROXY/1.0 error: TCP version and IP address family mismatch");

    extractPort(tok, message->sourceAddress, true);
    extractPort(tok, message->destinationAddress, false);
}

/// parses PROXY protocol v1 message from the buffer
ProxyProtocol::Parsed
ProxyProtocol::One::Parse(const SBuf &buf)
{
    Parser::Tokenizer tok(buf);

    static const SBuf::size_type maxMessageLength = 107; // including CRLF
    static const auto maxInteriorLength = maxMessageLength - Magic.length() - 2;
    static const auto interiorChars = CharacterSet::CR.complement().rename("non-CR");
    SBuf interior;

    if (!(tok.prefix(interior, interiorChars, maxInteriorLength) &&
            tok.skip('\r') &&
            tok.skip('\n'))) {
        if (tok.atEnd())
            throw Parser::BinaryTokenizer::InsufficientInput();
        else if (interior.isEmpty())
            throw TexcHere("PROXY/1.0 error: the message block is empty");
        else
            throw TexcHere("PROXY/1.0 error: missing CRLF in the message");
    }
    // grabbed all header bytes

    MessagePointer message = new Message("1.0");

    Parser::Tokenizer interiorTok(interior);

    if (!interiorTok.skip(' '))
        throw TexcHere("PROXY/1.0 error: missing SP after the magic sequence");

    static const SBuf protoUnknown("UNKNOWN");
    static const SBuf protoTcp("TCP");

    if (interiorTok.skip(protoTcp))
        parseAddresses(interiorTok, message);
    else if (interiorTok.skip(protoUnknown))
        message->ignoreAddresses();
    else
        throw TexcHere("PROXY/1.0 error: invalid INET protocol or family");

    return Parsed(message, tok.parsedSize());
}

void
ProxyProtocol::Two::parseAddresses(const uint8_t family, Parser::BinaryTokenizer &tok, MessagePointer &message)
{
    switch (family) {

    case afInet: {
        message->sourceAddress = tok.inet4("src_addr IPv4");
        message->destinationAddress = tok.inet4("dst_addr IPv4");
        message->sourceAddress.port(tok.uint16("src_port"));
        message->destinationAddress.port(tok.uint16("dst_port"));
        break;
    }

    case afInet6: {
        message->sourceAddress = tok.inet6("src_addr IPv6");
        message->destinationAddress = tok.inet6("dst_addr IPv6");
        message->sourceAddress.port(tok.uint16("src_port"));
        message->destinationAddress.port(tok.uint16("dst_port"));
        break;
    }

    case afUnix: { // TODO: add support
        // the address block length is 216 bytes
        tok.skip(216, "unix_addr");
        break;
    }

    default: {
        // unreachable code: we have checked family validity already
        Must(false);
        break;
    }
    }
}

void
ProxyProtocol::Two::parseTLVs(Parser::BinaryTokenizer &tok, MessagePointer &message) {
    while (!tok.atEnd()) {
        const auto type = tok.uint8("pp2_tlv::type");
        message->tlvs.emplace_back(type, tok.pstring16("pp2_tlv length and value"));
    }
}

ProxyProtocol::Parsed
ProxyProtocol::Two::Parse(const SBuf &buf)
{
    Parser::BinaryTokenizer tokMessage(buf, true);

    const auto versionAndCommand = tokMessage.uint8("version and command");

    const auto version = (versionAndCommand & 0xF0) >> 4;
    if (version != 2) // version == 2 is mandatory
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid version ", version));

    const auto command = (versionAndCommand & 0x0F);
    if (command > cmdProxy)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid command ", command));

    const auto familyAndProto = tokMessage.uint8("family and proto");

    const auto family = (familyAndProto & 0xF0) >> 4;
    if (family > afUnix)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid address family ", family));

    const auto proto = (familyAndProto & 0x0F);
    if (proto > tpDgram)
        throw TexcHere(ToSBuf("PROXY/2.0 error: invalid transport protocol ", proto));

    // the header length field contains the number following bytes beyond this field
    const auto headerLen = tokMessage.uint16("header length");

    const auto header = tokMessage.area(headerLen, "header");

    MessagePointer message = new Message("2.0", command);

    if (proto == tpUnspecified || family == afUnspecified) {
        message->ignoreAddresses();
        // discard address block and TLVs
    } else {
        Parser::BinaryTokenizer tokHeader(header);
        parseAddresses(family, tokHeader, message);
        // TODO: parse TLVs for local connections
        if (message->hasForwardedAddresses())
            parseTLVs(tokHeader, message);
    }

    return Parsed(message, tokMessage.parsed());
}

uint32_t
ProxyProtocol::HeaderNameToHeaderType(const SBuf &headerStr)
{
    const auto it = Message::PseudoHeaderFields.find(headerStr);
    if (it != Message::PseudoHeaderFields.end())
        return it->second;

    Parser::Tokenizer ptok(headerStr);
    int64_t tlvType = 0;
    if (!ptok.int64(tlvType, 10, false))
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type. Expecting a positive decimal integer but got ", headerStr));
    if (tlvType > std::numeric_limits<uint8_t>::max())
        throw TexcHere(ToSBuf("Invalid PROXY protocol TLV type. Expecting an integer less than ",
                              std::numeric_limits<uint8_t>::max(), " but got ", tlvType));
    return static_cast<uint32_t>(tlvType);
}

ProxyProtocol::Parsed
ProxyProtocol::Parse(const SBuf &buf)
{
    Parser::Tokenizer magicTok(buf);

    const auto parser =
        magicTok.skip(Two::Magic) ? &Two::Parse :
        magicTok.skip(One::Magic) ? &One::Parse :
        nullptr;

    if (parser) {
        const auto parsed = (parser)(magicTok.remaining());
        return Parsed(parsed.message, magicTok.parsedSize() + parsed.size);
    }

    // detect and terminate other protocols
    if (buf.length() >= Two::Magic.length()) {
        // PROXY/1.0 magic is shorter, so we know that
        // the input does not start with any PROXY magic
        throw TexcHere("PROXY protocol error: invalid magic");
    }

    // TODO: detect short non-magic prefixes earlier to avoid
    // waiting for more data which may never come

    // not enough bytes to parse yet
    throw Parser::BinaryTokenizer::InsufficientInput();
}

