/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "proxyp/Message.h"
#include "proxyp/Protocol.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "StrList.h"

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
                // XXX: tellp() always returns -1
                if (!result.buf().isEmpty())
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

bool
ProxyProtocol::Message::hasMatchingTcpVersion(const SBuf &tcpVersion) const
{
    if (tcpVersion.cmp("4") == 0)
        return sourceAddress.isIPv4() && destinationAddress.isIPv4();
    return tcpVersion.cmp("6") == 0 && sourceAddress.isIPv6() && destinationAddress.isIPv6();
}
