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
#include "sbuf/SBuf.h"

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
} ProxyProtocolTwoTypes;

class ProxyProtocolTwoTlv
{
    public:
        typedef RefCount<AccessLogEntry> Pointer;

        ProxyProtocolTwoTlv() : type(PP2_TYPE_UNKNOWN) {}

        static bool CheckType(const ProxyProtocolTwoTypes t) {
            switch(t) {
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
                    return true;
                default:
                    return false;
            }
        }

        ProxyProtocolTwoTypes type;
        SBuf value;
};

class ProxyProtocolTwoMessage : public RefCountable
{
    public:
        typedef RefCount<ProxyProtocolTwoMessage> Pointer;
        typedef std::vector<ProxyProtocolTwoTlv> Tlvs;

        Tlvs tlvs;
};


#endif

