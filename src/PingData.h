/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PINGDATA_H
#define SQUID_PINGDATA_H

class ping_data
{

public:
    ping_data();

    struct timeval start;

    struct timeval stop;
    int reqnum;
    int n_sent;
    int n_recv;
    int n_mcast_replies_expect;
    int n_parent_replies_expect;
    int n_sibling_replies_expect;
    int n_replies_expected;
    int timeout;        /* msec */
    int mcast_rtt;
    int parent_rtt;
    int sibling_rtt;
    int timedout;
    int w_rtt;
    int p_rtt;
};

#endif /* SQUID_PINGDATA_H */

