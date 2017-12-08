/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "carp.cc"
#include "tests/STUB.h"

class CachePeer;
class ps_state;

void carpInit(void) STUB
CachePeer *carpSelectParent(ps_state *ps) STUB_RETVAL(NULL)

