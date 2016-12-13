/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "ClientDelayConfig.h"
#define STUB_API "ClientDelayConfig.cc"
#include "tests/STUB.h"

ClientDelayConfig::~ClientDelayConfig() STUB_NOP

#endif

