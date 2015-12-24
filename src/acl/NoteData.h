/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLNOTEDATA_H
#define SQUID_ACLNOTEDATA_H

#include "acl/Data.h"
#include "MemPool.h"
#include "Notes.h"
#include "SquidString.h"

class ACLStringData;

/// \ingroup ACLAPI
class ACLNoteData : public ACLData<NotePairs::Entry *>
{
public:
    MEMPROXY_CLASS(ACLNoteData);

    ACLNoteData();
    virtual ~ACLNoteData();
    virtual bool match(NotePairs::Entry *);
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const;
    virtual ACLData<NotePairs::Entry *> *clone() const;

private:
    String name;                   ///< Note name to check. It is always set
    ACLStringData *values; ///< if set, at least one value must match
};

MEMPROXY_CLASS_INLINE(ACLNoteData);

#endif /* SQUID_ACLNOTEDATA_H */

