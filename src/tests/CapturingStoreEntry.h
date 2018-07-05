/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TESTS_CAPTURINGSTORE_ENTRY_H
#define SQUID_TESTS_CAPTURINGSTORE_ENTRY_H

#include "Store.h"

/* class that captures various call data for test analysis */

class CapturingStoreEntry : public StoreEntry
{
    MEMPROXY_CLASS(CapturingStoreEntry);

public:
    CapturingStoreEntry() : _buffer_calls(0), _flush_calls(0) {}

    String _appended_text;
    int _buffer_calls;
    int _flush_calls;
};

class CapturingStoreEntryPacker : public Packable
{
public:
    CapturingStoreEntryPacker(CapturingStoreEntry &e) : entry(&e) {}

    virtual void append(char const *buf, int len) override {
         if (!buf || len < 0) // old 'String' can't handle these cases
             return;
         entry->_appended_text.append(buf, len);
    }
    virtual void buffer() override { entry->_buffer_calls++; }
    virtual void flush() override { entry->_flush_calls++; }
    // TODO: fix duplication with StoreEntry::vappendf()
    virtual void vappendf(const char *fmt, va_list vargs) override
    {
        LOCAL_ARRAY(char, buf, 4096);
        *buf = 0;
        int x;

        va_list ap;
        /* Fix of bug 753r. The value of vargs is undefined
         * after vsnprintf() returns. Make a copy of vargs
         * incase we loop around and call vsnprintf() again.
         */
        va_copy(ap,vargs);
        errno = 0;
        if ((x = vsnprintf(buf, sizeof(buf), fmt, ap)) < 0) {
            fatal(xstrerr(errno));
            return;
        }
        va_end(ap);

        if (x < static_cast<int>(sizeof(buf))) {
            append(buf, x);
            return;
        }

        // okay, do it the slow way.
        char *buf2 = new char[x+1];
        int y = vsnprintf(buf2, x+1, fmt, vargs);
        assert(y >= 0 && y == x);
        append(buf2, y);
        delete[] buf2;
    }

private:
    CapturingStoreEntry *entry;
};

#endif

