/*
 * DEBUG: section 54    Interprocess Communication
 */

#include "squid.h"
#include "ipc/MemMap.h"
#include "store_key_md5.h"
#include "tools.h"

Ipc::MemMap::MemMap(const char *const aPath): cleaner(NULL), path(aPath),
                    shared(shm_old(Shared)(aPath))
{
    assert(shared->limit > 0); // we should not be created otherwise
    debugs(54, 5, HERE << "attached map [" << path << "] created: " <<
           shared->limit);
}

Ipc::MemMap::Owner *
Ipc::MemMap::Init(const char *const path, const int limit, const size_t extrasSize)
{
    assert(limit > 0); // we should not be created otherwise
    Owner *const owner = shm_new(Shared)(path, limit, extrasSize);
    debugs(54, 5, HERE << "new map [" << path << "] created: " << limit);
    return owner;
}

Ipc::MemMap::Owner *
Ipc::MemMap::Init(const char *const path, const int limit)
{
    return Init(path, limit, 0);
}


Ipc::MemMap::Slot *
Ipc::MemMap::openForWriting(const cache_key *const key, sfileno &fileno)
{
    Slot *slots = shared->slots();

    debugs(54, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for writing in map [" << path << ']');
    const int idx = slotIndexByKey(key);

    Slot &s = slots[idx];
    ReadWriteLock &lock = s.lock;

    if (lock.lockExclusive()) {
        assert(s.state != Slot::Writeable); // until we start breaking locks

        // free if the entry was used, keeping the entry locked
        if (s.waitingToBeFreed || s.state == Slot::Readable)
            freeLocked(s, true);

        assert(s.state == Slot::Empty);
        ++shared->count;
        s.state = Slot::Writeable;
        fileno = idx;
        //s.setKey(key); // XXX: the caller should do that
        debugs(54, 5, HERE << " opened slot at " << idx <<
               " for writing in map [" << path << ']');
        return &s; // and keep the entry locked
    }

    debugs(54, 5, HERE << " failed to open slot at " << idx <<
           " for writing in map [" << path << ']');
    return NULL;
}

void
Ipc::MemMap::closeForWriting(const sfileno fileno, bool lockForReading)
{
    debugs(54, 5, HERE << " closing slot at " << fileno << " for writing and "
           "openning for reading in map [" << path << ']');
    assert(valid(fileno));
    Slot *slots = shared->slots();
    Slot &s = slots[fileno];
    assert(s.state == Slot::Writeable);
    s.state = Slot::Readable;
    if (lockForReading)
        s.lock.switchExclusiveToShared();
    else
        s.lock.unlockExclusive();
}

/// terminate writing the entry, freeing its slot for others to use
void
Ipc::MemMap::abortWriting(const sfileno fileno)
{
    debugs(54, 5, HERE << " abort writing slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot *slots = shared->slots();
    Slot &s = slots[fileno];
    assert(s.state == Slot::Writeable);
    freeLocked(s, false);
}

void
Ipc::MemMap::abortIo(const sfileno fileno)
{
    debugs(54, 5, HERE << " abort I/O for slot at " << fileno <<
           " in map [" << path << ']');
    assert(valid(fileno));
    Slot *slots = shared->slots();
    Slot &s = slots[fileno];

    // The caller is a lock holder. Thus, if we are Writeable, then the
    // caller must be the writer; otherwise the caller must be the reader.
    if (s.state == Slot::Writeable)
        abortWriting(fileno);
    else
        closeForReading(fileno);
}

const Ipc::MemMap::Slot *
Ipc::MemMap::peekAtReader(const sfileno fileno) const
{
    assert(valid(fileno));
    Slot *slots = shared->slots();
    const Slot &s = slots[fileno];
    switch (s.state) {
    case Slot::Readable:
        return &s; // immediate access by lock holder so no locking
    case Slot::Writeable:
        return NULL; // cannot read the slot when it is being written
    case Slot::Empty:
        assert(false); // must be locked for reading or writing
    }
    assert(false); // not reachable
    return NULL;
}

void
Ipc::MemMap::free(const sfileno fileno)
{
    debugs(54, 5, HERE << " marking slot at " << fileno << " to be freed in"
           " map [" << path << ']');

    assert(valid(fileno));
    Slot *slots = shared->slots();
    Slot &s = slots[fileno];

    if (s.lock.lockExclusive())
        freeLocked(s, false);
    else
        s.waitingToBeFreed = true; // mark to free it later
}

const Ipc::MemMap::Slot *
Ipc::MemMap::openForReading(const cache_key *const key, sfileno &fileno)
{
    debugs(54, 5, HERE << " trying to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    const int idx = slotIndexByKey(key);
    if (const Slot *slot = openForReadingAt(idx)) {
        if (slot->sameKey(key)) {
            fileno = idx;
            debugs(54, 5, HERE << " opened slot at " << fileno << " for key "
                   << storeKeyText(key) << " for reading in map [" << path <<
                   ']');
            return slot; // locked for reading
        }
        slot->lock.unlockShared();
    }
    debugs(54, 5, HERE << " failed to open slot for key " << storeKeyText(key)
           << " for reading in map [" << path << ']');
    return NULL;
}

const Ipc::MemMap::Slot *
Ipc::MemMap::openForReadingAt(const sfileno fileno)
{
    Slot *slots = shared->slots();

    debugs(54, 5, HERE << " trying to open slot at " << fileno << " for "
           "reading in map [" << path << ']');
    assert(valid(fileno));
    Slot &s = slots[fileno];

    if (!s.lock.lockShared()) {
        debugs(54, 5, HERE << " failed to lock slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return NULL;
    }

    if (s.state == Slot::Empty) {
        s.lock.unlockShared();
        debugs(54, 7, HERE << " empty slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return NULL;
    }

    if (s.waitingToBeFreed) {
        s.lock.unlockShared();
        debugs(54, 7, HERE << " dirty slot at " << fileno << " for "
               "reading in map [" << path << ']');
        return NULL;
    }

    // cannot be Writing here if we got shared lock and checked Empty above
    assert(s.state == Slot::Readable);
    debugs(54, 5, HERE << " opened slot at " << fileno << " for reading in"
           " map [" << path << ']');
    return &s;
}

void
Ipc::MemMap::closeForReading(const sfileno fileno)
{
    debugs(54, 5, HERE << " closing slot at " << fileno << " for reading in "
           "map [" << path << ']');
    assert(valid(fileno));
    Slot *slots = shared->slots();
    Slot &s = slots[fileno];
    assert(s.state == Slot::Readable);
    s.lock.unlockShared();
}

int
Ipc::MemMap::entryLimit() const
{
    return shared->limit;
}

int
Ipc::MemMap::entryCount() const
{
    return shared->count;
}

bool
Ipc::MemMap::full() const
{
    return entryCount() >= entryLimit();
}

void
Ipc::MemMap::updateStats(ReadWriteLockStats &stats) const
{
    Slot *slots = shared->slots();
    for (int i = 0; i < shared->limit; ++i)
        slots[i].lock.updateStats(stats);
}

bool
Ipc::MemMap::valid(const int pos) const
{
    return 0 <= pos && pos < entryLimit();
}

static
unsigned int
hash_key(const unsigned char *data, unsigned int len, unsigned int hashSize)
{
    unsigned int n;
    unsigned int j;
    for(j = 0, n = 0; j < len; j++ ) {
        n ^= 271 * *data;
        ++data;
    }
    return (n ^ (j * 271)) % hashSize;
}

int
Ipc::MemMap::slotIndexByKey(const cache_key *const key) const
{
    const unsigned char *k = reinterpret_cast<const unsigned char *>(key);
    return hash_key(k, SSL_SESSION_ID_SIZE, shared->limit);
}

Ipc::MemMap::Slot &
Ipc::MemMap::slotByKey(const cache_key *const key)
{
    Slot *slots = shared->slots();
    return slots[slotIndexByKey(key)];
}

/// unconditionally frees the already exclusively locked slot and releases lock
void
Ipc::MemMap::freeLocked(Slot &s, bool keepLocked)
{
    Slot *slots = shared->slots();
    if (s.state == Slot::Readable && cleaner)
        cleaner->cleanReadable(&s - slots);

    s.waitingToBeFreed = false;
    s.state = Slot::Empty;
    if (!keepLocked)
        s.lock.unlockExclusive();
    --shared->count;
    debugs(54, 5, HERE << " freed slot at " << (&s - slots) <<
           " in map [" << path << ']');
}

/* Ipc::MemMapSlot */
Ipc::MemMapSlot::MemMapSlot(): state(Empty)
{
    memset(key, 0, sizeof(key));
    memset(p, 0, sizeof(p));
    pSize = 0;
}

void
Ipc::MemMapSlot::set(const unsigned char *aKey, const void *block, size_t blockSize, time_t expireOn)
{
    memcpy(key, aKey, sizeof(key));
    if (block)
        memcpy(p, block, blockSize);
    pSize = blockSize;
    expire = expireOn;
}

bool
Ipc::MemMapSlot::sameKey(const cache_key *const aKey) const
{
    return (memcmp(key, aKey, sizeof(key)) == 0);
}

/* Ipc::MemMap::Shared */

Ipc::MemMap::Shared::Shared(const int aLimit, const size_t anExtrasSize):
    limit(aLimit), extrasSize(anExtrasSize), count(0)
{
    // All of the Slot members should initialized to zero.
    // XXX: use FlexibleArray instead of this hack
    memset(slots(), 0, aLimit * sizeof(Shared));
}

Ipc::MemMap::Shared::~Shared()
{
}

size_t
Ipc::MemMap::Shared::sharedMemorySize() const
{
    return SharedMemorySize(limit, extrasSize);
}

size_t
Ipc::MemMap::Shared::SharedMemorySize(const int limit, const size_t extrasSize)
{
    return sizeof(Shared) + limit * (sizeof(Slot) + extrasSize);
}

Ipc::MemMap::Slot *
Ipc::MemMap::Shared::slots()
{
    // XXX: use FlexibleArray instead of this hack
    void *p = this;
    return (Slot *)((size_t)p + sizeof(Shared));
}
