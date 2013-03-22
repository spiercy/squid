#ifndef SQUID_IPC_STORE_MAP_H
#define SQUID_IPC_STORE_MAP_H

#include "Debug.h"
#include "ipc/ReadWriteLock.h"
#include "ipc/mem/Pointer.h"
#include "tools.h"
#include "typedefs.h"

namespace Ipc
{

#define SSL_SESSION_ID_SIZE 32
#define SSL_SESSION_MAX_SIZE 10*1024

/// a MemMap basic element, holding basic shareable memory block info
class MemMapSlot
{
public:
    mutable ReadWriteLock lock; ///< protects slot data below
    Atomic::WordT<uint8_t> waitingToBeFreed; ///< may be accessed w/o a lock

    /// possible persistent states
    typedef enum {
        Empty, ///< ready for writing, with nothing of value
        Writeable, ///< transitions from Empty to Readable
        Readable, ///< ready for reading
    } State;
    State state; ///< current state

    unsigned char key[SSL_SESSION_ID_SIZE]; ///< The entry key
    unsigned char p[SSL_SESSION_MAX_SIZE]; ///< The memory block;
    size_t pSize;
    time_t expire;

    MemMapSlot();
    size_t size() const {return sizeof(MemMapSlot);}
    size_t keySize() const {return sizeof(key);}
    bool sameKey(const cache_key *const aKey) const;
    void set(const unsigned char *aKey, const void *block, size_t blockSize, time_t expire = 0);
};

class MemMapCleaner;

/// map of MemMapSlots indexed by their keys, with read/write slot locking
/// kids extend to store custom data
class MemMap
{
public:
    typedef MemMapSlot Slot;

    /// data shared across maps in different processes
    class Shared
    {
    public:
        Shared(const int aLimit, const size_t anExtrasSize);
        size_t sharedMemorySize() const;
        static size_t SharedMemorySize(const int limit, const size_t anExtrasSize);
        Slot *slots();
        ~Shared();

        const int limit; ///< maximum number of map slots
        const size_t extrasSize; ///< size of slot extra data
        Atomic::Word count; ///< current number of map slots
    private:
        Shared(); //disabled
        Shared &operator=(const Shared&); //disabled
        Shared(const Shared&); //disabled
    };

public:
    typedef Mem::Owner<Shared> Owner;

    /// initialize shared memory
    static Owner *Init(const char *const path, const int limit);

    MemMap(const char *const aPath);

    /// finds, reservers space for writing a new entry or returns nil
    Slot *openForWriting(const cache_key *const key, sfileno &fileno);
    /// successfully finish writing the entry
    void closeForWriting(const sfileno fileno, bool lockForReading = false);

    /// only works on locked entries; returns nil unless the slot is readable
    const Slot *peekAtReader(const sfileno fileno) const;

    /// mark the slot as waiting to be freed and, if possible, free it
    void free(const sfileno fileno);

    /// open slot for reading, increments read level
    const Slot *openForReading(const cache_key *const key, sfileno &fileno);
    /// open slot for reading, increments read level
    const Slot *openForReadingAt(const sfileno fileno);
    /// close slot after reading, decrements read level
    void closeForReading(const sfileno fileno);

    /// called by lock holder to terminate either slot writing or reading
    void abortIo(const sfileno fileno);

    bool full() const; ///< there are no empty slots left
    bool valid(const int n) const; ///< whether n is a valid slot coordinate
    int entryCount() const; ///< number of used slots
    int entryLimit() const; ///< maximum number of slots that can be used

    /// adds approximate current stats to the supplied ones
    void updateStats(ReadWriteLockStats &stats) const;

    MemMapCleaner *cleaner; ///< notified before a readable entry is freed

protected:
    static Owner *Init(const char *const path, const int limit, const size_t extrasSize);

    const String path; ///< cache_dir path, used for logging
    Mem::Pointer<Shared> shared;
    int ttl;

private:
    int slotIndexByKey(const cache_key *const key) const;
    Slot &slotByKey(const cache_key *const key);

    Slot *openForReading(Slot &s);
    void abortWriting(const sfileno fileno);
    void freeIfNeeded(Slot &s);
    void freeLocked(Slot &s, bool keepLocked);
};

/// API for adjusting external state when dirty map slot is being freed
class MemMapCleaner
{
public:
    virtual ~MemMapCleaner() {}

    /// adjust slot-linked state before a locked Readable slot is erased
    virtual void cleanReadable(const sfileno fileno) = 0;
};

} // namespace Ipc

#endif /* SQUID_IPC_STORE_MAP_H */
