/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_ID_QUEUE_H
#define SQUID_IPC_ID_QUEUE_H

#include "base/TextException.h"
#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/Pointer.h"

#include <atomic>

namespace Ipc
{

/**
 * Lockless fixed-capacity more-or-less LIFO queue of atomic items. 
 *
 * Supports unlimited number of writers and readers. Suitable for
 * storing resource IDs for which strict order of retrieval and instant
 * availability of each queued item is not required. IDs must have
 * an std::atomic<> specialization and an "impossible" or "null" value.
 *
 * For strict lockless FIFO queues, see Ipc::OneToOneUniQueue and friends.
 *
 * TODO: Use this in Ipc::Mem::PageStack.
 */
template <class Id>
class IdQueue
{
public:
    typedef uint32_t size_type;
    typedef std::atomic<Id> value_type;
    typedef Ipc::Mem::Owner< IdQueue<Id> > Owner;

    inline IdQueue(const size_type aCapacity, const Id aNilId);

    /// fill the just-initialized queue with IDs, starting with `firstId`
    inline void prefill(size_type firstId);

    size_t sharedMemorySize() const { return SharedMemorySize(capacity, nilId); }
    static size_t SharedMemorySize(const int aCapacity, const Id) { return sizeof(IdQueue) + sizeof(value_type) * aCapacity; }

    /// approximate number of IDs in the queue (for statistics and such)
    size_type size() const { const size_type sz = size_; return sz > capacity ? 0 : sz; }

    /// returns true iff a [non-nil] id was extracted
    inline bool pop(Id &id);

    /// adds pop()ed id back into the queue at about the same position
    // TODO: inline void unPop(const Id id);

    /// adds the id to the queue
    inline void push(const Id id);

    const Id nilId; // "impossible" or "null" ID value
    const size_type capacity;

private:
    /// approximate number of IDs in the queue; may occasionally underflow
    std::atomic<size_type> size_;

    std::atomic<size_type> pushPos; ///< input index; overflows OK
    std::atomic<size_type> popPos; ///< output index; overflows OK
    Ipc::Mem::FlexibleArray< value_type > ring; // IDs
};

template <class Id>
IdQueue<Id>::IdQueue(const size_type aCapacity, const Id aNilId):
    nilId(aNilId),
    capacity(aCapacity),
    size_(0),
    pushPos(0),
    popPos(0),
    ring(capacity)
{
}

template <class Id>
void
IdQueue<Id>::prefill(size_type id)
{
    // this method is meant to be called before the first push()
    Must(!size_);
    Must(!pushPos);

    // we are emulating push(id); push(nilId) is not allowed
    Must(id != nilId);

    while (pushPos < capacity)
        ring[pushPos++] = id++;
    size_ = capacity;
}

template <class Id>
void
IdQueue<Id>::push(const Id id)
{
    Must(id != nilId);

    // We should be able to find the hole much faster, but, technically, there
    // is no guarantee that we would find it at all. This limits our damages
    // and also protects from division by zero inside the loop.
    size_type holeSearchAllowance = 2*capacity;

    // find a nil slot, starting with pushPos and going right
    while (holeSearchAllowance--) {
        size_type idx = pushPos;
        Id expectedNilId = nilId;
        const bool pushed = ring[idx % capacity].compare_exchange_strong(expectedNilId, id);

        // Whether we pushed the page number or not, we should try going right
        // to maintain the index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        pushPos.compare_exchange_weak(idx, idx+1); // may fail or lie

        if (pushed) {
            popPos = idx; // may lie
            ++size_;
        }
        // TODO: report suspiciously long loops
    }

    Must(false);
}

template <class Id>
bool
IdQueue<Id>::pop(Id &id)
{
    // find a non-nil slot, starting with popPos and going left
    while (size()) {
        size_type idx = popPos;
        // invalidate the slot at idx while extracting its current value
        const Id value = ring[idx % capacity].exchange(nilId);
        const bool popped = value != nilId;

        // Whether we popped or not, we should try going left
        // to maintain the pop index (and make progress).
        // We may fail if others already updated the index, but that is OK.
        popPos.compare_exchange_weak(idx, idx-1); // may fail or lie

        if (popped) {
            pushPos = idx; // may lie
            id = value;
            --size_;
            return true;
        }
        // TODO: report suspiciously long loops
    }
    return false;
}

} // namespace Ipc

#endif // SQUID_IPC_ID_QUEUE_H
