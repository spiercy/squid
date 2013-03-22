#ifndef SQUID_BASE_ASYNCCBDATACALLS_H
#define SQUID_BASE_ASYNCCBDATACALLS_H

#include "base/AsyncCall.h"
#include "base/CbcPointer.h"

/// Dialers to run cbdata callback functions as Async Calls,
/// to ease the transition of the corresponding cbdata objects to full Jobs:

/// function(cbdata *self) dialer
template<class Argument1>
class UnaryCbdataDialer : public CallDialer
{
public:
    typedef void Handler(Argument1 *);

    UnaryCbdataDialer(Handler *aHandler, Argument1 *aArg) :
            arg1(aArg),
            handler(aHandler) {}

    virtual bool canDial(AsyncCall &call) { return arg1.valid(); }
    void dial(AsyncCall &call) { handler(arg1.get()); }
    virtual void print(std::ostream &os) const {  os << '(' << arg1 << ')'; }

public:
    CbcPointer<Argument1> arg1;
    Handler *handler;
};

/// function(cbdata *self, cbdata *arg2) dialer
template<class Argument1, class Argument2>
class BinaryCbdataDialer : public CallDialer
{
public:
    typedef void Handler(Argument1 *, Argument2 *);

    BinaryCbdataDialer(Handler *aHandler, Argument1 *a1, Argument2 *a2):
            arg1(a1), arg2(a2),
            handler(aHandler) {}

    virtual bool canDial(AsyncCall &call) { return arg1.valid() && (!arg2.set() || arg2.valid()); }
    void dial(AsyncCall &call) { handler(arg1.get(), arg2.raw()); }
    virtual void print(std::ostream &os) const {
        os << '(' << arg1 << ", " << arg2 << ')'; }

public:
    CbcPointer<Argument1> arg1;
    CbcPointer<Argument2> arg2;
    Handler *handler;
};

/// Helper functions to simplify Dialer creation.

/// Creates UnaryCbdataDialer.
template <class Argument1>
UnaryCbdataDialer<Argument1>
cbdataDialer(typename UnaryCbdataDialer<Argument1>::Handler *handler, Argument1 *arg1)
{
    return UnaryCbdataDialer<Argument1>(handler, arg1);
}

/// Creates BinaryCbdataDialer.
template <class Argument1, class Argument2>
BinaryCbdataDialer<Argument1, Argument2>
cbdataDialer(typename BinaryCbdataDialer<Argument1,Argument2>::Handler *handler,
             Argument1 *arg1, Argument2 *arg2)
{
    return BinaryCbdataDialer<Argument1,Argument2>(handler, arg1, arg2);
}

#endif
