/*
 * $Id$
 * DEBUG: section 93    eCAP Interface
 */

#ifndef SQUID_ECAP_SERVICE_REP_H
#define SQUID_ECAP_SERVICE_REP_H

#include "adaptation/Service.h"
#include "adaptation/forward.h"
#include <libecap/common/forward.h>
#include <libecap/common/memory.h>

namespace Adaptation
{
namespace Ecap
{

/* The eCAP service representative maintains information about a single eCAP
   service that Squid communicates with. One eCAP module may register many
   eCAP services. */

class ServiceRep : public Adaptation::Service
{
public:
    explicit ServiceRep(const ServiceConfigPointer &aConfig);
    virtual ~ServiceRep();

    typedef libecap::shared_ptr<libecap::adapter::Service> AdapterService;

    /* Adaptation::Service API */
    virtual void finalize();
    virtual bool probed() const;
    virtual bool up() const;
    virtual Adaptation::Initiate *makeXactLauncher(HttpMsg *virginHeader, HttpRequest *virginCause);
    virtual bool wantsUrl(const String &urlPath) const;
    virtual void noteFailure();
    virtual const char *status() const;
    virtual void detach();
    virtual bool detached() const;

private:
    AdapterService theService; // the actual adaptation service we represent
    bool           isDetached;
};

/// register loaded eCAP module service
extern void RegisterAdapterService(const ServiceRep::AdapterService& adapterService);
/// unregister loaded eCAP module service by service uri
extern void UnregisterAdapterService(const String& serviceUri);

/// returns loaded eCAP module service by service uri
extern ServiceRep::AdapterService FindAdapterService(const String& serviceUri);

/// check for loaded eCAP services without matching ecap_service in squid.conf
extern void CheckUnusedAdapterServices(const Services& services);
} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_SERVICE_REP_H */
