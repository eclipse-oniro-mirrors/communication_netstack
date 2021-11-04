#ifndef __INCLUDE_EVENT_REPORTER_H__
#define __INCLUDE_EVENT_REPORTER_H__
#include <string>

namespace OHOS {
namespace nmd {

typedef struct inetd_unsolicited_event_listener {
    void (*onInterfaceAddressUpdated)(const std::string &addr, const std::string &ifName, int flags, int scope);
    void (*onInterfaceAddressRemoved)(const std::string &addr, const std::string &ifName, int flags, int scope);
    void (*onInterfaceAdded)(const std::string &ifName);
    void (*onInterfaceRemoved)(const std::string &ifName);
    void (*onInterfaceChanged)(const std::string &ifName, bool up);
    void (*onInterfaceLinkStateChanged)(const std::string &ifName, bool up);
    void (*onRouteChanged)(
        bool updated, const std::string &route, const std::string &gateway, const std::string &ifName);
} inetd_unsolicited_event_listener;

class event_reporter {
private:
    inetd_unsolicited_event_listener listener_;

public:
    event_reporter() = default;
    void registerEventListener(inetd_unsolicited_event_listener &listener);
    inetd_unsolicited_event_listener getListener()
    {
        return this->listener_;
    }
    ~event_reporter();
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_EVENT_REPORTER_H__