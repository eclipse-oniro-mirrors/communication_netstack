#ifndef __INCLUDE_NETLINK_HANDLER_H__
#define __INCLUDE_NETLINK_HANDLER_H__

#include "netlink_listener.h"
#include <vector>
#include "netlink_event.h"
#include <memory>
#include "event_reporter.h"

namespace OHOS {
namespace nmd {
class netlink_handler : public netlink_listener {
private:
    std::shared_ptr<event_reporter> reporter_;

public:
    void onEvent(std::shared_ptr<netlink_event> evt);

    void notifyInterfaceAdded(const std::string &ifName);
    void notifyInterfaceRemoved(const std::string &ifName);
    void notifyInterfaceChanged(const std::string &ifName, bool isUp);
    void notifyInterfaceLinkChanged(const std::string &ifName, bool isUp);
    void notifyAddressUpdated(const std::string &addr, const std::string &ifName, int flags, int scope);
    void notifyAddressRemoved(const std::string &addr, const std::string &ifName, int flags, int scope);
    void notifyRouteChange(
        bool updated, const std::string &route, const std::string &gateway, const std::string &ifName);

    int start();
    void stop();

    int getSock()
    {
        return this->socketFd_;
    }

    void setEventListener(const std::shared_ptr<event_reporter> &reporter)
    {
        this->reporter_ = reporter;
    }

    netlink_handler(int protocol, int pid);
    ~netlink_handler();
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_NETLINK_HANDLER_H__