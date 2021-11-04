#ifndef __INCLUDE_NETLINK_MANAGER_H__
#define __INCLUDE_NETLINK_MANAGER_H__
#include "netlink_handler.h"
#include <memory>
#include "event_reporter.h"

namespace OHOS {
namespace nmd {
namespace listeners {
void defaultOnInterfaceAddressUpdated(const std::string &, const std::string &, int, int);
void defaultOnInterfaceAddressRemoved(const std::string &, const std::string &, int, int);
void defaultOnInterfaceAdded(const std::string &);
void defaultOnInterfaceRemoved(const std::string &);
void defaultOnInterfaceChanged(const std::string &, bool);
void defaultOnInterfaceLinkStateChanged(const std::string &, bool);
void defaultOnRouteChanged(bool, const std::string &, const std::string &, const std::string &);
} // namespace listeners
class netlink_manager {
private:
    static int pid_;
    static std::shared_ptr<event_reporter> reporter_;

    std::shared_ptr<netlink_handler> routeHandler_;
    void startRouteHandler();

public:
    void start();
    void stop();

    int getRouteSock()
    {
        return this->routeHandler_->getSock();
    }
    std::shared_ptr<netlink_handler> getRouteHandler()
    {
        return this->routeHandler_;
    }

    static int getPid()
    {
        return pid_;
    }
    static void setPid(int pid)
    {
        pid_ = pid;
    }
    static std::shared_ptr<event_reporter> getReporter()
    {
        return reporter_;
    }

    explicit netlink_manager(int pid);
    ~netlink_manager();
};

} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_NETLINK_MANAGER_H__