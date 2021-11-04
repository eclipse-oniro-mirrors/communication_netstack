#include <netlink_manager.h>
#include <thread>
#include <logger.h>
#include <warning_disable.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
int netlink_manager::pid_;
std::shared_ptr<nmd::event_reporter> netlink_manager::reporter_;

void listeners::defaultOnInterfaceAddressUpdated(const std::string &, const std::string &, int, int) {}
void listeners::defaultOnInterfaceAddressRemoved(const std::string &, const std::string &, int, int) {}
void listeners::defaultOnInterfaceAdded(const std::string &) {}
void listeners::defaultOnInterfaceRemoved(const std::string &) {}
void listeners::defaultOnInterfaceChanged(const std::string &, bool) {}
void listeners::defaultOnInterfaceLinkStateChanged(const std::string &, bool) {}
void listeners::defaultOnRouteChanged(bool, const std::string &, const std::string &, const std::string &) {}

netlink_manager::netlink_manager(int pid) : routeHandler_(std::make_shared<netlink_handler>(NETLINK_ROUTE, pid))
{
    this->pid_ = pid;
    this->reporter_ = std::make_shared<event_reporter>();

    DISABLE_WARNING_PUSH
    DISABLE_WARNING_C99_EXTENSIONS

    inetd_unsolicited_event_listener glistener {
        .onInterfaceAddressUpdated = listeners::defaultOnInterfaceAddressUpdated,
        .onInterfaceAddressRemoved = listeners::defaultOnInterfaceAddressRemoved,
        .onInterfaceAdded = listeners::defaultOnInterfaceAdded,
        .onInterfaceRemoved = listeners::defaultOnInterfaceRemoved,
        .onInterfaceChanged = listeners::defaultOnInterfaceChanged,
        .onInterfaceLinkStateChanged = listeners::defaultOnInterfaceLinkStateChanged,
        .onRouteChanged = listeners::defaultOnRouteChanged,
    };

    DISABLE_WARNING_POP

    this->reporter_->registerEventListener(glistener);
    this->routeHandler_->setEventListener(this->reporter_);
}

netlink_manager::~netlink_manager() {}

void netlink_manager::startRouteHandler()
{
    NETNATIVE_LOGE("[NetlinkManager] startRouteHandler");
    if (this->routeHandler_->start() == -1) {
        // LogError << "[NetlinkManager] satrt failed." << endl;
        NETNATIVE_LOGE("[NetlinkManager] satrt failed.");
    } else {
        // common::logger::info() << "[NetlinkManager] satrted." << endl;
        NETNATIVE_LOGI("[NetlinkManager] satrted.");
    }
}

void netlink_manager::start()
{
    this->startRouteHandler();
}

void netlink_manager::stop()
{
    this->routeHandler_->stop();
}
} // namespace nmd
} // namespace OHOS
