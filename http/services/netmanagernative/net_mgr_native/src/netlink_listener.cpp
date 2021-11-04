#include <netlink_listener.h>
#include <iostream>
#include "logger.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
netlink_listener::netlink_listener(int protocol, int pid)
{
    this->create(protocol);
    this->pid_ = pid;
    this->setOnDataReceiveHandler(std::bind(&netlink_listener::onDataAvaliable, this, std::placeholders::_1,
        std::placeholders::_2, std::placeholders::_3));
}

netlink_listener::~netlink_listener() {}

void netlink_listener::onDataAvaliable(int, char *buf, ssize_t size)
{
    // common::logger::info() << "[NetlinkListener] netlink message come." << endl;
    NETNATIVE_LOGI("[NetlinkListener] netlink message come.");
    std::shared_ptr<netlink_event> event = std::make_shared<netlink_event>();

    if (!event->parseNetLinkMessage(buf, size)) {
        // LogError << "[NetlinkListener] netlink message parse failed." << endl;
        NETNATIVE_LOGE("[NetlinkListener] netlink message parse failed.");
    } else {
        this->onEventHandler_(event);
    }
}

void netlink_listener::setOnEventHandler(const std::function<void(std::shared_ptr<netlink_event>)> &handler)
{
    this->onEventHandler_ = handler;
}

int netlink_listener::listen()
{
    if (this->binding() == -1) {
        return -1;
    }
    // common::logger::info() << "[NetlinkListener] start listen at pid:" << this->pid_ << endl;
    NETNATIVE_LOGI("[NetlinkListener] start listen at pid: %{public}d", this->pid_);
    this->running_ = true;
    while (this->running_) {
        this->acceptAndListen();
    }
    return 1;
}

void netlink_listener::stopListen()
{
    this->running_ = false;
}

bool netlink_listener::getNetlinkListenerState()
{
    return this->running_;
}
} // namespace nmd
} // namespace OHOS
