#include "netlink_handler.h"
#include "logger.h"
#include <memory>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <interface_controller.h>
#include <sock_diag.h>
#include <network_controller.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
netlink_handler::netlink_handler(int protocol, int pid) : netlink_listener(protocol, pid)
{
    this->setOnEventHandler(std::bind(&netlink_handler::onEvent, this, std::placeholders::_1));
}

netlink_handler::~netlink_handler() {}

static long parseIfIndex(const char *ifIndex)
{
    if (ifIndex == nullptr) {
        return 0;
    }
    long ifaceIndex = strtol(ifIndex, nullptr, 10);
    // strtol returns 0 on error, which is fine because 0 is not a valid ifindex.
    if (errno == ERANGE && (ifaceIndex == LONG_MAX || ifaceIndex == LONG_MIN)) {
        return 0;
    }
    return ifaceIndex;
}

void netlink_handler::onEvent(std::shared_ptr<netlink_event> evt)
{
    const char *iface = evt->findParam("INTERFACE");
    const char *address = evt->findParam("ADDRESS");
    const char *flags = evt->findParam("FLAGS");
    const char *scope = evt->findParam("SCOPE");
    const char *ifIndex = evt->findParam("IFINDEX");
    const char *route = evt->findParam("ROUTE");
    const char *gateway = evt->findParam("GATEWAY");
    // yep, we got the netlink message action, so let's notify the user
    switch (evt->getAction()) {
        case Action::Unknown:
            // LogError << "[NetlinkHandler]: unknown action." << endl;
            NETNATIVE_LOGE("[NetlinkHandler]: unknown action.");
            break;
        case Action::Add: {
            notifyInterfaceAdded(iface);
            break;
        }
        case Action::Remove: {
            // std::cout << "remvoe interface onEvent" << std::endl;
            NETNATIVE_LOGI("remvoe interface onEvent");
            notifyInterfaceRemoved(iface);
            break;
        }
        case Action::Change:
            break;
        case Action::LinkUp: {
            notifyInterfaceLinkChanged(iface, true);
            break;
        }
        case Action::LinkDown: {
            notifyInterfaceLinkChanged(iface, false);
            break;
        }
        case Action::AddressUpdated:
        case Action::AddressRemoved:
            char addrstr[INET6_ADDRSTRLEN + 4];
            strncpy(addrstr, address, sizeof(addrstr));
            if (!parseIfIndex(ifIndex)) {
                // LogError << "invalid interface index: " << iface << "(" << ifIndex << ")" << endl;
                NETNATIVE_LOGE("invalid interface index: %{public}s (%{public}s)", iface, ifIndex);
            }
            // Note: if this interface was deleted, iface is "" and we don't notify.
            if (iface && iface[0] && address && flags && scope) {
                if (evt->getAction() == Action::AddressUpdated) {
                    notifyAddressUpdated(address, iface, std::stoi(flags), std::stoi(scope));
                } else {
                    notifyAddressRemoved(address, iface, std::stoi(flags), std::stoi(scope));
                }
            }
            break;
        case Action::RouteUpdated: {
            if (route && (gateway || iface)) {
                notifyRouteChange(
                    true, route, (gateway == nullptr) ? "" : gateway, (iface == nullptr) ? "" : iface);
            }
            break;
        }
        case Action::RouteRemoved: {
            if (route && (gateway || iface)) {
                notifyRouteChange(
                    false, route, (gateway == nullptr) ? "" : gateway, (iface == nullptr) ? "" : iface);
            }
            break;
        }
        case Action::DelRule:
        case Action::NewRule: {
            // common::logger::info() << "[NetlinkHandler]: rule changed." << endl;
            NETNATIVE_LOGI("[NetlinkHandler]: rule changed.");
            break;
        }
        default:
            break;
    }
}

void netlink_handler::notifyInterfaceAdded(const std::string &ifName)
{
    this->reporter_->getListener().onInterfaceAdded(ifName);
}

void netlink_handler::notifyInterfaceRemoved(const std::string &ifName)
{
    this->reporter_->getListener().onInterfaceRemoved(ifName);
}

void netlink_handler::notifyInterfaceChanged(const std::string &ifName, bool isUp)
{
    this->reporter_->getListener().onInterfaceChanged(ifName, isUp);
}

void netlink_handler::notifyInterfaceLinkChanged(const std::string &ifName, bool isUp)
{
    this->reporter_->getListener().onInterfaceLinkStateChanged(ifName, isUp);
}

void netlink_handler::notifyAddressUpdated(const std::string &addr, const std::string &ifName, int flags, int scope)
{
    this->reporter_->getListener().onInterfaceAddressUpdated(addr, ifName, flags, scope);
}

void netlink_handler::notifyAddressRemoved(const std::string &addr, const std::string &ifName, int flags, int scope)
{
    this->reporter_->getListener().onInterfaceAddressRemoved(addr, ifName, flags, scope);
}

void netlink_handler::notifyRouteChange(
    bool updated, const std::string &route, const std::string &gateway, const std::string &ifName)
{
    this->reporter_->getListener().onRouteChanged(updated, route, gateway, ifName);
}

int netlink_handler::start()
{
    // common::logger::info() << "[NetLinkHandler] start." << endl;
    NETNATIVE_LOGI("[NetLinkHandler] start.");
    return this->listen();
}

void netlink_handler::stop()
{
    this->stopListen();
}

} // namespace nmd
} // namespace OHOS