#include "native_netd_service.h"
#include "interface_controller.h"
//#include "logger.h"
//#include "error_code.h"
#include "netlink_manager.h"
#include "network_controller.h"
#include "route_controller.h"
#include "traffic_controller.h"
#include "interface_controller.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sock_diag.h>
#include <utils.h>
#include <net/if.h>
#include "netnative_log_wrapper.h"

std::vector<unsigned int> OHOS::nmd::NativeNetdService::interfaceIdex_;

namespace OHOS {
namespace nmd {

NativeNetdService::NativeNetdService(/* args */)
    : networkController_(std::make_shared<network_controller>()),
      routeController_(std::make_shared<route_controller>()),
      interfaceController_(std::make_shared<interface_controller>())
{}

NativeNetdService::~NativeNetdService() {}

void NativeNetdService::initChildChains()
{
    NETNATIVE_LOGD("nmd::NativeNetdService::initChildChains()");

    route_controller::createChildChains("mangle", "INPUT", "routectrl_mangle_INPUT");
    route_controller::createChildChains("filter", "FORWARD", "TETHER_TRAFFIC");
}

void NativeNetdService::initUnixSocket()
{
    NETNATIVE_LOGD("nmd::NativeNetdService::initUnixSocket()");
    static const char *filePath = "/dev/socket";
    if ((common::utils::removeDirectory(filePath) == -2) || (mkdir(filePath, 0643) == -1)) {
        NETNATIVE_LOGD("[Socket] Unable to remove dir: '%{public}s' %{public}s", filePath, strerror(errno));
        exit(-1);
    }
}

void NativeNetdService::getOriginInterfaceIdex()
{
    NETNATIVE_LOGD("nmd::NativeNetdService::getOriginInterfaceIdex()");
    std::vector<std::string> ifNameList = interface_controller::getInterfaceNames();
    NativeNetdService::interfaceIdex_.clear();
    for (auto iter = ifNameList.begin(); iter != ifNameList.end(); ++iter) {
        unsigned int infIndex = if_nametoindex((*iter).c_str());
        NativeNetdService::interfaceIdex_.push_back(infIndex);
    }
}

void NativeNetdService::updateInterfaceIdex(unsigned int infIndex)
{
    NativeNetdService::interfaceIdex_.push_back(infIndex);
}

std::vector<unsigned int> NativeNetdService::getCurrentInterfaceIdex()
{
    return NativeNetdService::interfaceIdex_;
}

void NativeNetdService::init()
{
    NETNATIVE_LOGD("nmd::NativeNetdService::init()");
    this->initChildChains();
    this->initUnixSocket();
    this->getOriginInterfaceIdex();
}

int NativeNetdService::networkCreatePhysical(int netId, int permission)
{
    return this->networkController_->createPhysicalNetwork(
        static_cast<uint16_t>(netId), static_cast<Permission>(permission));
}

int NativeNetdService::networkDestroy(int netId)
{
    return this->networkController_->destroyNetwork(netId);
}

int NativeNetdService::networkAddInterface(int netId, std::string interfaceName)
{
    return this->networkController_->addInterfaceToNetwork(netId, interfaceName);
}

int NativeNetdService::networkRemoveInterface(int netId, std::string interfaceName)
{
    return this->networkController_->removeInterfaceFromNetwork(netId, interfaceName);
}

void NativeNetdService::socketDestroy(std::string ifName)
{
    sock_diag dg;
    if (dg.open()) {
        dg.destroySockets(ifName);
    }
}

void NativeNetdService::socketDestroy(int netId)
{
    nmd::network *nw = this->networkController_->getNetwork(netId);
    if (nw != nullptr) {
        sock_diag dg;
        if (dg.open()) {
            for (std::string ifName : nw->getAllInterface()) {
                dg.destroySockets(ifName);
            }
        }
    }
}

int NativeNetdService::interfaceAddAddress(std::string ifName, std::string addrString, int prefixLength)
{
    return nmd::interface_controller::interfaceAddAddress(ifName, addrString, prefixLength);
}

int NativeNetdService::interfaceDelAddress(std::string ifName, std::string addrString, int prefixLength)
{
    return nmd::interface_controller::interfaceDelAddress(ifName, addrString, prefixLength);
}

int NativeNetdService::networkAddRoute(
    int netId, std::string interfaceName, std::string destination, std::string nextHop)
{
    return this->networkController_->addRoute(netId, interfaceName, destination, nextHop);
}

int NativeNetdService::networkRemoveRoute(
    int netId, std::string interfaceName, std::string destination, std::string nextHop)
{
    return this->networkController_->removeRoute(netId, interfaceName, destination, nextHop);
}

int NativeNetdService::networkGetDefault()
{
    return this->networkController_->getDefaultNetwork();
}

int NativeNetdService::networkSetDefault(int netId)
{
    return this->networkController_->setDefaultNetwork(netId);
}

int NativeNetdService::networkClearDefault()
{
    return this->networkController_->clearDefaultNetwork();
}

int NativeNetdService::networkSetPermissionForNetwork(int netId, NetworkPermission permission)
{
    return this->networkController_->setPermissionForNetwork(netId, permission);
}

std::vector<std::string> NativeNetdService::interfaceGetList()
{
    return interface_controller::getInterfaceNames();
}

nmd::interface_configuration_parcel NativeNetdService::interfaceGetConfig(std::string interfaceName)
{
    return interface_controller::getConfig(interfaceName.c_str());
}

void NativeNetdService::interfaceSetConfig(nmd::interface_configuration_parcel parcel)
{
    interface_controller::setConfig(parcel);
}

void NativeNetdService::interfaceClearAddrs(const std::string ifName)
{
    interface_controller::clearAddrs(ifName.c_str());
}

int NativeNetdService::interfaceGetMtu(std::string ifName)
{
    return interface_controller::getMtu(ifName.c_str());
}

int NativeNetdService::interfaceSetMtu(std::string ifName, int mtuValue)
{
    std::string mtu = std::to_string(mtuValue);
    return interface_controller::setMtu(ifName.c_str(), mtu.c_str());
}

void NativeNetdService::registerUnsolicitedEventListener(nmd::inetd_unsolicited_event_listener listener)
{
    nmd::netlink_manager::getReporter()->registerEventListener(listener);
}

nmd::mark_mask_parcel NativeNetdService::getFwmarkForNetwork(int netId)
{
    nmd::mark_mask_parcel mark;
    mark.mark = this->networkController_->getFwmarkForNetwork(netId);
    mark.mask = 0XFFFF;
    return mark;
}

void NativeNetdService::networkAddRouteParcel(int netId, route_info_parcel parcel)
{
    this->networkController_->addRoute(netId, parcel.ifName, parcel.destination, parcel.nextHop);
}

void NativeNetdService::networkRemoveRouteParcel(int netId, route_info_parcel parcel)
{
    this->networkController_->removeRoute(netId, parcel.ifName, parcel.destination, parcel.nextHop);
}

std::tuple<const char *, const char *> getPathComponents(int32_t ipversion, int which)
{
    const char *ipversionStr = nullptr;
    switch (ipversion) {
        case nmd::set_proc_sys_net::IPV4:
            ipversionStr = "ipv4";
            break;
        case nmd::set_proc_sys_net::IPV6:
            ipversionStr = "ipv6";
            break;
        default:
            return {"Bad Ip address", ""};
    }
    const char *whichStr = nullptr;
    switch (which) {
        case nmd::set_proc_sys_net::CONF:
            whichStr = "conf";
            break;
        case nmd::set_proc_sys_net::NEIGH:
            whichStr = "neigh";
            break;
        default:
            return {"", "Bad which"};
    }
    return {ipversionStr, whichStr};
}

int NativeNetdService::setProcSysNet(int32_t ipversion, int32_t which, const std::string ifname,
    const std::string parameter, const std::string value)
{
    const auto pathParts = getPathComponents(ipversion, which);
    if (std::string(std::get<0>(pathParts)) == std::string("Bad Ip address") ||
        std::string(std::get<1>(pathParts)) == std::string("Bad which")) {
        return -1;
    }
    return nmd::interface_controller::setParameter(
        std::get<0>(pathParts), std::get<1>(pathParts), ifname.c_str(), parameter.c_str(), value.c_str());
}

int NativeNetdService::getProcSysNet(
    int32_t ipversion, int32_t which, const std::string ifname, const std::string parameter, std::string *value)
{
    const auto pathParts = getPathComponents(ipversion, which);
    if (std::string(std::get<0>(pathParts)) == std::string("Bad Ip address") ||
        std::string(std::get<1>(pathParts)) == std::string("Bad which")) {
        return -1;
    }
    return nmd::interface_controller::getParameter(
        std::get<0>(pathParts), std::get<1>(pathParts), ifname.c_str(), parameter.c_str(), value);
}

long NativeNetdService::getCellularRxBytes()
{
    return nmd::traffic_controller::getCellularRxTraffic();
}

long NativeNetdService::getCellularTxBytes()
{
    return nmd::traffic_controller::getCellularTxTraffic();
}

long NativeNetdService::getAllRxBytes()
{
    return nmd::traffic_controller::getAllRxTraffic();
}

long NativeNetdService::getAllTxBytes()
{
    return nmd::traffic_controller::getAllTxTraffic();
}

long NativeNetdService::getUidTxBytes(int uid)
{
    return nmd::traffic_controller::getTxUidTraffic(uid);
}

long NativeNetdService::getUidRxBytes(int uid)
{
    return nmd::traffic_controller::getRxUidTraffic(uid);
}

nmd::traffic_stats_parcel NativeNetdService::interfaceGetStats(std::string ifName)
{
    return nmd::traffic_controller::getInterfaceTraffic(ifName);
}

long NativeNetdService::getIfaceRxBytes(std::string interfaceName)
{
    nmd::traffic_stats_parcel interfaceTraffic = nmd::traffic_controller::getInterfaceTraffic(interfaceName);
    return interfaceTraffic.rxBytes;
}

long NativeNetdService::getIfaceTxBytes(std::string interfaceName)
{
    nmd::traffic_stats_parcel interfaceTraffic = nmd::traffic_controller::getInterfaceTraffic(interfaceName);
    return interfaceTraffic.txBytes;
}

long NativeNetdService::getTetherRxBytes()
{
    return nmd::traffic_controller::getRxTetherTraffic();
}

long NativeNetdService::getTetherTxBytes()
{
    return nmd::traffic_controller::getTxTetherTraffic();
}

} // namespace nmd
} // namespace OHOS
