/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "netd_controller.h"
#include <unistd.h>
#include <signal.h>
#ifdef NATIVE_NETD_FEATURE

#include "net_conn_types.h"
#endif

namespace OHOS {
namespace NetManagerStandard {
NetdController::NetdController() {}

NetdController::~NetdController() {}

void ExitHandler(int32_t signum)
{
    exit(1);
}

void NetdController::Init()
{
    NETMGR_LOGD("netd Init");

    signal(SIGTERM, ExitHandler);
    signal(SIGABRT, ExitHandler);
    netdService_ = std::make_unique<nmd::NativeNetdService>();
    netdService_->init();

    int32_t pid = getpid();
    manager_ = std::make_unique<nmd::netlink_manager>(pid);
    std::thread nlManager([&] { manager_->start(); });

    fwmarkServer_ = std::make_unique<nmd::fwmark_server>();
    std::thread fwserve([&] { fwmarkServer_->start(); });

    dnsResolvService_ = std::make_unique<nmd::dnsresolv_service>();
    std::thread dnsresolvServe([&] { dnsResolvService_->start(); });

    nlManager.detach();
    fwserve.detach();
    dnsresolvServe.detach();
#ifdef NATIVE_NETD_FEATURE
#else
    return;
#endif
}

int32_t NetdController::NetworkCreatePhysical(int32_t netId, int32_t permission)
{
    NETMGR_LOGD("Create Physical network: netId[%{public}d], permission[%{public}d]", netId, permission);
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->networkCreatePhysical(netId, permission);
#else
    return 0;
#endif
}

int32_t NetdController::NetworkDestroy(int32_t netId)
{
    NETMGR_LOGD("Destroy network: netId[%{public}d]", netId);
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->networkDestroy(netId);
#else
    return 0;
#endif
}

int32_t NetdController::NetworkAddInterface(int32_t netId, const std::string &iface)
{
    NETMGR_LOGD("Add network interface: netId[%{public}d], iface[%{public}s]", netId, iface.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->networkAddInterface(netId, iface);
#else
    return 0;
#endif
}

int32_t NetdController::NetworkRemoveInterface(int32_t netId, const std::string &iface)
{
    NETMGR_LOGD("Remove network interface: netId[%{public}d], iface[%{public}s]", netId, iface.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->networkRemoveInterface(netId, iface);
#else
    return 0;
#endif
}

int32_t NetdController::NetworkAddRoute(
    int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop)
{
    NETMGR_LOGD("Add Route: netId[%{public}d], ifName[%{public}s], destination[%{public}s], nextHop[%{public}s]",
        netId, ifName.c_str(), destination.c_str(), nextHop.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->networkAddRoute(netId, ifName, destination, nextHop);
#else
    return 0;
#endif
}

int32_t NetdController::NetworkRemoveRoute(
    int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop)
{
    NETMGR_LOGD(
        "Remove Route: netId[%{public}d], ifName[%{public}s], destination[%{public}s], nextHop[%{public}s]", netId,
        ifName.c_str(), destination.c_str(), nextHop.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->networkRemoveRoute(netId, ifName, destination, nextHop);
#else
    return 0;
#endif
}

void NetdController::SetInterfaceDown(const std::string &iface)
{
    NETMGR_LOGD("Set interface down: iface[%{public}s]", iface.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return;
    }
    auto interfaceConfig = netdService_->interfaceGetConfig(iface);
    auto fit = std::find(interfaceConfig.flags.begin(), interfaceConfig.flags.end(), "up");
    if (fit != interfaceConfig.flags.end()) {
        interfaceConfig.flags.erase(fit);
    }
    interfaceConfig.flags.push_back("down");
    netdService_->interfaceSetConfig(interfaceConfig);
#else
    return;
#endif
}

void NetdController::SetInterfaceUp(const std::string &iface)
{
    NETMGR_LOGD("Set interface up: iface[%{public}s]", iface.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return;
    }
    auto interfaceConfig = netdService_->interfaceGetConfig(iface);
    auto fit = std::find(interfaceConfig.flags.begin(), interfaceConfig.flags.end(), "down");
    if (fit != interfaceConfig.flags.end()) {
        interfaceConfig.flags.erase(fit);
    }
    interfaceConfig.flags.push_back("up");
    netdService_->interfaceSetConfig(interfaceConfig);
#else
    return;
#endif
}

void NetdController::InterfaceClearAddrs(const std::string &ifName)
{
    NETMGR_LOGD("Clear addrs: ifName[%{public}s]", ifName.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return;
    }
    return netdService_->interfaceClearAddrs(ifName);
#else
    return;
#endif
}

int32_t NetdController::InterfaceGetMtu(const std::string &ifName)
{
    NETMGR_LOGD("Get mtu: ifName[%{public}s]", ifName.c_str());
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->interfaceGetMtu(ifName);
#else
    return 0;
#endif
}

int32_t NetdController::InterfaceSetMtu(const std::string &ifName, int32_t mtu)
{
    NETMGR_LOGD("Set mtu: ifName[%{public}s], mtu[%{public}d]", ifName.c_str(), mtu);
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->interfaceSetMtu(ifName, mtu);
#else
    int ret = netdService_->interfaceDelAddress("eth1", "192.168.0.12", 32);
    if (ret != 0) {
        NETNATIVE_LOGE("interfaceDelAddress error: %{public}s", gai_strerror(ret));
        return 0;
    }
    ret = netdService_->networkRemoveInterface(1, "eth1");
    if (ret != 0) {
        NETNATIVE_LOGE("networkAddInterface error: %{public}s", gai_strerror(ret));
        return 0;
    }
    nmd::mark_mask_parcel testFwmark = netdService_->getFwmarkForNetwork(12);
    // EXPECT_EQ(12, testFwmark.mark);
    // EXPECT_EQ(65535, testFwmark.mask);
    NETNATIVE_LOGE("getFwmarkForNetwork testFwmark: %{public}d", testFwmark.mark);
    return 0;
#endif
}

int32_t NetdController::InterfaceAddAddress(
    const std::string &ifName, const std::string &addrString, int32_t prefixLength)
{
    NETMGR_LOGD("Add address: ifName[%{public}s]，addrString[%{public}s], prefixLength[%{public}d]",
        ifName.c_str(), addrString.c_str(), prefixLength);
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->interfaceAddAddress(ifName, addrString, prefixLength);
#else
    int ret = netdService_->networkCreatePhysical(1, OHOS::nmd::NetworkPermission::PERMISSION_NONE);
    if (ret != 0) {
        NETNATIVE_LOGE("networkCreatePhysical error: %{public}s", gai_strerror(ret));
        return 0;
    }
    ret = netdService_->networkAddInterface(1, "eth1");
    if (ret != 0) {
        NETNATIVE_LOGE("networkAddInterface error: %{public}s", gai_strerror(ret));
        return 0;
    }
    ret = netdService_->interfaceAddAddress("eth1", "192.168.0.12", 32);
    if (ret != 0) {
        NETNATIVE_LOGE("interfaceAddAddress error: %{public}s", gai_strerror(ret));
        return 0;
    }
    return 0;
#endif
}

int32_t NetdController::InterfaceDelAddress(
    const std::string &ifName, const std::string &addrString, int32_t prefixLength)
{
    NETMGR_LOGD("Delete address: ifName[%{public}s]，addrString[%{public}s], prefixLength[%{public}d]",
        ifName.c_str(), addrString.c_str(), prefixLength);
#ifdef NATIVE_NETD_FEATURE
    if (netdService_ == nullptr) {
        NETMGR_LOGE("netdService_ is null");
        return ERR_SERVICE_UPDATE_NET_LINK_INFO_FAIL;
    }
    return netdService_->interfaceDelAddress(ifName, addrString, prefixLength);
#else
    nmd::dnsresolver_params params;
    params.netId = 0;
    params.baseTimeoutMsec = 0;
    params.retryCount = 1;
    nmd::dns_res_params res;
    dnsResolvService_->getResolverInfo(params.netId, params.servers, params.domains, res);
    NETMGR_LOGD("Get resolver config: ");
    for (auto itr = params.servers.begin(); itr != params.servers.end(); itr++) {
        NETMGR_LOGI("dns server is %{public}s", itr->c_str());
    }
    for (auto itr = params.domains.begin(); itr != params.domains.end(); itr++) {
        NETMGR_LOGI("dns domains is %{public}s", itr->c_str());
    }
    NETMGR_LOGI("baseTimeoutMsec is %{public}d and retryCount is %{public}d", res.baseTimeoutMsec, res.retryCount);

    NETMGR_LOGI("getaddrinfo:: begin");
    struct addrinfo *res1;
    struct addrinfo hints;
    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    std::string hostName = "www.baidu.com";
    res1 = nullptr;
    NETMGR_LOGI("getaddrinfo error: %{public}s", hostName.c_str());
    return 0;
#endif
}

int32_t NetdController::SetResolverConfig(uint16_t netId, uint16_t baseTimeoutMsec, uint8_t retryCount,
    const std::vector<std::string> &servers, const std::vector<std::string> &domains)
{
    NETMGR_LOGD("Set resolver config: netId[%{public}d]", netId);
    //#ifdef NATIVE_NETD_FEATURE
    if (dnsResolvService_ == nullptr) {
        NETMGR_LOGE("dnsResolvService_ is null");
        return 0;
    }
    dnsResolvService_->createNetworkCache(netId);
    const nmd::dnsresolver_params params = {netId, baseTimeoutMsec, retryCount, servers, domains};
    return dnsResolvService_->setResolverConfig(params);
    //#else
    //    return 0;
    //#endif
}
} // namespace NetManagerStandard
} // namespace OHOS