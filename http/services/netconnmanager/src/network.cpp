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

#include "network.h"
#include "net_id_manager.h"
#include "netmgr_log_wrapper.h"
#include "net_service.h"
#include "netd_controller.h"

namespace OHOS {
namespace NetManagerStandard {
Network::Network(sptr<NetProvider> &provider) : provider_(provider)
{
    netId_ = DelayedSingleton<NetIdManager>::GetInstance()->ReserveNetId();
}

bool Network::operator==(const Network &network) const
{
    return (provider_ != nullptr && network.provider_ != nullptr) && *provider_ == *(network.provider_) &&
        netId_ == network.netId_;
}

bool Network::NetworkConnect(const NetCapabilities &netCapability)
{
    NETMGR_LOGD("provider is connecting");
    if (isConnected_) {
        NETMGR_LOGD("provider is connected");
        return true;
    }

    // Call NetProvider class to activate the network
    NETMGR_LOGD("ProviderConnection processing");
    bool ret = provider_->ProviderConnection(netCapability);
    if (!ret) {
        NETMGR_LOGD("connect failed");
        return ret;
    }

    isConnecting_ = true;
    isConnected_ = true;
    return ret;
}

bool Network::NetworkDisconnect(const NetCapabilities &netCapability)
{
    NETMGR_LOGD("provider is disConnecting");
    if (!isConnecting_ && !isConnected_) {
        NETMGR_LOGD("no connecting or connected");
        return false;
    }

    // Call NetProvider class to deactivate the network
    NETMGR_LOGD("ProviderDisconnection processing");
    bool ret = provider_->ProviderDisconnection(netCapability);
    if (!ret) {
        NETMGR_LOGD("disconnect failed");
    }

    return ret;
}

bool Network::UpdateNetLinkInfo(const NetLinkInfo &netLinkInfo)
{
    NETMGR_LOGD("update net link information process");

    UpdateInterfaces(netLinkInfo);
    UpdateRoutes(netLinkInfo);
    UpdateDnses(netLinkInfo);
    updateMtu(netLinkInfo);

    netLinkInfo_ = netLinkInfo;
    return true;
}

int32_t Network::GetNetId() const
{
    return netId_;
}

void Network::SetIpAdress(const INetAddr &ipAdress)
{
    ipAddr_ = ipAdress;
}

void Network::SetDns(const INetAddr &dns)
{
    dns_ = dns;
}

void Network::SetRoute(const Route &route)
{
    route_ = route;
}

NetLinkInfo Network::GetNetLinkInfo() const
{
    return netLinkInfo_;
}

INetAddr Network::GetIpAdress() const
{
    return ipAddr_;
}

INetAddr Network::GetDns() const
{
    return dns_;
}

Route Network::GetRoute() const
{
    return route_;
}

sptr<NetProvider> Network::GetNetProvider() const
{
    return provider_;
}

bool Network::UpdateNetProviderInfo(const NetProviderInfo &netProviderInfo)
{
    NETMGR_LOGD("process strart");
    provider_->UpdateNetProviderInfo(netProviderInfo);

    if (!isPhyNetCreated_) {
        std::string permission;
        // Create a physical network
        DelayedSingleton<NetdController>::GetInstance()->NetworkCreatePhysical(netId_, 0);
        isPhyNetCreated_ = true;
    }
    return true;
}

bool Network::IsNetworkConnecting() const
{
    return isConnecting_;
}

void Network::SetConnected(bool connected)
{
    isConnected_ = connected;
}

void Network::SetConnecting(bool connecting)
{
    isConnecting_ = connecting;
}

void Network::UpdateInterfaces(const NetLinkInfo &netLinkInfo)
{
    if (netLinkInfo.ifaceName_ == netLinkInfo_.ifaceName_) {
        return;
    }

    // Call netd to add and remove interface
    if (!netLinkInfo.ifaceName_.empty()) {
        DelayedSingleton<NetdController>::GetInstance()->NetworkAddInterface(netId_, netLinkInfo.ifaceName_);
    }
    if (!netLinkInfo_.ifaceName_.empty()) {
        DelayedSingleton<NetdController>::GetInstance()->NetworkRemoveInterface(netId_, netLinkInfo_.ifaceName_);
    }
}

static bool NetAddrCmp(const INetAddr &netAddr1, const INetAddr &netAddr2)
{
    return netAddr1.type_ == netAddr2.type_ && netAddr1.family_ == netAddr2.family_ &&
        netAddr1.prefixlen_ == netAddr2.prefixlen_ && netAddr1.address_ == netAddr2.address_ &&
        netAddr1.netMask_ == netAddr2.netMask_ && netAddr1.hostName_ == netAddr2.hostName_;
}

void Network::UpdateRoutes(const NetLinkInfo &netLinkInfo)
{
    for (auto it = netLinkInfo.routeList_.begin(); it != netLinkInfo.routeList_.end(); ++it) {
        auto route = *it;
        if (std::find_if(netLinkInfo_.routeList_.begin(), netLinkInfo_.routeList_.end(), [route](auto another) {
                return another.iface_ == route.iface_ && NetAddrCmp(another.destination_, route.destination_) &&
                    NetAddrCmp(another.gateway_, route.gateway_);
            }) == netLinkInfo_.routeList_.end()) {
            DelayedSingleton<NetdController>::GetInstance()->NetworkAddRoute(
                netId_, route.iface_, route.destination_.address_, route.gateway_.address_);
        }
    }

    for (auto it = netLinkInfo_.routeList_.begin(); it != netLinkInfo_.routeList_.end(); ++it) {
        auto route = *it;
        if (std::find_if(netLinkInfo.routeList_.begin(), netLinkInfo.routeList_.end(), [route](auto another) {
                return another.iface_ == route.iface_ && NetAddrCmp(another.destination_, route.destination_) &&
                    NetAddrCmp(another.gateway_, route.gateway_);
            }) == netLinkInfo.routeList_.end()) {
            DelayedSingleton<NetdController>::GetInstance()->NetworkRemoveRoute(
                netId_, route.iface_, route.destination_.address_, route.gateway_.address_);
        }
    }
}

void Network::UpdateDnses(const NetLinkInfo &netLinkInfo)
{
    std::vector<std::string> addDnses;
    if (netLinkInfo.domain_ == netLinkInfo_.domain_ && netLinkInfo.dnsList_.size() == netLinkInfo_.dnsList_.size()) {
        for (auto it = netLinkInfo.dnsList_.begin(); it != netLinkInfo.dnsList_.end(); ++it) {
            auto dns = *it;
            if (std::find_if(netLinkInfo_.dnsList_.begin(), netLinkInfo_.dnsList_.end(),
                    [dns](auto another) { return NetAddrCmp(dns, another); }) != netLinkInfo_.dnsList_.end()) {
                addDnses.push_back(dns.address_);
            }
        }
    }

    std::vector<std::string> addDoamains;
    addDoamains.push_back(netLinkInfo.domain_);
    // Call netd to set dns
    DelayedSingleton<NetdController>::GetInstance()->SetResolverConfig(netId_, 0, 0, addDnses, addDoamains);
}

void Network::updateMtu(const NetLinkInfo &netLinkInfo)
{
    if (netLinkInfo.mtu_ == netLinkInfo_.mtu_) {
        return;
    }

    DelayedSingleton<NetdController>::GetInstance()->InterfaceSetMtu(netLinkInfo.ifaceName_, netLinkInfo.mtu_);
}
} // namespace NetManagerStandard
} // namespace OHOS
