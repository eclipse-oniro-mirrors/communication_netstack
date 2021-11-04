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

#include "net_conn_service.h"
#include <memory>
#include <iostream>
#include <ctime>
#include <thread>
#include <unistd.h>
#include "string_ex.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"
#include "net_conn_types.h"
#include "netmgr_log_wrapper.h"
#include "net_service.h"
#include "net_provider.h"
#include "netd_controller.h"

namespace OHOS {
namespace NetManagerStandard {
const bool REGISTER_LOCAL_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<NetConnService>::GetInstance().get());

NetConnService::NetConnService()
    : SystemAbility(COMMUNICATION_NET_MANAGER_SYS_ABILITY_ID, true), registerToService_(false),
      state_(STATE_STOPPED)
{}

NetConnService::~NetConnService() {}

void NetConnService::OnStart()
{
    if (state_ == STATE_RUNNING) {
        NETMGR_LOGD("the state is already running");
        return;
    }
    if (!Init()) {
        NETMGR_LOGE("init failed");
        return;
    }
    state_ = STATE_RUNNING;
}

void NetConnService::OnStop()
{
    state_ = STATE_STOPPED;
    registerToService_ = false;
}

int32_t NetConnService::SystemReady()
{
    NETMGR_LOGD("System ready.");
    return 0;
}

bool NetConnService::Init()
{
    if (!REGISTER_LOCAL_RESULT) {
        NETMGR_LOGE("Register to local sa manager failed");
        registerToService_ = false;
        return false;
    }
    if (!registerToService_) {
        if (!Publish(DelayedSingleton<NetConnService>::GetInstance().get())) {
            NETMGR_LOGE("Register to sa manager failed");
            return false;
        }
        registerToService_ = true;
    }

    DelayedSingleton<NetdController>::GetInstance()->Init();
    return true;
}

int32_t NetConnService::RegisterNetProvider(uint32_t netType, const std::string &ident, uint32_t netCapabilities)
{
    NETMGR_LOGD("register provider, netType[%{public}d] ident[%{public}s] netCapabilities[%{public}d]", netType,
        ident.c_str(), netCapabilities);
    // According to netType, ident, get the provider from the list and save the providerId in the list
    // if (netType >= NET_TYPE_MAX) {
    //    NETMGR_LOGE("netType parameter invalid");
    //    return ERR_INVALID_NETORK_TYPE;
    //}

    // sptr<NetProvider> provider = GetNetProviderFromList(netType, ident);
    // if (provider != nullptr) {
    //    NETMGR_LOGD("provider already exists.");
    //    return provider->GetProviderId();
    //}

    // If there is no provider in the list, create a provider
    // provider = (std::make_unique<NetProvider>(static_cast<NetworkType>(netType), ident)).release();

    // if (provider == nullptr) {
    //    NETMGR_LOGE("provider is nullptr");
    //    return ERR_NO_PROVIDER;
    //}

    // create network
    // sptr<Network> network = (std::make_unique<Network>(provider)).release();
    // if (network == nullptr) {
    //    NETMGR_LOGE("network is nullptr");
    //    return ERR_NO_NETWORK;
    //}

    // create service by netCapabilities
    // NetworkType type = static_cast<NetworkType>(netType);
    // if (netCapabilities & NET_CAPABILITIES_INTERNET) {
    //    auto service = std::make_unique<NetService>(ident, type, NET_CAPABILITIES_INTERNET, network).release();
    //    if (service != nullptr) {
    //        netServices_.push_back(service);
    //        defaultNetService_ = service;
    //    }
    //}

    // if (netCapabilities & NET_CAPABILITIES_MMS) {
    //    auto service = std::make_unique<NetService>(ident, type, NET_CAPABILITIES_MMS, network).release();
    //    if (service != nullptr) {
    //        netServices_.push_back(service);
    //    }
    //}

    // save provider, network to list
    // netProviders_.push_back(provider);
    // networks_.push_back(network);
    // NETMGR_LOGD("netProviders_ size[%{public}d] networks_ size[%{public}d] netServices_ size[%{public}d]",
    //    netProviders_.size(), networks_.size(), netServices_.size());

    // if (defaultNetService_ != nullptr) {
    //    NETMGR_LOGD("service is connecting...");
    //    defaultNetService_->ServiceConnect();
    //}
    NETMGR_LOGD("dnsresolvService setResolverConfig begin");
    const OHOS::nmd::dnsresolver_params param = {
        OHOS::nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};
    DelayedSingleton<NetdController>::GetInstance()->SetResolverConfig(
        param.netId, param.baseTimeoutMsec, param.retryCount, param.servers, param.domains);

    NETMGR_LOGD("dnsresolvService setResolverConfig end");

    std::string ifName = "";
    std::string addrString = "";
    int32_t prefixLength = 0;
    DelayedSingleton<NetdController>::GetInstance()->InterfaceDelAddress(ifName, addrString, prefixLength);
    // return provider->GetProviderId();
    return 0;
}

int32_t NetConnService::UnregisterNetProvider(uint32_t providerId)
{
    NETMGR_LOGD("UnregisterNetProvider providerId[%{public}d]", providerId);
    // Remove provider from the list based on providerId
    // sptr<NetProvider> provider = GetNetProviderFromListById(providerId);
    // if (provider == nullptr) {
    //    NETMGR_LOGE("provider doesn't exist.");
    //    return ERR_NO_PROVIDER;
    //}

    // sptr<Network> network = GetNetworkFromListByProviderId(providerId);
    // if (network == nullptr) {
    //    NETMGR_LOGE("GetNetworkFromListByProviderId get error, network is nullptr");
    //    DeleteProviderFromListById(providerId);
    //    return ERR_NO_NETWORK;
    //}

    // DeleteServiceFromListByNet(*network);
    // DeleteNetworkFromListByProviderId(providerId);
    // DeleteProviderFromListById(providerId);
    // NETMGR_LOGD("netProviders_ size[%{public}d], networks_ size[%{public}d], netServices_ size[%{public}d]",
    //            netProviders_.size(), networks_.size(), netServices_.size());

    std::string ifName = "";
    std::string addrString = "";
    int32_t prefixLength = 0;
    DelayedSingleton<NetdController>::GetInstance()->InterfaceAddAddress(ifName, addrString, prefixLength);
    return ERR_NONE;
}

int32_t NetConnService::UpdateNetProviderInfo(uint32_t providerId, const sptr<NetProviderInfo> &netProviderInfo)
{
    NETMGR_LOGD("Update provider info: providerId[%{public}d]", providerId);
    if (netProviderInfo == nullptr) {
        NETMGR_LOGE("netProviderInfo is nullptr");
        return ERR_INVALID_PARAMS;
    }

    NETMGR_LOGD("Update provider info: netProviderInfo[%{public}s]", netProviderInfo->ToString("").c_str());

    // According to providerId, get the provider from the list
    sptr<NetProvider> provider = GetNetProviderFromListById(providerId);
    if (provider == nullptr) {
        NETMGR_LOGE("provider is nullptr");
        return ERR_NO_PROVIDER;
    }

    // Call NetProvider class to update network connection status information
    sptr<Network> network = GetNetworkFromListByProviderId(provider->GetProviderId());
    if (network == nullptr) {
        NETMGR_LOGE("network is nullptr");
        return ERR_NO_NETWORK;
    }
    network->UpdateNetProviderInfo(*netProviderInfo);

    return ERR_NONE;
}

int32_t NetConnService::UpdateNetCapabilities(uint32_t providerId, uint32_t netCapabilities)
{
    NETMGR_LOGD("providerId[%{public}d] netCapabilities[%{public}d]", providerId, netCapabilities);
    // According to providerId, get the provider from the list
    sptr<NetProvider> provider = GetNetProviderFromListById(providerId);
    if (provider == nullptr) {
        NETMGR_LOGE("provider is nullptr");
        return ERR_NO_PROVIDER;
    }

    // According to netId, get network from the list
    sptr<Network> network = GetNetworkFromListByProviderId(provider->GetProviderId());
    if (network == nullptr) {
        NETMGR_LOGE("network is nullptr");
        return ERR_NO_NETWORK;
    }
    auto type = provider->GetNetProviderType();
    auto ident = provider->GetNetProviderIdent();
    // Create or delete network services based on the netCapabilities
    if (netCapabilities & NET_CAPABILITIES_INTERNET) {
        if (!IsServiceInList(network->GetNetId(), NET_CAPABILITIES_INTERNET)) {
            auto service = std::make_unique<NetService>(ident, type, NET_CAPABILITIES_INTERNET, network).release();
            netServices_.push_back(service);
        }
    } else {
        if (IsServiceInList(network->GetNetId(), NET_CAPABILITIES_INTERNET)) {
            DeleteServiceFromListByCap(network->GetNetId(), NET_CAPABILITIES_INTERNET);
        }
    }

    if (netCapabilities & NET_CAPABILITIES_MMS) {
        if (!IsServiceInList(network->GetNetId(), NET_CAPABILITIES_MMS)) {
            auto service = std::make_unique<NetService>(ident, type, NET_CAPABILITIES_MMS, network).release();
            netServices_.push_back(service);
        }
    } else {
        if (IsServiceInList(network->GetNetId(), NET_CAPABILITIES_MMS)) {
            DeleteServiceFromListByCap(network->GetNetId(), NET_CAPABILITIES_MMS);
        }
    }
    NETMGR_LOGD("netProviders_ size[%{public}d], networks_ size[%{public}d], netServices_ size[%{public}d]",
        netProviders_.size(), networks_.size(), netServices_.size());
    return ERR_NONE;
}

int32_t NetConnService::UpdateNetLinkInfo(uint32_t providerId, const sptr<NetLinkInfo> &netLinkInfo)
{
    NETMGR_LOGD("providerId[%{public}d]", providerId);
    if (netLinkInfo == nullptr) {
        NETMGR_LOGE("netLinkInfo is nullptr");
        return ERR_INVALID_PARAMS;
    }

    NETMGR_LOGD("Update netlink info: netLinkInfo[%{public}s]", netLinkInfo->ToString("").c_str());
    // According to providerId, get the provider from the list
    sptr<NetProvider> provider = GetNetProviderFromListById(providerId);
    if (provider == nullptr) {
        NETMGR_LOGE("provider is nullptr");
        return ERR_NO_PROVIDER;
    }
    // According to provider id, get network from the list
    sptr<Network> network = GetNetworkFromListByProviderId(provider->GetProviderId());
    if (network == nullptr) {
        NETMGR_LOGE("network is nullptr");
        return ERR_NO_NETWORK;
    }
    // Call Network class to update network link attribute information
    network->UpdateNetLinkInfo(*netLinkInfo);
    return ERR_NONE;
}

sptr<NetProvider> NetConnService::GetNetProviderFromList(uint32_t netType, const std::string &ident)
{
    for (auto it = netProviders_.begin(); it != netProviders_.end(); ++it) {
        auto providerType = (*it)->GetNetProviderType();
        auto providerIdent = (*it)->GetNetProviderIdent();
        if ((netType == providerType) && (ident.compare(providerIdent) == 0)) {
            return *it;
        }
    }

    NETMGR_LOGE("net provider is nullptr");
    return nullptr;
}

sptr<NetProvider> NetConnService::GetNetProviderFromListById(uint32_t providerId)
{
    for (auto it = netProviders_.begin(); it != netProviders_.end(); ++it) {
        auto id = (*it)->GetProviderId();
        if (providerId == id) {
            return *it;
        }
    }

    NETMGR_LOGE("net provider is nullptr");
    return nullptr;
}

void NetConnService::DeleteProviderFromListById(uint32_t providerId)
{
    for (auto it = netProviders_.begin(); it != netProviders_.end(); ++it) {
        auto id = (*it)->GetProviderId();
        if (providerId == id) {
            netProviders_.erase(it);
            return;
        }
    }
}

void NetConnService::DeleteNetworkFromListByProviderId(uint32_t providerId)
{
    for (auto it = networks_.begin(); it != networks_.end(); ++it) {
        sptr<NetProvider> netProvider = (*it)->GetNetProvider();
        if ((netProvider != nullptr) && (netProvider->GetProviderId() == providerId)) {
            networks_.erase(it);
            return;
        }
    }
}

sptr<Network> NetConnService::GetNetworkFromListByProviderId(uint32_t providerId)
{
    for (auto it = networks_.begin(); it != networks_.end(); ++it) {
        sptr<NetProvider> netProvider = (*it)->GetNetProvider();
        if ((netProvider != nullptr) && (netProvider->GetProviderId() == providerId)) {
            return *it;
        }
    }

    NETMGR_LOGE("network is nullptr");
    return nullptr;
}

void NetConnService::DeleteServiceFromListByNet(const Network &network)
{
    sptr<Network> currNetwork = nullptr;
    for (auto it = netServices_.begin(); it != netServices_.end();) {
        currNetwork = (*it)->GetNetwork();
        if (currNetwork != nullptr && *currNetwork == network) {
            netServices_.erase(it++);
        } else {
            ++it;
        }
    }
}

bool NetConnService::DeleteServiceFromListByCap(int32_t netId, const NetCapabilities &netCapability)
{
    sptr<Network> network = nullptr;
    for (auto it = netServices_.begin(); it != netServices_.end(); ++it) {
        network = (*it)->GetNetwork();
        if (network == nullptr) {
            continue;
        }
        if ((network->GetNetId() == netId) && (netCapability == (*it)->GetNetCapability())) {
            netServices_.erase(it);
            return true;
        }
    }

    return false;
}

bool NetConnService::IsServiceInList(int32_t netId, const NetCapabilities &netCapability) const
{
    sptr<Network> network = nullptr;
    for (auto it = netServices_.begin(); it != netServices_.end(); ++it) {
        network = (*it)->GetNetwork();
        if (network == nullptr) {
            continue;
        }
        if ((network->GetNetId() == netId) && (netCapability == (*it)->GetNetCapability())) {
            return true;
        }
    }

    return false;
}
} // namespace NetManagerStandard
} // namespace OHOS
