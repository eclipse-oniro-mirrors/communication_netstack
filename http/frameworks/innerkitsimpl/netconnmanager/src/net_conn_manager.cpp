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

#include "net_conn_manager.h"

#include "system_ability_definition.h"
#include "iservice_registry.h"

#include "netmgr_log_wrapper.h"

namespace OHOS {
namespace NetManagerStandard {
NetConnManager::NetConnManager() : NetConnService_(nullptr), deathRecipient_(nullptr) {}

NetConnManager::~NetConnManager() {}

int32_t NetConnManager::SystemReady()
{
    sptr<INetConnService> proxy = getProxy();
    if (proxy == nullptr) {
        NETMGR_LOGE("proxy is nullptr");
        return IPC_PROXY_ERR;
    }

    return proxy->SystemReady();
}

int32_t NetConnManager::RegisterNetProvider(uint32_t netType, const std::string &ident, uint64_t netCapabilities)
{
    sptr<INetConnService> proxy = getProxy();
    if (proxy == nullptr) {
        NETMGR_LOGE("proxy is nullptr");
        return IPC_PROXY_ERR;
    }

    return proxy->RegisterNetProvider(netType, ident, netCapabilities);
}

int32_t NetConnManager::UnregisterNetProvider(uint32_t providerId)
{
    sptr<INetConnService> proxy = getProxy();
    if (proxy == nullptr) {
        NETMGR_LOGE("proxy is nullptr");
        return IPC_PROXY_ERR;
    }

    return proxy->UnregisterNetProvider(providerId);
}

int32_t NetConnManager::UpdateNetProviderInfo(uint32_t providerId, const sptr<NetProviderInfo> &netProviderInfo)
{
    sptr<INetConnService> proxy = getProxy();
    if (proxy == nullptr) {
        NETMGR_LOGE("proxy is nullptr");
        return IPC_PROXY_ERR;
    }

    return proxy->UpdateNetProviderInfo(providerId, netProviderInfo);
}

int32_t NetConnManager::UpdateNetCapabilities(uint32_t providerId, uint64_t netCapabilities)
{
    sptr<INetConnService> proxy = getProxy();
    if (proxy == nullptr) {
        NETMGR_LOGE("proxy is nullptr");
        return IPC_PROXY_ERR;
    }

    return proxy->UpdateNetCapabilities(providerId, netCapabilities);
}

int32_t NetConnManager::UpdateNetLinkInfo(uint32_t providerId, const sptr<NetLinkInfo> &netLinkInfo)
{
    sptr<INetConnService> proxy = getProxy();
    if (proxy == nullptr) {
        NETMGR_LOGE("proxy is nullptr");
        return IPC_PROXY_ERR;
    }

    return proxy->UpdateNetLinkInfo(providerId, netLinkInfo);
}

sptr<INetConnService> NetConnManager::getProxy()
{
    std::lock_guard lock(mutex_);

    if (NetConnService_) {
        NETMGR_LOGD("get proxy is ok");
        return NetConnService_;
    }

    NETMGR_LOGD("execute GetSystemAbilityManager");
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        NETMGR_LOGE("NetConnManager::getProxy(), get SystemAbilityManager failed");
        return nullptr;
    }

    sptr<IRemoteObject> remote = sam->CheckSystemAbility(COMMUNICATION_NET_MANAGER_SYS_ABILITY_ID);
    if (remote == nullptr) {
        NETMGR_LOGE("get Remote service failed");
        return nullptr;
    }

    deathRecipient_ = (std::make_unique<NetConnDeathRecipient>(*this)).release();
    if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
        NETMGR_LOGE("add death recipient failed");
        return nullptr;
    }

    NetConnService_ = iface_cast<INetConnService>(remote);
    if (NetConnService_ == nullptr) {
        NETMGR_LOGE("get Remote service proxy failed");
        return nullptr;
    }

    return NetConnService_;
}

void NetConnManager::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    NETMGR_LOGD("on remote died");
    if (remote == nullptr) {
        NETMGR_LOGE("remote object is nullptr");
        return;
    }

    std::lock_guard lock(mutex_);
    if (NetConnService_ == nullptr) {
        NETMGR_LOGE("NetConnService_ is nullptr");
        return;
    }

    sptr<IRemoteObject> local = NetConnService_->AsObject();
    if (local != remote.promote()) {
        NETMGR_LOGE("proxy and stub is not same remote object");
        return;
    }

    local->RemoveDeathRecipient(deathRecipient_);
    NetConnService_ = nullptr;
}
} // namespace NetManagerStandard
} // namespace OHOS
