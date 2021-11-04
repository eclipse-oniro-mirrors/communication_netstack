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
#include "net_provider.h"
#include <atomic>
#include "netmgr_log_wrapper.h"
#include "network.h"
#include "net_service.h"
#include "net_controller_factory.h"
#include "telephony_controller.h"

namespace OHOS {
namespace NetManagerStandard {
static std::atomic<uint32_t> g_nextNetProviderId = 0x03EB;
static const int32_t REG_OK = 1;

NetProvider::NetProvider(NetworkType netProviderType, const std::string &netProviderIdent)
{
    sptr<INetController> netController =
        DelayedSingleton<NetControllerFactory>::GetInstance().get()->MakeNetController(netProviderType);
    if (netController != nullptr) {
        netController_ = netController;
    }
    netProviderType_ = netProviderType;
    netProviderIdent_ = netProviderIdent;
    providerId_ = g_nextNetProviderId++;
}

bool NetProvider::operator==(const NetProvider &netProvider) const
{
    return providerId_ == netProvider.providerId_ && netProviderType_ == netProvider.netProviderType_ &&
        netProviderIdent_ == netProvider.netProviderIdent_;
}

NetworkType NetProvider::GetNetProviderType() const
{
    return netProviderType_;
}

std::string NetProvider::GetNetProviderIdent() const
{
    return netProviderIdent_;
}

bool NetProvider::ProviderConnection(NetCapabilities netCapabilities)
{
    NETMGR_LOGD("param ident[%{public}s] netCapabilities[%{public}d]", netProviderIdent_.c_str(),
        static_cast<int32_t>(netCapabilities));
    if (netController_ == nullptr) {
        NETMGR_LOGE("netController_ is nullptr");
        return false;
    }
    NETMGR_LOGD("execute RequestNetwork");
    int32_t errCode = netController_->RequestNetwork(netProviderIdent_, netCapabilities);
    NETMGR_LOGD("RequestNetwork errCode[%{public}d]", errCode);
    if (errCode == REG_OK) {
        connected_ = true;
        return true;
    }

    return false;
}

bool NetProvider::ProviderDisconnection(NetCapabilities netCapabilities)
{
    NETMGR_LOGD("param ident_[%{public}s] netCapabilities[%{public}d]", netProviderIdent_.c_str(),
        static_cast<int32_t>(netCapabilities));
    if (netController_ == nullptr) {
        NETMGR_LOGE("netController_ is nullptr");
        return false;
    }
    NETMGR_LOGD("execute ReleaseNetwork");
    int32_t errCode = netController_->ReleaseNetwork(netProviderIdent_, netCapabilities);
    NETMGR_LOGD("ReleaseNetwork errCode[%{public}d]", errCode);
    if (errCode == REG_OK) {
        connected_ = false;
        return true;
    }
    return false;
}

void NetProvider::UpdateNetProviderInfo(const NetProviderInfo &netProviderInfo)
{
    isAvailable_ = netProviderInfo.isAvailable_;
    isRoaming_ = netProviderInfo.isRoaming_;
    strength_ = netProviderInfo.strength_;
    frequency_ = netProviderInfo.frequency_;
    NETMGR_LOGD(
        "isAvailable_[%{public}d] isRoaming_[%{public}d] strength_[%{public}d] "
        "frequency_[%{public}d]",
        isAvailable_, isRoaming_, strength_, frequency_);
}

uint32_t NetProvider::GetProviderId() const
{
    return providerId_;
}

bool NetProvider::GetConnected() const
{
    return connected_;
}

bool NetProvider::GetAvailable() const
{
    return isAvailable_;
}

bool NetProvider::GetRoaming() const
{
    return isRoaming_;
}

bool NetProvider::GetStrength() const
{
    return strength_;
}

bool NetProvider::GetFrequency() const
{
    return frequency_;
}
} // namespace NetManagerStandard
} // namespace OHOS