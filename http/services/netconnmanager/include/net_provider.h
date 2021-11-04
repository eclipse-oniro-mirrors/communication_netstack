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

#ifndef NET_PROVIDER_H
#define NET_PROVIDER_H

#include <string>

#include "net_specifier.h"
#include "i_net_controller.h"

namespace OHOS {
namespace NetManagerStandard {
class Network;
class NetService;
class NetProvider : public virtual RefBase {
public:
    NetProvider();
    NetProvider(NetworkType netProviderType, const std::string &netProviderIdent);
    ~NetProvider() = default;
    bool operator==(const NetProvider &netProvider) const;
    NetworkType GetNetProviderType() const;
    std::string GetNetProviderIdent() const;
    bool ProviderConnection(NetCapabilities netCapabilities);
    bool ProviderDisconnection(NetCapabilities netCapabilities);
    void UpdateNetProviderInfo(const NetProviderInfo &netProviderInfo);
    uint32_t GetProviderId() const;
    bool GetConnected() const;
    bool GetAvailable() const;
    bool GetRoaming() const;
    bool GetStrength() const;
    bool GetFrequency() const;

private:
    sptr<INetController> netController_;
    NetworkType netProviderType_;
    std::string netProviderIdent_;
    uint32_t providerId_ = 0;
    uint16_t frequency_ = 0x00;
    uint8_t strength_ = 0x00;
    bool connected_ = false;
    bool isAvailable_ = false; // whether the network is available
    bool isRoaming_ = false;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_PROVIDER_H
