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

#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <memory>

#include "net_provider.h"
#include "net_service.h"
#include "inet_addr.h"
#include "route.h"
#include "net_link_info.h"
#include "net_specifier.h"

namespace OHOS {
namespace NetManagerStandard {
class Network : public virtual RefBase {
public:
    Network(sptr<NetProvider> &provider);
    ~Network() = default;
    bool operator==(const Network &network) const;

    bool NetworkConnect(const NetCapabilities &netCapability);
    bool NetworkDisconnect(const NetCapabilities &netCapability);
    bool UpdateNetLinkInfo(const NetLinkInfo &netLinkInfo);
    void SetIpAdress(const INetAddr &ipAdress);
    void SetDns(const INetAddr &dns);
    void SetRoute(const Route &route);
    INetAddr GetIpAdress() const;
    INetAddr GetDns() const;
    Route GetRoute() const;
    NetLinkInfo GetNetLinkInfo() const;
    int32_t GetNetId() const;
    sptr<NetProvider> GetNetProvider() const;
    bool UpdateNetProviderInfo(const NetProviderInfo &netProviderInfo);
    bool IsNetworkConnecting() const;
    void SetConnected(bool connected);
    void SetConnecting(bool connecting);
    void UpdateInterfaces(const NetLinkInfo &netLinkInfo);
    void UpdateRoutes(const NetLinkInfo &netLinkInfo);
    void UpdateDnses(const NetLinkInfo &netLinkInfo);
    void updateMtu(const NetLinkInfo &netLinkInfo);

private:
    NetLinkInfo netLinkInfo_;
    INetAddr ipAddr_;
    INetAddr dns_;
    Route route_;

    // netd network param
    bool isPhyNetCreated_ = false;
    bool isConnecting_ = false;
    bool isConnected_ = false;

    sptr<NetProvider> provider_;
    int32_t netId_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NETWORK_H
