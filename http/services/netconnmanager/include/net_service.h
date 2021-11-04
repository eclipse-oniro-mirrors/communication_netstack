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

#ifndef NET_SERVICE_H
#define NET_SERVICE_H

#include <string>

#include "network.h"
#include "net_link_info.h"

namespace OHOS {
namespace NetManagerStandard {
enum ServiceState {
    SERVICE_STATE_UNKNOWN = 0,
    SERVICE_STATE_IDLE = 1,
    SERVICE_STATE_CONNECTING = 2,
    SERVICE_STATE_READY = 3,
    SERVICE_STATE_CONNECTED = 4,
    SERVICE_STATE_DISCONNECTING = 5,
    SERVICE_STATE_DISCONNECTED = 6,
    SERVICE_STATE_FAILURE = 7,
};

class NetService : public virtual RefBase {
public:
    NetService(
        const std::string &ident, NetworkType networkType, NetCapabilities netCapability, sptr<Network> &network);
    ~NetService() = default;
    void SetIdent(const std::string &ident);
    void SetNetworkType(const NetworkType &networkType);
    void SetNetCapability(const NetCapabilities &netCapability);
    void SetServiceState(const ServiceState &serviceState);
    std::string GetIdent() const;
    NetworkType GetNetworkType() const;
    NetCapabilities GetNetCapability() const;
    ServiceState GetServiceState() const;
    sptr<Network> GetNetwork() const;

    /**
     * @brief Initiate a network connection request to the network service of the network provider
     *
     * @return Return ERR_SERVICE_REQUEST_SUCCESS, Succeed
     */
    int32_t ServiceConnect();

    /**
     * @brief Initiate a disconnect request to the network service of the network provider
     *
     * @return Return ERR_SERVICE_DISCONNECTED_SUCCESS, Succeed
     */
    int32_t ServiceDisConnect();

    /**
     * @brief Automatically initiate a network connection request to the network service of the network provider
     *
     * @return Return ERR_SERVICE_REQUEST_SUCCESS, Succeed
     */
    int32_t ServiceAutoConnect();

private:
    int32_t ConnectTimeout();
    int32_t NetworkConnect();
    int32_t NetworkDisConnect();
    void UpdateServiceState(ServiceState serviceState);
    bool IsConnecting();
    bool IsConnected();

private:
    std::string ident_;
    NetworkType networkType_ = NET_TYPE_UNKNOWN;
    ServiceState state_ = SERVICE_STATE_IDLE;

    NetCapabilities netCapability_ = NET_CAPABILITIES_NONE;
    sptr<Network> network_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_SERVICE_H