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

#ifndef NET_CONN_SERVICE_H
#define NET_CONN_SERVICE_H

#include <mutex>
#include <string>
#include <list>

#include "singleton.h"
#include "system_ability.h"

#include "ipc/net_conn_service_stub.h"
#include "net_service.h"
#include "network.h"
#include "net_provider.h"

namespace OHOS {
namespace NetManagerStandard {
class NetConnService : public SystemAbility,
                       public NetConnServiceStub,
                       public std::enable_shared_from_this<NetConnService> {
    DECLARE_DELAYED_SINGLETON(NetConnService)
    DECLARE_SYSTEM_ABILITY(NetConnService)

    using NET_SERVICE_LIST = std::list<sptr<NetService>>;
    using NET_NETWORK_LIST = std::list<sptr<Network>>;
    using NET_PROVIDER_LIST = std::list<sptr<NetProvider>>;

public:
    void OnStart() override;
    void OnStop() override;
    /**
     * @brief The interface in NetConnService can be called when the system is ready
     *
     * @return Returns 0, the system is ready, otherwise the system is not ready
     */
    int32_t SystemReady() override;

    /**
     * @brief The interface is register the network
     *
     * @param netType Network Type
     * @param ident Unique identification of mobile phone card
     * @param netCapabilities Network capabilities registered by the network provider
     *
     * @return The id of the network provider
     */
    int32_t RegisterNetProvider(uint32_t netType, const std::string &ident, uint32_t netCapabilities) override;

    /**
     * @brief The interface is unregister the network
     *
     * @param providerId The id of the network provider
     *
     * @return Returns 0, unregister the network successfully, otherwise it will fail
     */
    int32_t UnregisterNetProvider(uint32_t providerId) override;

    /**
     * @brief The interface is update network connection status information
     *
     * @param providerId The id of the network provider
     * @param netProviderInfo network connection status information
     *
     * @return Returns 0, successfully update the network connection status information, otherwise it will fail
     */
    int32_t UpdateNetProviderInfo(uint32_t providerId, const sptr<NetProviderInfo> &netProviderInfo) override;

    /**
     * @brief The interface is Create or delete network services based on the providerId and the netCapabilities
     *
     * @param providerId The id of the network provider
     * @param netCapabilities Network capabilities registered by the network provider
     *
     * @return Returns 0, successfully create network service or delete network service, otherwise fail
     */
    int32_t UpdateNetCapabilities(uint32_t providerId, uint32_t netCapabilities) override;

    /**
     * @brief The interface is update network link attribute information
     *
     * @param providerId The id of the network provider
     * @param netLinkInfo network link attribute information
     *
     * @return Returns 0, successfully update the network link attribute information, otherwise it will fail
     */
    int32_t UpdateNetLinkInfo(uint32_t providerId, const sptr<NetLinkInfo> &netLinkInfo) override;

private:
    bool Init();
    sptr<NetProvider> GetNetProviderFromList(uint32_t netType, const std::string &ident);
    sptr<NetProvider> GetNetProviderFromListById(uint32_t providerId);
    sptr<Network> GetNetworkFromListByProviderId(uint32_t providerId);
    void DeleteProviderFromListById(uint32_t providerId);
    void DeleteNetworkFromListByProviderId(uint32_t providerId);
    bool DeleteServiceFromListByCap(int32_t netId, const NetCapabilities &netCapability);
    void DeleteServiceFromListByNet(const Network &network);
    bool IsServiceInList(int32_t netId, const NetCapabilities &netCapability) const;

private:
    enum ServiceRunningState {
        STATE_STOPPED = 0,
        STATE_RUNNING,
    };

    bool registerToService_;
    ServiceRunningState state_;
    sptr<NetService> defaultNetService_ = nullptr;

    std::mutex mtx_;
    NET_SERVICE_LIST netServices_;
    NET_NETWORK_LIST networks_;
    NET_PROVIDER_LIST netProviders_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_CONN_SERVICE_H
