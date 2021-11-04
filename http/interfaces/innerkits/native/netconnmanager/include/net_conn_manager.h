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

#ifndef NET_CONN_MANAGER_H
#define NET_CONN_MANAGER_H

#include <string>

#include "parcel.h"
#include "singleton.h"

#include "i_net_conn_service.h"
#include "net_link_info.h"
#include "net_specifier.h"

namespace OHOS {
namespace NetManagerStandard {
class NetConnManager {
    DECLARE_DELAYED_SINGLETON(NetConnManager)

public:
    int32_t SystemReady();
    int32_t RegisterNetProvider(uint32_t netType, const std::string &ident, uint64_t netCapabilities);
    int32_t UnregisterNetProvider(uint32_t providerId);
    int32_t UpdateNetProviderInfo(uint32_t providerId, const sptr<NetProviderInfo> &netProviderInfo);
    int32_t UpdateNetCapabilities(uint32_t providerId, uint64_t netCapabilities);
    int32_t UpdateNetLinkInfo(uint32_t providerId, const sptr<NetLinkInfo> &netLinkInfo);

private:
    class NetConnDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit NetConnDeathRecipient(NetConnManager &client) : client_(client) {}
        ~NetConnDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        NetConnManager &client_;
    };

private:
    sptr<INetConnService> getProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    std::mutex mutex_;
    sptr<INetConnService> NetConnService_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
} // namespace NetManagerStandard
} // namespace OHOS

#endif // NET_CONN_MANAGER_H