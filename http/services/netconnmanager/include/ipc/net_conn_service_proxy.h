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

#ifndef NET_CONN_SERVICE_PROXY_H
#define NET_CONN_SERVICE_PROXY_H

#include "iremote_proxy.h"
#include "i_net_conn_service.h"

namespace OHOS {
namespace NetManagerStandard {
class NetConnServiceProxy : public IRemoteProxy<INetConnService> {
public:
    explicit NetConnServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~NetConnServiceProxy();
    int32_t SystemReady() override;
    int32_t RegisterNetProvider(uint32_t netType, const std::string &ident, uint32_t netCapabilities) override;
    int32_t UnregisterNetProvider(uint32_t providerId) override;
    int32_t UpdateNetProviderInfo(uint32_t providerId, const sptr<NetProviderInfo> &netProviderInfo) override;
    int32_t UpdateNetCapabilities(uint32_t providerId, uint32_t netCapabilities) override;
    int32_t UpdateNetLinkInfo(uint32_t providerId, const sptr<NetLinkInfo> &netLinkInfo) override;

private:
    bool WriteInterfaceToken(MessageParcel &data);

private:
    static inline BrokerDelegator<NetConnServiceProxy> delegator_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_CONN_SERVICE_PROXY_H
