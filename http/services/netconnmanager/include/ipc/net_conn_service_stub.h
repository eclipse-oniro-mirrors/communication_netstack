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

#ifndef NET_CONN_SERVICE_STUB_H
#define NET_CONN_SERVICE_STUB_H

#include <map>
#include "iremote_stub.h"
#include "i_net_conn_service.h"

namespace OHOS {
namespace NetManagerStandard {
class NetConnServiceStub : public IRemoteStub<INetConnService> {
public:
    NetConnServiceStub();
    ~NetConnServiceStub();

    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    using NetConnServiceFunc = int32_t (NetConnServiceStub::*)(MessageParcel &, MessageParcel &);

private:
    int32_t OnSystemReady(MessageParcel &data, MessageParcel &reply);
    int32_t OnRegisterNetProvider(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnregisterNetProvider(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateNetProviderInfo(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateNetCapabilities(MessageParcel &data, MessageParcel &reply);
    int32_t OnUpdateNetLinkInfo(MessageParcel &data, MessageParcel &reply);

private:
    std::map<uint32_t, NetConnServiceFunc> memberFuncMap_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_CONN_SERVICE_STUB_H
