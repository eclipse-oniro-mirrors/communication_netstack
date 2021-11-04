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

#include "net_conn_service_stub.h"

#include <cstring>

#include "string_ex.h"
#include "ipc_types.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"

#include "netmgr_log_wrapper.h"
#include "net_conn_types.h"
#include "net_conn_constants.h"

namespace OHOS {
namespace NetManagerStandard {
NetConnServiceStub::NetConnServiceStub()
{
    memberFuncMap_[CMD_NM_SYSTEM_READY] = &NetConnServiceStub::OnSystemReady;
    memberFuncMap_[CMD_NM_REG_NET_PROVIDER] = &NetConnServiceStub::OnRegisterNetProvider;
    memberFuncMap_[CMD_NM_UNREG_NETWORK] = &NetConnServiceStub::OnUnregisterNetProvider;
    memberFuncMap_[CMD_NM_SET_NET_PROVIDER_INFO] = &NetConnServiceStub::OnUpdateNetProviderInfo;
    memberFuncMap_[CMD_NM_SET_NET_CAPABILTITES] = &NetConnServiceStub::OnUpdateNetCapabilities;
    memberFuncMap_[CMD_NM_SET_NET_LINK_INFO] = &NetConnServiceStub::OnUpdateNetLinkInfo;
}

NetConnServiceStub::~NetConnServiceStub() {}

int32_t NetConnServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    NETMGR_LOGD("stub call start, code = [%{public}d]", code);

    std::u16string myDescripter = NetConnServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        NETMGR_LOGD("descriptor checked fail");
        return ERR_FLATTEN_OBJECT;
    }

    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }

    NETMGR_LOGD("stub default case, need check");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t NetConnServiceStub::OnSystemReady(MessageParcel &data, MessageParcel &reply)
{
    SystemReady();
    return ERR_NONE;
}

int32_t NetConnServiceStub::OnRegisterNetProvider(MessageParcel &data, MessageParcel &reply)
{
    NETMGR_LOGD("stub processing");
    uint32_t netType;
    std::string ident;
    uint32_t netCapabilities;
    if (!data.ReadUint32(netType)) {
        NETMGR_LOGE("stub read netType[%{public}d] from parcel failed", netType);
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.ReadString(ident)) {
        NETMGR_LOGE("stub read ident[%{public}s] from parcel failed", ident.c_str());
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.ReadUint32(netCapabilities)) {
        NETMGR_LOGE("stub read netCapabilities[%{public}d] from parcel failed", netCapabilities);
        return ERR_FLATTEN_OBJECT;
    }

    int32_t ret = RegisterNetProvider(netType, ident, netCapabilities);
    if (ret == ERR_NO_NETWORK || ret == ERR_NO_PROVIDER) {
        NETMGR_LOGE("Register network provider failed, error code:[%{public}d].", ret);
        ret = NET_CONN_ERR_INVALID_PROVIDER_ID;
    }
    if (!reply.WriteInt32(ret)) {
        NETMGR_LOGE("stub write ret[%{public}d] to parcel failed", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}

int32_t NetConnServiceStub::OnUnregisterNetProvider(MessageParcel &data, MessageParcel &reply)
{
    uint32_t providerId;
    if (!data.ReadUint32(providerId)) {
        NETMGR_LOGE("stub read providerId[%{public}d] from parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }

    int32_t ret = UnregisterNetProvider(providerId);
    if (!reply.WriteInt32(ret)) {
        NETMGR_LOGE("stub write[%{public}d] ret to parcel failed", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}

int32_t NetConnServiceStub::OnUpdateNetProviderInfo(MessageParcel &data, MessageParcel &reply)
{
    uint32_t providerId;
    if (!data.ReadUint32(providerId)) {
        NETMGR_LOGE("stub read providerId[%{public}d] from parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }

    sptr<NetProviderInfo> netProviderInfo = NetProviderInfo::Unmarshalling(data);
    int32_t ret = UpdateNetProviderInfo(providerId, netProviderInfo);
    if (!reply.WriteInt32(ret)) {
        NETMGR_LOGE("stub write ret[%{public}d] to parcel failed", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}

int32_t NetConnServiceStub::OnUpdateNetCapabilities(MessageParcel &data, MessageParcel &reply)
{
    uint32_t providerId;
    uint32_t netCapabilities;

    if (!data.ReadUint32(providerId)) {
        NETMGR_LOGE("stbu read providerId[%{public}d] from parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.ReadUint32(netCapabilities)) {
        NETMGR_LOGE("stbu read netCapabilities[%{public}d] from parcel failed", netCapabilities);
        return ERR_FLATTEN_OBJECT;
    }

    NETMGR_LOGD("stub execute UpdateNetCapabilities");
    int32_t ret = UpdateNetCapabilities(providerId, netCapabilities);
    if (!reply.WriteInt32(ret)) {
        NETMGR_LOGE("stub write ret[%{public}d] to parcel failed", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}

int32_t NetConnServiceStub::OnUpdateNetLinkInfo(MessageParcel &data, MessageParcel &reply)
{
    uint32_t providerId;

    if (!data.ReadUint32(providerId)) {
        NETMGR_LOGE("stub read providerId[%{public}d] from parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }

    sptr<NetLinkInfo> netLinkInfo = NetLinkInfo::Unmarshalling(data);

    int32_t ret = UpdateNetLinkInfo(providerId, netLinkInfo);
    if (!reply.WriteInt32(ret)) {
        NETMGR_LOGE("stub write ret[%{public}d] to parcel failed", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}
} // namespace NetManagerStandard
} // namespace OHOS
