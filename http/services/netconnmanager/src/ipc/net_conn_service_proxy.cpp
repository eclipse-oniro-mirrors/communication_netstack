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

#include "net_conn_service_proxy.h"
#include "string_ex.h"
#include "ipc_types.h"
#include "net_conn_constants.h"
#include "netmgr_log_wrapper.h"

namespace OHOS {
namespace NetManagerStandard {
NetConnServiceProxy::NetConnServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<INetConnService>(impl) {}

NetConnServiceProxy::~NetConnServiceProxy() {}

int32_t NetConnServiceProxy::SystemReady()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETMGR_LOGE("Remote is null");
        return ERR_NULL_OBJECT;
    }
    int32_t error = remote->SendRequest(CMD_NM_SYSTEM_READY, data, reply, option);
    if (error != ERR_NONE) {
        NETMGR_LOGE("proxy SendRequest failed, error code: [%{public}d]", error);
    }
    return error;
}

int32_t NetConnServiceProxy::RegisterNetProvider(
    uint32_t netType, const std::string &ident, uint32_t netCapabilities)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return NET_CONN_ERR_INVALID_PROVIDER_ID;
    }

    NETMGR_LOGD("proxy netType[%{public}d], ident[%{public}s], netCapabilities[%{public}d]", netType,
        ident.c_str(), netCapabilities);
    if (!data.WriteUint32(netType)) {
        NETMGR_LOGE("proxy netType[%{public}d] write to parcel failed", netType);
        return NET_CONN_ERR_INVALID_PROVIDER_ID;
    }
    if (!data.WriteString(ident)) {
        NETMGR_LOGE("proxy ident[%{public}s] write to parcel failed", ident.c_str());
        return NET_CONN_ERR_INVALID_PROVIDER_ID;
    }
    if (!data.WriteUint32(netCapabilities)) {
        NETMGR_LOGE("proxy netCapabilities[%{public}d] write to parcel failed", netCapabilities);
        return NET_CONN_ERR_INVALID_PROVIDER_ID;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETMGR_LOGE("Remote is null");
        return NET_CONN_ERR_INVALID_PROVIDER_ID;
    }
    int32_t error = remote->SendRequest(CMD_NM_REG_NET_PROVIDER, data, reply, option);
    if (error != ERR_NONE) {
        NETMGR_LOGE("proxy SendRequest failed, error code: [%{public}d]", error);
        return NET_CONN_ERR_INVALID_PROVIDER_ID;
    }

    return reply.ReadInt32();
}

int32_t NetConnServiceProxy::UnregisterNetProvider(uint32_t providerId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }

    NETMGR_LOGD("proxy providerId[%{public}d]", providerId);
    if (!data.WriteUint32(providerId)) {
        NETMGR_LOGE("proxy providerId[%{public}d] write to parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETMGR_LOGE("Remote is null");
        return ERR_NULL_OBJECT;
    }
    int32_t error = remote->SendRequest(CMD_NM_UNREG_NETWORK, data, reply, option);
    if (error != ERR_NONE) {
        NETMGR_LOGE("proxy SendRequest failed, error code: [%{public}d]", error);
        return error;
    }

    return reply.ReadInt32();
}

int32_t NetConnServiceProxy::UpdateNetProviderInfo(
    uint32_t providerId, const sptr<NetProviderInfo> &netProviderInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return ERR_FLATTEN_OBJECT;
    }

    NETMGR_LOGD("proxy providerId[%{public}d]", providerId);
    if (!data.WriteUint32(providerId)) {
        NETMGR_LOGE("proxy providerId[%{public}d] write to parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }
    NETMGR_LOGD("proxy providerId[%{public}d] Marshalling success", providerId);
    if (!netProviderInfo->Marshalling(data)) {
        NETMGR_LOGE("proxy Marshalling failed");
        return ERR_FLATTEN_OBJECT;
    }
    NETMGR_LOGD("proxy Marshalling success");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETMGR_LOGE("Remote is null");
        return ERR_NULL_OBJECT;
    }
    int32_t error = remote->SendRequest(CMD_NM_SET_NET_PROVIDER_INFO, data, reply, option);
    if (error != ERR_NONE) {
        NETMGR_LOGE("proxy SendRequest failed, error code: [%{public}d]", error);
        return error;
    }

    return reply.ReadInt32();
}

int32_t NetConnServiceProxy::UpdateNetCapabilities(uint32_t providerId, uint32_t netCapabilities)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return IPC_PROXY_ERR;
    }

    NETMGR_LOGD("proxy providerId[%{public}d], netCapabilities[%{public}d]", providerId, netCapabilities);
    if (!data.WriteUint32(providerId)) {
        NETMGR_LOGE("proxy providerId[%{public}d] write to parcel failed", providerId);
        return ERR_FLATTEN_OBJECT;
    }
    if (!data.WriteUint32(netCapabilities)) {
        NETMGR_LOGE("proxy netCapabilities[%{public}d] write to parcel failed", netCapabilities);
        return ERR_FLATTEN_OBJECT;
    }
    NETMGR_LOGD("proxy Marshalling success");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETMGR_LOGE("Remote is null");
        return ERR_NULL_OBJECT;
    }
    int32_t error = remote->SendRequest(CMD_NM_SET_NET_CAPABILTITES, data, reply, option);
    if (error != ERR_NONE) {
        NETMGR_LOGE("proxy SendRequest failed, error code: [%{public}d]", error);
        return error;
    }

    return reply.ReadInt32();
}

int32_t NetConnServiceProxy::UpdateNetLinkInfo(uint32_t providerId, const sptr<NetLinkInfo> &netLinkInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!WriteInterfaceToken(data)) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return IPC_PROXY_ERR;
    }

    NETMGR_LOGD("proxy providerId[%{public}d]", providerId);
    if (!data.WriteUint32(providerId)) {
        NETMGR_LOGE("proxy providerId[%{public}d] write to parcel faield", providerId);
        return IPC_PROXY_ERR;
    }
    NETMGR_LOGD("proxy providerId[%{public}d] Marshalling success", providerId);

    if (!netLinkInfo->Marshalling(data)) {
        NETMGR_LOGE("proxy Marshalling failed");
        return IPC_PROXY_ERR;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETMGR_LOGE("Remote is null");
        return ERR_NULL_OBJECT;
    }
    int32_t error = remote->SendRequest(CMD_NM_SET_NET_LINK_INFO, data, reply, option);
    if (error != ERR_NONE) {
        NETMGR_LOGE("proxy SendRequest failed, error code: [%{public}d]", error);
        return error;
    }

    return reply.ReadInt32();
}

bool NetConnServiceProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(NetConnServiceProxy::GetDescriptor())) {
        NETMGR_LOGE("WriteInterfaceToken failed");
        return false;
    }
    return true;
}

} // namespace NetManagerStandard
} // namespace OHOS
