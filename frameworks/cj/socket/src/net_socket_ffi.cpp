/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ffi_remote_data.h"
#include "ffi_structs.h"
#include "constant.h"
#include "netstack_log.h"
#include "net_socket_impl.h"
#include "cj_lambda.h"

using namespace OHOS::FFI;
namespace OHOS::NetStack::Socket {

EXTERN_C_START

int64_t FfiOHOSTcpSocketCreate()
{
    auto instance = FFI::FFIData::Create<CJTcpSocketProxy>();
    if (!instance) {
        NETSTACK_LOGE("CJTcpSocket Create CJTcpSocketProxy failed.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return instance->GetID();
}

int32_t FfiOHOSTcpSocketBind(int64_t id, CNetAddress address)
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketBind failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::Bind(instance, address);
}

int32_t FfiOHOSTcpSocketConnect(int64_t id, CTcpConnectOptions options,
    int64_t callback)
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketConnect failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::Connect(instance, options, callback);
}

int32_t FfiOHOSTcpSocketSend(int64_t id, CTcpSendOptions options)
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketSend failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::Send(instance, options);
}

int32_t FfiOHOSTcpSocketClose(int64_t id)
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketClose failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::Close(instance);
}

CGetStateResult FfiOHOSTcpSocketGetState(int64_t id)
{
    CGetStateResult ret = {};
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketGetState failed. instance is null.");
        ret.code = ERR_INVALID_INSTANCE_CODE;
        return ret;
    }
    return CJTcpSocketImpl::GetState(instance);
}

CGetAddressResult FfiOHOSTcpSocketGetRemoteAddress(int64_t id)
{
    CGetAddressResult ret = {};
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketGetRemoteAddress failed. instance is null.");
        ret.code = ERR_INVALID_INSTANCE_CODE;
        return ret;
    }
    return CJTcpSocketImpl::GetRemoteAddress(instance);
}

CGetAddressResult FfiOHOSTcpSocketGetLocalAddress(int64_t id)
{
    CGetAddressResult ret = {};
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketGetLocalAddress failed. instance is null.");
        ret.code = ERR_INVALID_INSTANCE_CODE;
        return ret;
    }
    return CJTcpSocketImpl::GetLocalAddress(instance);
}

CGetSocketFdResult FfiOHOSTcpSocketGetSocketFd(int64_t id)
{
    CGetSocketFdResult ret = {};
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketGetSocketFd failed. instance is null.");
        ret.code = ERR_INVALID_INSTANCE_CODE;
        return ret;
    }
    return CJTcpSocketImpl::GetSocketFd(instance);
}

int32_t FfiOHOSTcpSocketSetExtraOptions(int64_t id, CTcpExtraOptions options)
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketSetExtraOptions failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::SetExtraOptions(instance, options);
}

int32_t FfiOHOSTcpSocketOnController(int64_t id, int32_t typeId, void (*callback)(CCallbackData *))
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketOnController failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::OnController(instance, typeId, CJLambda::Create(callback));
}

int32_t FfiOHOSTcpSocketOffController(int64_t id, int32_t typeId)
{
    auto instance = FFIData::GetData<CJTcpSocketProxy>(id);
    if (instance == nullptr) {
        NETSTACK_LOGE("CJTcpSocket FfiOHOSTcpSocketOffController failed. instance is null.");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return CJTcpSocketImpl::OffController(instance, typeId);
}

EXTERN_C_END

}
