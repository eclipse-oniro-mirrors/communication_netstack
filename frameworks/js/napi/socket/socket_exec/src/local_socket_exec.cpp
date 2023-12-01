/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "local_socket_exec.h"

#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include "context_key.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "socket_async_work.h"
#include "socket_module.h"

namespace {
constexpr int BACKLOG = 32;

constexpr int DEFAULT_BUFFER_SIZE = 8192;

constexpr int DEFAULT_POLL_TIMEOUT_MS = 500;

constexpr int UNKNOW_ERROR = -1;

constexpr int NO_MEMORY = -2;

constexpr int MAX_CLIENTS = 1024;

constexpr int ERRNO_BAD_FD = 9;

constexpr char LOCAL_SOCKET_CONNECTION[] = "LocalSocketConnection";

constexpr char LOCAL_SOCKET_SERVER_HANDLE_CLIENT[] = "LocalSocketServerHandleClient";

constexpr char LOCAL_SOCKET_SERVER_ACCEPT_RECV_DATA[] = "LocalSocketServerAcceptRecvData";
} // namespace

namespace OHOS::NetStack::Socket::LocalSocketExec {
struct MsgWithLocalRemoteInfo {
    MsgWithLocalRemoteInfo() = delete;
    MsgWithLocalRemoteInfo(void *d, size_t length, const std::string &path) : data(d), len(length)
    {
        remoteInfo.SetAddress(path);
    }
    ~MsgWithLocalRemoteInfo()
    {
        if (data) {
            free(data);
        }
    }
    void *data = nullptr;
    size_t len = 0;
    LocalSocketRemoteInfo remoteInfo;
};

void LocalSocketServerConnectionFinalize(napi_env, void *data, void *)
{
    NETSTACK_LOGI("localsocket connection is finalized");
    EventManager *manager = reinterpret_cast<EventManager *>(data);
    if (manager != nullptr) {
        LocalSocketConnectionData *data = reinterpret_cast<LocalSocketConnectionData *>(manager->GetData());
        if (data != nullptr) {
            data->serverManager_->RemoveEventManager(data->clientId_);
            data->serverManager_->RemoveAccept(data->clientId_);
            delete data;
        }
    }
}

napi_value NewInstanceWithConstructor(napi_env env, napi_callback_info info, napi_value jsConstructor,
                                      LocalSocketConnectionData *data)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    EventManager *manager = new (std::nothrow) EventManager();
    if (manager == nullptr) {
        return result;
    }
    manager->SetData(reinterpret_cast<void *>(data));
    EventManager::SetValid(manager);
    data->serverManager_->AddEventManager(data->clientId_, manager);
    napi_wrap(env, result, reinterpret_cast<void *>(manager), LocalSocketServerConnectionFinalize, nullptr, nullptr);
    return result;
}

napi_value ConstructLocalSocketConnection(napi_env env, napi_callback_info info, LocalSocketConnectionData *data)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_SEND,
                              SocketModuleExports::LocalSocketConnection::Send),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_CLOSE,
                              SocketModuleExports::LocalSocketConnection::Close),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_ON,
                              SocketModuleExports::LocalSocketConnection::On),
        DECLARE_NAPI_FUNCTION(SocketModuleExports::LocalSocketConnection::FUNCTION_OFF,
                              SocketModuleExports::LocalSocketConnection::Off),
    };

    auto constructor = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVal = nullptr;
        NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));
        return thisVal;
    };

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    napi_value jsConstructor = nullptr;
    NAPI_CALL_BASE(env,
                   napi_define_class(env, LOCAL_SOCKET_CONNECTION, NAPI_AUTO_LENGTH, constructor, nullptr,
                                     properties.size(), descriptors, &jsConstructor),
                   NapiUtils::GetUndefined(env));

    if (jsConstructor != nullptr) {
        napi_value result = NewInstanceWithConstructor(env, info, jsConstructor, data);
        NapiUtils::SetInt32Property(env, result, SocketModuleExports::LocalSocketConnection::PROPERTY_CLIENT_ID,
                                    data->clientId_);
        return result;
    }
    return NapiUtils::GetUndefined(env);
}

static napi_value MakeLocalSocketConnectionMessage(napi_env env, void *para)
{
    auto pData = reinterpret_cast<LocalSocketConnectionData *>(para);
    napi_callback_info info = nullptr;
    return ConstructLocalSocketConnection(env, info, pData);
}

static napi_value MakeJsLocalSocketMessageParam(napi_env env, napi_value msgBuffer, MsgWithLocalRemoteInfo *msg)
{
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return nullptr;
    }
    if (NapiUtils::ValueIsArrayBuffer(env, msgBuffer)) {
        NapiUtils::SetNamedProperty(env, obj, KEY_MESSAGE, msgBuffer);
    }
    napi_value jsRemoteInfo = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsRemoteInfo) != napi_object) {
        return nullptr;
    }
    NapiUtils::SetStringPropertyUtf8(env, jsRemoteInfo, KEY_ADDRESS, msg->remoteInfo.GetAddress());
    NapiUtils::SetUint32Property(env, jsRemoteInfo, KEY_SIZE, msg->len);
    NapiUtils::SetNamedProperty(env, obj, KEY_REMOTE_INFO, jsRemoteInfo);
    return obj;
}
} // namespace OHOS::NetStack::Socket::LocalSocketExec