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

#include "monitor_server.h"

#include <cstddef>
#include <utility>

#include <napi/native_api.h>
#include <napi/native_common.h>
#include <securec.h>
#include <uv.h>

#include "module_template.h"
#include "napi_utils.h"
#include "netstack_log.h"

#include "tls_socket_server.h"
#include "tlssocketserver_module.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
namespace {
constexpr int PARAM_OPTION = 1;
constexpr int PARAM_OPTION_CALLBACK = 2;
constexpr std::string_view EVENT_MESSAGE = "message";
constexpr std::string_view EVENT_CONNECT = "connect";
constexpr std::string_view EVENT_CLOSE = "close";
constexpr std::string_view EVENT_ERROR = "error";

constexpr const char *PROPERTY_ADDRESS = "address";
constexpr const char *PROPERTY_FAMILY = "family";
constexpr const char *PROPERTY_PORT = "port";
constexpr const char *PROPERTY_SIZE = "size";
constexpr const char *ON_MESSAGE = "message";
constexpr const char *ON_REMOTE_INFO = "remoteInfo";

napi_value NewInstanceWithConstructor(napi_env env, napi_callback_info info, napi_value jsConstructor, int32_t counter,
                                      std::shared_ptr<EventManager> eventManager)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, jsConstructor, 0, nullptr, &result));

    std::shared_ptr<EventManager> manager = eventManager;

    napi_wrap(
        env, result, reinterpret_cast<void *>(manager.get()),
        [](napi_env, void *data, void *) {
            NETSTACK_LOGI("socket handle is finalized");
            auto manager = static_cast<EventManager *>(data);
            if (manager != nullptr) {
                auto tlsServer = static_cast<TLSSocketServer *>(manager->GetData());
                if (tlsServer != nullptr) {
                    tlsServer->CloseConnectionByEventManager(manager);
                    tlsServer->DeleteConnectionByEventManager(manager);
                }
                EventManager::SetInvalid(manager);
            }
        },
        nullptr, nullptr);

    return result;
}

napi_value ConstructTLSSocketConnection(napi_env env, napi_callback_info info, int32_t counter,
                                        std::shared_ptr<EventManager> eventManager)
{
    napi_value jsConstructor = nullptr;
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_GET_CERTIFICATE,
                              TLSSocketServerModuleExports::TLSSocketConnection::GetCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_GET_REMOTE_CERTIFICATE,
                              TlsSocketServer::TLSSocketServerModuleExports::TLSSocketConnection::GetRemoteCertificate),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_GET_SIGNATURE_ALGORITHMS,
                              TLSSocketServerModuleExports::TLSSocketConnection::GetSignatureAlgorithms),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_GET_CIPHER_SUITE,
                              TLSSocketServerModuleExports::TLSSocketConnection::GetCipherSuites),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_SEND,
                              TLSSocketServerModuleExports::TLSSocketConnection::Send),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_CLOSE,
                              TLSSocketServerModuleExports::TLSSocketConnection::Close),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_GET_REMOTE_ADDRESS,
                              TLSSocketServerModuleExports::TLSSocketConnection::GetRemoteAddress),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_ON,
                              TLSSocketServerModuleExports::TLSSocketConnection::On),
        DECLARE_NAPI_FUNCTION(TLSSocketServerModuleExports::TLSSocketConnection::FUNCTION_OFF,
                              TLSSocketServerModuleExports::TLSSocketConnection::Off),
    };

    auto constructor = [](napi_env env, napi_callback_info info) -> napi_value {
        napi_value thisVal = nullptr;
        NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVal, nullptr));

        return thisVal;
    };

    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    NAPI_CALL_BASE(env,
                   napi_define_class(env, TLSSocketServerModuleExports::INTERFACE_TLS_SOCKET_SERVER_CONNECTION,
                                     NAPI_AUTO_LENGTH, constructor, nullptr, properties.size(), descriptors,
                                     &jsConstructor),
                   NapiUtils::GetUndefined(env));

    if (jsConstructor != nullptr) {
        napi_value result = NewInstanceWithConstructor(env, info, jsConstructor, counter, eventManager);
        NapiUtils::SetInt32Property(env, result, TLSSocketServerModuleExports::TLSSocketConnection::PROPERTY_CLIENT_ID,
                                    counter);
        return result;
    }
    return NapiUtils::GetUndefined(env);
}

napi_value MakeMessageObj(napi_env env, std::shared_ptr<MonitorServer::MessageRecvParma> MessagePara)
{
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(env, MessagePara->data.size(), &data);
    if (data != nullptr && arrayBuffer != nullptr) {
        if (memcpy_s(data, MessagePara->data.size(), MessagePara->data.c_str(), MessagePara->data.size()) != EOK) {
            NETSTACK_LOGE("memcpy_s failed!");
            return nullptr;
        }
    } else {
        return nullptr;
    }

    napi_value obj = NapiUtils::CreateObject(env);
    napi_value remoteInfo = NapiUtils::CreateObject(env);

    napi_value message = nullptr;
    napi_create_typedarray(env, napi_uint8_array, MessagePara->data.size(), arrayBuffer, 0, &message);
    napi_value address = NapiUtils::CreateStringUtf8(env, MessagePara->remoteInfo_.GetAddress());
    napi_value family = NapiUtils::CreateStringUtf8(env, MessagePara->remoteInfo_.GetFamily());
    napi_value port = NapiUtils::CreateInt32(env, MessagePara->remoteInfo_.GetPort());
    napi_value size = NapiUtils::CreateInt32(env, MessagePara->remoteInfo_.GetSize());
    NapiUtils::SetNamedProperty(env, remoteInfo, PROPERTY_ADDRESS, address);
    NapiUtils::SetNamedProperty(env, remoteInfo, PROPERTY_FAMILY, family);
    NapiUtils::SetNamedProperty(env, remoteInfo, PROPERTY_PORT, port);
    NapiUtils::SetNamedProperty(env, remoteInfo, PROPERTY_SIZE, size);
    NapiUtils::SetNamedProperty(env, obj, ON_MESSAGE, message);
    NapiUtils::SetNamedProperty(env, obj, ON_REMOTE_INFO, remoteInfo);

    return obj;
}

void EventMessageCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    if (workWrapper == nullptr) {
        NETSTACK_LOGE("workWrapper is nullptr");
        delete work;
        return;
    }
    std::shared_ptr<MonitorServer::MessageRecvParma> ptrMessageRecvParma(
        static_cast<MonitorServer::MessageRecvParma *>(workWrapper->data));
    if (ptrMessageRecvParma == nullptr) {
        NETSTACK_LOGE("messageRecvParma is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    if (workWrapper->manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    napi_handle_scope scope = NapiUtils::OpenScope(workWrapper->env);
    auto obj = MakeMessageObj(workWrapper->env, ptrMessageRecvParma);
    if (obj == nullptr) {
        NapiUtils::CloseScope(workWrapper->env, scope);
        delete workWrapper;
        delete work;
        return;
    }

    workWrapper->manager->Emit(workWrapper->type, std::make_pair(NapiUtils::GetUndefined(workWrapper->env), obj));
    NapiUtils::CloseScope(workWrapper->env, scope);

    delete workWrapper;
    delete work;
}

void EventConnectCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    if (workWrapper == nullptr) {
        NETSTACK_LOGE("workWrapper is nullptr");
        delete work;
        return;
    }
    std::shared_ptr<MonitorServer::MessageParma> messageParma(
        static_cast<MonitorServer::MessageParma *>(workWrapper->data));
    if (messageParma == nullptr) {
        NETSTACK_LOGE("messageParma is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    auto clientid = messageParma->clientID;
    auto eventManager = messageParma->eventManager;
    napi_handle_scope scope = NapiUtils::OpenScope(workWrapper->env);
    napi_callback_info info = nullptr;
    napi_value obj = ConstructTLSSocketConnection(workWrapper->env, info, clientid, eventManager);
    workWrapper->manager->Emit(workWrapper->type, std::make_pair(NapiUtils::GetUndefined(workWrapper->env), obj));
    NapiUtils::CloseScope(workWrapper->env, scope);
    delete workWrapper;
    delete work;
}

void EventCloseCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    if (workWrapper == nullptr) {
        NETSTACK_LOGE("workWrapper is nullptr");
        delete work;
        return;
    }
    std::shared_ptr<int> ptrClientID(static_cast<int *>(workWrapper->data));
    if (ptrClientID == nullptr) {
        NETSTACK_LOGE("ptrClientID == nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    if (workWrapper->manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    napi_handle_scope scope = NapiUtils::OpenScope(workWrapper->env);
    napi_value obj = nullptr;
    workWrapper->manager->Emit(workWrapper->type, std::make_pair(NapiUtils::GetUndefined(workWrapper->env), obj));
    NapiUtils::CloseScope(workWrapper->env, scope);
    delete workWrapper;
    delete work;
}

void EventErrorCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    if (workWrapper == nullptr) {
        NETSTACK_LOGE("workWrapper is nullptr");
        delete work;
        return;
    }
    auto monitor = static_cast<MonitorServer *>(workWrapper->data);
    if (monitor == nullptr) {
        NETSTACK_LOGE("monitor is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    if (workWrapper->manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    napi_handle_scope scope = NapiUtils::OpenScope(workWrapper->env);
    napi_value obj = NapiUtils::CreateObject(workWrapper->env);
    napi_value errorNumber = NapiUtils::CreateInt32(workWrapper->env, monitor->errorNumber_);
    napi_value errorString = NapiUtils::CreateStringUtf8(workWrapper->env, monitor->errorString_);
    NapiUtils::SetNamedProperty(workWrapper->env, obj, "errorNumber", errorNumber);
    NapiUtils::SetNamedProperty(workWrapper->env, obj, "errorString", errorString);
    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);
    NapiUtils::CloseScope(workWrapper->env, scope);
    delete workWrapper;
    delete work;
}
} // namespace

MonitorServer::MonitorServer() {}

MonitorServer::~MonitorServer() {}

napi_value MonitorServer::On(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (paramsCount != PARAM_OPTION_CALLBACK || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }
    EventManager *manager_ = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&manager_));
    if (manager_ == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager_->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("tlsSocketServer is null");
        return NapiUtils::GetUndefined(env);
    }

    const std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    auto itor = monitors_.find(event);
    if (itor != monitors_.end()) {
        NETSTACK_LOGE("monitor is exits %{public}s", event.c_str());
        return NapiUtils::GetUndefined(env);
    }
    manager_->AddListener(env, event, params[1], false, false);
    TLSServerRegEvent(event, tlsSocketServer, manager_);
    return NapiUtils::GetUndefined(env);
}

napi_value MonitorServer::ConnectionOn(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if (false == NapiUtils::HasNamedProperty(env, thisVal,
                                             TLSSocketServerModuleExports::TLSSocketConnection::PROPERTY_CLIENT_ID)) {
        NETSTACK_LOGI("not found Property clientId");
        return NapiUtils::GetUndefined(env);
    }

    int clientid = NapiUtils::GetInt32Property(env, thisVal,
                                               TLSSocketServerModuleExports::TLSSocketConnection::PROPERTY_CLIENT_ID);

    if (paramsCount != PARAM_OPTION_CALLBACK || NapiUtils::GetValueType(env, params[0]) != napi_string ||
        NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }
    EventManager *manager_ = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&manager_));
    if (manager_ == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager_->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("tlsSocketServer is null");
        return NapiUtils::GetUndefined(env);
    }

    const std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);

    manager_->AddListener(env, event, params[1], false, false);
    TLSConnectionRegEvent(event, tlsSocketServer, clientid, manager_);
    return NapiUtils::GetUndefined(env);
}

napi_value MonitorServer::Off(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    if ((paramsCount != PARAM_OPTION && paramsCount != PARAM_OPTION_CALLBACK) ||
        NapiUtils::GetValueType(env, params[0]) != napi_string) {
        NETSTACK_LOGE("on off once interface para: [string, function?]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    if (paramsCount == PARAM_OPTION_CALLBACK && NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }
    EventManager *manager_ = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&manager_));
    if (manager_ == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager_->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("tlsSocketServer is null");
        return NapiUtils::GetUndefined(env);
    }

    const std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    auto itor = monitors_.find(event);
    if (itor == monitors_.end()) {
        NETSTACK_LOGE("monitor is off %{public}s", event.c_str());
        return NapiUtils::GetUndefined(env);
    }
    if (manager_ != nullptr) {
        if (paramsCount == PARAM_OPTION_CALLBACK) {
            manager_->DeleteListener(event, params[1]);
        } else {
            manager_->DeleteListener(event);
        }
    }

    if (event == EVENT_CONNECT) {
        monitors_.erase(EVENT_CONNECT);
        tlsSocketServer->OffConnect();
    }
    if (event == EVENT_ERROR) {
        monitors_.erase(EVENT_ERROR);
        tlsSocketServer->OffError();
    }
    return NapiUtils::GetUndefined(env);
}

napi_value MonitorServer::ConnectionOff(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    int clientid = NapiUtils::GetInt32Property(env, thisVal,
                                               TLSSocketServerModuleExports::TLSSocketConnection::PROPERTY_CLIENT_ID);

    if ((paramsCount != PARAM_OPTION && paramsCount != PARAM_OPTION_CALLBACK) ||
        NapiUtils::GetValueType(env, params[0]) != napi_string) {
        NETSTACK_LOGE("on off once interface para: [string, function?]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }

    if (paramsCount == PARAM_OPTION_CALLBACK && NapiUtils::GetValueType(env, params[1]) != napi_function) {
        NETSTACK_LOGE("on off once interface para: [string, function]");
        napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        return NapiUtils::GetUndefined(env);
    }
    EventManager *manager_ = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&manager_));
    if (manager_ == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto tlsSocketServer = reinterpret_cast<TLSSocketServer *>(manager_->GetData());
    if (tlsSocketServer == nullptr) {
        NETSTACK_LOGE("tlsSocketServer is null");
        return NapiUtils::GetUndefined(env);
    }

    const std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    auto itor = monitors_.find(event);
    if (itor == monitors_.end()) {
        NETSTACK_LOGE("monitor is off %{public}s", event.c_str());
        return NapiUtils::GetUndefined(env);
    }
    if (manager_ != nullptr) {
        if (paramsCount == PARAM_OPTION_CALLBACK) {
            manager_->DeleteListener(event, params[1]);
        } else {
            manager_->DeleteListener(event);
        }
    }
    TLSConnectionUnRegEvent(event, tlsSocketServer, clientid);
    return NapiUtils::GetUndefined(env);
}

void MonitorServer::TLSServerRegEvent(std::string event, TLSSocketServer *tlsSocketServer,
                                      EventManager *ServerEventManager)
{
    if (event == EVENT_CONNECT) {
        monitors_.insert(EVENT_CONNECT);
        tlsSocketServer->OnConnect(
            [this, ServerEventManager](auto clientFd, std::shared_ptr<EventManager> eventManager) {
                auto messageParma = new MonitorServer::MessageParma();
                messageParma->clientID = clientFd;
                messageParma->eventManager = eventManager;
                ServerEventManager->EmitByUv(std::string(EVENT_CONNECT), messageParma, EventConnectCallback);
            });
    }
    if (event == EVENT_ERROR) {
        monitors_.insert(EVENT_ERROR);
        tlsSocketServer->OnError([this, ServerEventManager](auto errorNumber, auto errorString) {
            errorNumber_ = errorNumber;
            errorString_ = errorString;
            ServerEventManager->EmitByUv(std::string(EVENT_ERROR), static_cast<void *>(this), EventErrorCallback);
        });
    }
}

void MonitorServer::TLSConnectionRegEvent(std::string event, TLSSocketServer *tlsSocketServer, int clientId,
                                          EventManager *eventManager)
{
    if (event == EVENT_MESSAGE) {
        monitors_.insert(EVENT_MESSAGE);
        auto ptrConnection = tlsSocketServer->GetConnectionByClientID(clientId);
        if (ptrConnection != nullptr) {
            ptrConnection->OnMessage([this, eventManager](auto clientFd, auto data, auto remoteInfo) {
                auto messageRecvParma = new MessageRecvParma();
                messageRecvParma->clientID = clientFd;
                messageRecvParma->data = data;
                messageRecvParma->remoteInfo_.SetAddress(remoteInfo.GetAddress());
                messageRecvParma->remoteInfo_.SetFamilyByStr(remoteInfo.GetFamily());
                messageRecvParma->remoteInfo_.SetPort(remoteInfo.GetPort());
                messageRecvParma->remoteInfo_.SetSize(remoteInfo.GetSize());
                eventManager->EmitByUv(std::string(EVENT_MESSAGE), messageRecvParma, EventMessageCallback);
            });
        }
    }
    if (event == EVENT_CLOSE) {
        monitors_.insert(EVENT_CLOSE);
        auto ptrConnection = tlsSocketServer->GetConnectionByClientID(clientId);
        if (ptrConnection != nullptr) {
            ptrConnection->OnClose([this, eventManager](auto clientFd) {
                eventManager->EmitByUv(std::string(EVENT_CLOSE), static_cast<void *>(this), EventCloseCallback);
            });
        }
    }
    if (event == EVENT_ERROR) {
        monitors_.insert(EVENT_ERROR);
        auto ptrConnection = tlsSocketServer->GetConnectionByClientID(clientId);
        if (ptrConnection != nullptr) {
            ptrConnection->OnError([this, eventManager](auto errorNumber, auto errorString) {
                eventManager->EmitByUv(std::string(EVENT_ERROR), static_cast<void *>(this), EventErrorCallback);
            });
        }
    }
}

void MonitorServer::TLSConnectionUnRegEvent(std::string event, TLSSocketServer *tlsSocketServer, int clientId)
{
    if (event == EVENT_MESSAGE) {
        monitors_.erase(EVENT_MESSAGE);
        auto ptrConnection = tlsSocketServer->GetConnectionByClientID(clientId);
        if (ptrConnection != nullptr) {
            ptrConnection->OffMessage();
        }
    }
    if (event == EVENT_CLOSE) {
        monitors_.erase(EVENT_CLOSE);
        auto ptrConnection = tlsSocketServer->GetConnectionByClientID(clientId);
        if (ptrConnection != nullptr) {
            ptrConnection->OffClose();
        }
    }
    if (event == EVENT_ERROR) {
        monitors_.erase(EVENT_ERROR);
        auto ptrConnection = tlsSocketServer->GetConnectionByClientID(clientId);
        if (ptrConnection != nullptr) {
            ptrConnection->OffError();
        }
    }
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
