/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "socket_napi.h"

#include "napi_util.h"
#include "netmgr_log_wrapper.h"
#include "node_api_types.h"

#include "tcp_socket.h"
#include "udp_socket.h"

#include <cerrno>
#include <netinet/tcp.h>
#include <vector>
#include <string>

namespace OHOS {
namespace NetManagerStandard {
static napi_value g_UdpSocketConstructorJS;
static napi_value g_TcpSocketConstructorJS;
std::vector<Baseinfo> g_onInfoList;
std::vector<TcpBaseContext> g_tcpSocketList;
static std::map<UDPSocket*, Baseinfo*> udpSocketInstances;
static std::map<TCPSocket*, TcpBaseContext*> tcpSocketInstances;
constexpr int32_t INVALID_SOCKET = -1;
constexpr int32_t EVENT_ARRAY_LENGTH = 64;

constexpr int32_t NONE_EVENT_TYPE = 0;
constexpr int32_t MESSAGE_SOCKET_STATE = 1;
constexpr int32_t LISTENING_SOCKET_STATE = 2;
constexpr int32_t CLOSE_SOCKET_STATE = 3;
constexpr int32_t ERROR_SOCKET_STATE = 4;
constexpr int32_t CONNECT_SOCKET_STATE = 5;

const std::string MESSAGE_RECEIVE = "message";
const std::string LISTENING_RECEIVE = "listening";
const std::string CLOSE_RECEIVE = "close";
const std::string ERROR_RECEIVE = "error";
const std::string CONNECT_RECEIVE = "connect";

constexpr int32_t MAX_SOCKET_OBJ_COUNT = 100;

bool MatchSocketEventType(const std::string &type, const std::string &goalTypeStr)
{
    return goalTypeStr.compare(type) == 0;
}

int32_t GetSocketEventType(const std::string &type)
{
    if (MatchSocketEventType(type, MESSAGE_RECEIVE)) {
        return MESSAGE_SOCKET_STATE;
    } else if (MatchSocketEventType(type, LISTENING_RECEIVE)) {
        return LISTENING_SOCKET_STATE;
    } else if (MatchSocketEventType(type, CLOSE_RECEIVE)) {
        return CLOSE_SOCKET_STATE;
    } else if (MatchSocketEventType(type, ERROR_RECEIVE)) {
        return ERROR_SOCKET_STATE;
    } else if (MatchSocketEventType(type, CONNECT_RECEIVE)) {
        return CONNECT_SOCKET_STATE;
    }
    return NONE_EVENT_TYPE;
}

static void EmitUdpEvent(UDPSocket *obj, const std::string &type, const std::string &message)
{
    int32_t eventType = GetSocketEventType(type);
    for (std::list<UdpEventListener>::iterator listenerIterator = g_udpEventListenerList.begin();
        listenerIterator != g_udpEventListenerList.end(); ++listenerIterator) {
        if (listenerIterator->udpSocket_ == obj && listenerIterator->eventType_ == eventType) {
            napi_env env = listenerIterator->env_;
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            napi_value undefine = nullptr;
            napi_get_undefined(env, &undefine);
            napi_ref callbackRef = listenerIterator->callbackRef_;
            napi_value callbackFunc = nullptr;
            napi_get_reference_value(env, callbackRef, &callbackFunc);
            napi_value callbackValues[2] = {0};

            callbackValues[0] = NapiUtil::CreateUndefined(env);
            napi_value object = nullptr;
            napi_create_object(env, &object);
            NapiUtil::SetPropertyStringUtf8(env, object, type, message);

            callbackValues[1] = object;
            napi_value callbackResult = nullptr;
            napi_call_function(env, undefine, callbackFunc, PARAMS_COUNT, callbackValues, &callbackResult);
            napi_close_handle_scope(env, scope);
            napi_delete_reference(env, listenerIterator->callbackRef_);
            break;
        }
    }
}

static void NativeUdpBind(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeUdpBind formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    struct sockaddr_in addr;
    asyncContext->udpRequestInfo_->GetSocketInfo(addr, asyncContext);

    if (!asyncContext->isBound && asyncContext->isClose && !asyncContext->isConnected) {
        asyncContext->errorCode = asyncContext->udpRequestInfo_->UdpBind(asyncContext->socketfd,
            (struct sockaddr *)&addr, sizeof(struct sockaddr));
    }
    if (asyncContext->errorCode >= 0) {
        asyncContext->isBound = true;
        asyncContext->resolved_ = true;
        std::string listening("listening");
        EmitUdpEvent(asyncContext->udpRequestInfo_, "listening",  listening);
    } else {
        std::string error("error");
        EmitUdpEvent(asyncContext->udpRequestInfo_, "error",  error);
    }
}

static void UdpBindCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("UdpBindCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "bind failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeUdpConnect(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeUdpConnect formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    struct sockaddr_in addr;
    asyncContext->udpRequestInfo_->GetSocketInfo(addr, asyncContext);
    // the init isclose=true and if fd close we can bind also
    if (!asyncContext->isBound && asyncContext->isClose && !asyncContext->isConnected) {
        asyncContext->errorCode = asyncContext->udpRequestInfo_->UdpConnect(asyncContext->socketfd,
            (struct sockaddr *)&addr, sizeof(struct sockaddr));
    }
    if (asyncContext->errorCode >= 0) {
        asyncContext->isConnected = true;
         // Once Connect Success ,the close state must false
        asyncContext->isClose = false;
    }
}

static void UdpConnectCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("UdpConnectCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "udp connect failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }
    
    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeUdpSend(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeUdpBind formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);

    struct sockaddr_in addr;
    asyncContext->udpRequestInfo_->GetSocketInfo(addr, asyncContext);
    
    if (!asyncContext->isClose) {
        asyncContext->errorCode = asyncContext->udpRequestInfo_->UdpSend(asyncContext->socketfd,
            asyncContext->data.c_str(), asyncContext->data.size(), 0);
    }

    if (asyncContext->errorCode >= 0) {
        std::string message("message");
        EmitUdpEvent(asyncContext->udpRequestInfo_, "message",  message);
    } else {
        std::string error("error");
        EmitUdpEvent(asyncContext->udpRequestInfo_, "error",  error);
    }
}

static void UdpSendCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("UdpSendCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "Request failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeUdpClose(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeUdpClose formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);

    if (!asyncContext->isClose) {
        asyncContext->errorCode = asyncContext->udpRequestInfo_->UdpClose(asyncContext->socketfd);
        std::string close("close");
        EmitUdpEvent(asyncContext->udpRequestInfo_, "close",  close);
    } else {
        std::string error("error");
        EmitUdpEvent(asyncContext->udpRequestInfo_, "error",  error);
    }
}

static void UdpCloseCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("UdpCloseCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "udp socket close failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeUdpGetState(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeUdpGetState formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    asyncContext->resolved_ = true;
}

static void UdpGetStateCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("UdpGetStateCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "isBound", asyncContext->isBound);
        NapiUtil::SetPropertyInt32(env, callbackValue, "isClose", asyncContext->isClose);
        NapiUtil::SetPropertyInt32(env, callbackValue, "isConnected", asyncContext->isConnected);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "udp socket getState failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, PARAMS_COUNT, callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeUdpSetExtraOptions(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeSetExtraOptionsSend formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);

    struct sockaddr_in addr;
    asyncContext->udpRequestInfo_->GetSocketInfo(addr, asyncContext);
}

static void UdpSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("UdpSetExtraOptionsCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<Baseinfo *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "udp socket SetExtraOptions  failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

napi_value CreateUDPSocket(napi_env env, napi_callback_info info)
{
    std::size_t argc = 2;
    napi_value args[2] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));

    napi_value result = nullptr;
    napi_value argvArray[] = {nullptr};
    napi_new_instance(env, g_UdpSocketConstructorJS, 0, argvArray, &result);

    return result;
}

napi_value UdpBind(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    uint32_t flag = 0;
    bool isFdExist = false;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));

    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("udpSocketInstances add udp socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);
    for (int i = 0; i < g_onInfoList.size(); i++) {
        if (objectInfo->remInfo.socketfd == g_onInfoList.at(i).socketfd) {
            flag = i;
            isFdExist = true;
            break;
        }
    }
    if (!isFdExist) {
        if (asyncContext->family == IPV6) {
            asyncContext->socketfd = objectInfo->UdpSocket(AF_INET6, SOCK_DGRAM, 0);
        } else {
            asyncContext->socketfd = objectInfo->UdpSocket(AF_INET, SOCK_DGRAM, 0);
        }
        if (asyncContext->socketfd < 0) {
            return nullptr;
        }
    }

    if (!isFdExist) {
        objectInfo->remInfo = *asyncContext;
        g_onInfoList.push_back(objectInfo->remInfo);
    } else {
        g_onInfoList[flag] = *asyncContext;
        objectInfo->remInfo = *asyncContext;
    }

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "udpBind", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeUdpBind, UdpBindCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp bind Async Work Successful");
    }
    return result;
}

napi_value UdpConnect(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    uint32_t flag = 0;
    bool isFdExist = false;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));

    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("UdpConnect not find socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);
    for (int i = 0; i < g_onInfoList.size(); i++) {
        if (objectInfo->remInfo.socketfd == g_onInfoList.at(i).socketfd) {
            flag = i;
            isFdExist = true;
            break;
        }
    }
    if (!isFdExist) {
        return nullptr;
    }

    g_onInfoList[flag] = *asyncContext;
    objectInfo->remInfo = *asyncContext;

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "udpConnect", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeUdpConnect, UdpConnectCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp connect Async Work Successful");
    }
    return result;
}

napi_value UdpSend(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    uint32_t flag = 0;
    bool isFdExist = false;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));

    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("UdpSend not find socket pointer");
        return nullptr;
    }
    
    for (int i = 0; i < g_onInfoList.size(); i++) {
        if (objectInfo->remInfo.socketfd == g_onInfoList.at(i).socketfd) {
            flag = i;
            isFdExist = true;
            break;
        }
    }
    if (!isFdExist) {
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);
    
    g_onInfoList.at(flag) = *asyncContext;
    objectInfo->remInfo = *asyncContext;

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "udpSend", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeUdpSend, UdpSendCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp send Async Work Successful");
    }
    return result;
}

napi_value UdpClose(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    uint32_t flag = 0;
    bool isFdExist = false;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));

    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("UdpClose not find socket pointer");
        return nullptr;
    }

    for (int i = 0; i < g_onInfoList.size(); i++) {
        if (objectInfo->remInfo.socketfd == g_onInfoList.at(i).socketfd) {
            flag = i;
            isFdExist = true;
            break;
        }
    }
    if (!isFdExist) {
        return nullptr;
    }

    g_onInfoList[flag] = *asyncContext;
    objectInfo->remInfo = *asyncContext;
 
    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "udpClose", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeUdpClose, UdpCloseCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp send Async Work Successful");
    }
    return result;
}

napi_value UdpGetState(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 1;
    napi_value parameters[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    uint32_t flag = 0;
    bool isFdExist = false;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));

    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("UdpGetState not find socket pointer");
        return nullptr;
    }

    for (int i = 0; i < g_onInfoList.size(); i++) {
        if (objectInfo->remInfo.socketfd == g_onInfoList.at(i).socketfd) {
            flag = i;
            isFdExist = true;
            break;
        }
    }
    if (!isFdExist) {
        return nullptr;
    }

    if (parameterCount == 1) {
        napi_valuetype valuetype1;
        NAPI_CALL(env, napi_typeof(env, parameters[0], &valuetype1));
        if (NapiUtil::MatchValueType(env, parameters[0], napi_function)) {
            NETMGR_LOGD("MatchValueType is true");
            NAPI_CALL(env, napi_create_reference(env, parameters[0], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "udpGetState", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeUdpGetState, UdpGetStateCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp GetState Async Work Successful");
    }

    return result;
}

napi_value UdpSetExtraOptions(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    uint32_t flag = 0;
    bool isFdExist = false;
    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));
    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("udpSocketInstances add udp socket pointer");
        return nullptr;
    }

    for (int i = 0; i < g_onInfoList.size(); i++) {
        if (objectInfo->remInfo.socketfd == g_onInfoList.at(i).socketfd) {
            flag = i;
            isFdExist = true;
            asyncContext = &g_onInfoList.at(i);
            break;
        }
    }
    if (!isFdExist) {
        return nullptr;
    }
    asyncContext->ipAddress = "255.255.255.255";
    asyncContext->broadcast = true;

    g_onInfoList[flag] = *asyncContext;
    objectInfo->remInfo = *asyncContext;

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "udpSetExtraOptions", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeUdpSetExtraOptions, UdpSetExtraOptionsCallback,
        (void *)asyncContext, &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp SetExtraOptions Async Work Successful");
    }
    return result;
}

napi_value UdpRequestConstructor(napi_env env, napi_callback_info info)
{
    std::size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    auto asyncContext = new Baseinfo();
    auto objectInfo = new UDPSocket(*asyncContext);

    if (udpSocketInstances.size() <= MAX_SOCKET_OBJ_COUNT) {
        asyncContext->udpRequestInfo_ = objectInfo;
        udpSocketInstances[objectInfo] = asyncContext;
    } else {
        NETMGR_LOGE("UDP object count max 100");
        return thisVar;
    }

    napi_wrap(env,
        thisVar,
        objectInfo,
        [](napi_env env, void *data, void *hint) {
            UDPSocket *objectInfo = (UDPSocket *)data;
            if (objectInfo) {
                delete objectInfo;
                objectInfo = nullptr;
            }
        },
        nullptr,
        nullptr);
    return thisVar;
}

napi_value UdpOn(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {nullptr, nullptr};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("udpSocketInstances add udp socket pointer");
        return nullptr;
    }

    char eventTypeChars[OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH] = {0};
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], eventTypeChars, OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH - 1, &strLen));

    napi_ref callbackRef = nullptr;

    if (parameterCount == PARAMS_COUNT) {
        napi_create_reference(env, parameters[1], 1, &callbackRef);
    }
    napi_value result = nullptr;
    uint32_t eventType = GetSocketEventType(eventTypeChars);
    struct UdpEventListener listener = {env, eventType, true, callbackRef, objectInfo};
    if (eventType != NONE_EVENT_TYPE) {
        g_udpEventListenerList.push_back(listener);
        result = thisVar;
    }

    return thisVar;
}

napi_value UdpOff(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    Baseinfo *asyncContext = nullptr;
    UDPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));

    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = udpSocketInstances.find(objectInfo);
    if (requestKey != udpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("udpSocketInstances add udp socket pointer");
        return nullptr;
    }

    char eventTypeChars[OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH] = {0};
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], eventTypeChars, OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH - 1, &strLen));

    napi_ref callbackRef = nullptr;
    if (parameterCount == PARAMS_COUNT) {
        napi_create_reference(env, parameters[1], 1, &callbackRef);
    }
    napi_value result = nullptr;
    uint32_t eventType = GetSocketEventType(eventTypeChars);

    struct UdpEventListener listener = {env, eventType, true, callbackRef, objectInfo};
    if (eventType != NONE_EVENT_TYPE) {
        napi_delete_reference(env, listener.callbackRef_);
        g_udpEventListenerList.remove_if([objectInfo, eventType](UdpEventListener listener)->bool {
            return (listener.udpSocket_ == objectInfo && listener.eventType_ == eventType);
        });
        result = thisVar;
    }

    return thisVar;
}

static void EmitTcpEvent(TCPSocket *obj, const std::string &type, const std::string &message)
{
    int32_t eventType = GetSocketEventType(type);
    for (std::list<TcpEventListener>::iterator listenerIterator = g_tcpEventListenerList.begin();
        listenerIterator != g_tcpEventListenerList.end(); ++listenerIterator) {
        if (listenerIterator->tcpSocket_ == obj && listenerIterator->eventType_ == eventType) {
            napi_env env = listenerIterator->env_;
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            napi_value undefine = nullptr;
            napi_get_undefined(env, &undefine);
            napi_ref callbackRef = listenerIterator->callbackRef_;
            napi_value callbackFunc = nullptr;
            napi_get_reference_value(env, callbackRef, &callbackFunc);
            napi_value callbackValues[2] = {0};

            callbackValues[0] = NapiUtil::CreateUndefined(env);
            napi_value object = nullptr;
            napi_create_object(env, &object);
            NapiUtil::SetPropertyStringUtf8(env, object, type, message);

            callbackValues[1] = object;
            napi_value callbackResult = nullptr;
            napi_call_function(env, undefine, callbackFunc, PARAMS_COUNT, callbackValues, &callbackResult);
            napi_close_handle_scope(env, scope);
            napi_delete_reference(env, listenerIterator->callbackRef_);
            break;
        }
    }
}

static void NativeTcpBind(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeTcpBind formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    
    struct sockaddr_in addr;
    asyncContext->tcpSocket_->GetSocketInfo(addr, asyncContext);

    if (asyncContext->socketfd_ == INVALID_SOCKET && asyncContext->tcpSocket_ != nullptr) {
        if (asyncContext->family == IPV6) {
            asyncContext->socketfd_ = asyncContext->tcpSocket_->TcpSocket(AF_INET6, SOCK_STREAM, 0);
        } else {
            asyncContext->socketfd_ = asyncContext->tcpSocket_->TcpSocket(AF_INET, SOCK_STREAM, 0);
        }
        if (asyncContext->socketfd_ < 0) {
            return;
        }
    }

    if (!asyncContext->isBound && asyncContext->isClose && !asyncContext->isConnected) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpBind(asyncContext->socketfd_,
            (struct sockaddr *)&addr, sizeof(struct sockaddr));
    }
    if (asyncContext->errorCode_ >= 0) {
        asyncContext->isBound = true;
        asyncContext->resolved_ = true;
        asyncContext->errorString_.clear();
    } else {
        asyncContext->errorString_ = strerror(errno);
        std::string error = asyncContext->errorString_;
        EmitTcpEvent(asyncContext->tcpSocket_, "error",  error);
    }
}

static void TcpBindCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpBindCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode_);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, asyncContext->errorString_);
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }
    
    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeTcpConnect(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeTcpConnect formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);

    struct sockaddr_in addr;
    asyncContext->tcpSocket_->GetSocketInfo(addr, asyncContext);

    if (asyncContext->socketfd_ == INVALID_SOCKET && asyncContext->tcpSocket_ != nullptr) {
        if (asyncContext->family == IPV6) {
            asyncContext->socketfd_ = asyncContext->tcpSocket_->TcpSocket(AF_INET6, SOCK_STREAM, 0);
        } else {
            asyncContext->socketfd_ = asyncContext->tcpSocket_->TcpSocket(AF_INET, SOCK_STREAM, 0);
        }
        if (asyncContext->socketfd_ < 0) {
            return;
        }
    }

    if (!asyncContext->isBound && asyncContext->isClose && !asyncContext->isConnected) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpConnect(asyncContext->socketfd_,
            (struct sockaddr *)&addr, sizeof(struct sockaddr));
    }
    if (asyncContext->errorCode_ >= 0) {
        asyncContext->isConnected = true;
        asyncContext->isClose = false; // Once Connect Success ,the close state must false
        std::string connect("connect");
        EmitTcpEvent(asyncContext->tcpSocket_, "connect",  connect);
    } else {
        asyncContext->errorString_ = strerror(errno);
        std::string error = asyncContext->errorString_;
        EmitTcpEvent(asyncContext->tcpSocket_, "error",  error);
    }
}

static void TcpConnectCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpConnectCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode_);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, asyncContext->errorString_);
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeTcpSend(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeUdpBind formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);

    struct sockaddr_in addr;
    asyncContext->tcpSocket_->GetSocketInfo(addr, asyncContext);
    
    if (!asyncContext->isClose) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpSend(asyncContext->socketfd_,
            asyncContext->data.c_str(), asyncContext->data.size(), 0);
        std::string message("message");
        EmitTcpEvent(asyncContext->tcpSocket_, "message",  message);
    }  else {
        asyncContext->errorString_ = strerror(errno);
        std::string error = asyncContext->errorString_;
        EmitTcpEvent(asyncContext->tcpSocket_, "error",  error);
    }
}

static void TcpSendCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpSendCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode_);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, asyncContext->errorString_);
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeTcpClose(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeTcpClose formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);

    if (!asyncContext->isClose) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpClose(asyncContext->socketfd_);
    }

    if (asyncContext->errorCode_ >= 0) {
        std::string  close("close");
        EmitTcpEvent(asyncContext->tcpSocket_, "close",  close);
    } else {
        std::string error("error");
        EmitTcpEvent(asyncContext->tcpSocket_, "error",  error);
    }
}

static void TcpCloseCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpCloseCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode_);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "tcp socket close failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeTcpGetRemoteAddress(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeTcpGetState formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    asyncContext->resolved_ = true;
    asyncContext->errorString_.clear();
}

static void TcpGetRemoteAddressCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpGetRemoteAddressCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyStringUtf8(env, callbackValue, "ipAddress", asyncContext->ipAddress);
        NapiUtil::SetPropertyInt32(env, callbackValue, "family", asyncContext->family);
        NapiUtil::SetPropertyInt32(env, callbackValue, "port", asyncContext->port);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "tcp socket getRemoteAddress failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }
    
    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeTcpGetState(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeTcpGetState formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    asyncContext->resolved_ = true;
    asyncContext->errorString_.clear();
}

static void TcpGetStateCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpGetStateCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "isBound", asyncContext->isBound);
        NapiUtil::SetPropertyInt32(env, callbackValue, "isClose", asyncContext->isClose);
        NapiUtil::SetPropertyInt32(env, callbackValue, "isConnected", asyncContext->isConnected);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "tcp socket getState failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

static void NativeTcpSetExtraOptions(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeSetExtraOptionsSend formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);

    struct sockaddr_in addr;
    asyncContext->tcpSocket_->GetSocketInfo(addr, asyncContext);

    if (asyncContext->socketfd_ == INVALID_SOCKET && asyncContext->tcpSocket_ != nullptr) {
        if (asyncContext->family == IPV6) {
            asyncContext->socketfd_ = asyncContext->tcpSocket_->TcpSocket(AF_INET6, SOCK_STREAM, 0);
        } else {
            asyncContext->socketfd_ = asyncContext->tcpSocket_->TcpSocket(AF_INET, SOCK_STREAM, 0);
        }
        if (asyncContext->socketfd_ < 0) {
            return;
        }
    }

    bool keepAlive = asyncContext->tcpExtraOptions_.GetKeepAlive();
    if (keepAlive) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpSetSockopt(asyncContext->socketfd_,
            SOL_SOCKET, SO_KEEPALIVE, (void *) &keepAlive, sizeof (keepAlive));
    }

    bool OOBInline = asyncContext->tcpExtraOptions_.GetOOBInline();
    if (OOBInline) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpSetSockopt(asyncContext->socketfd_,
            SOL_SOCKET, SO_OOBINLINE, (void *) &OOBInline, sizeof (OOBInline));
    }

    bool TCPNoDelay = asyncContext->tcpExtraOptions_.GetTCPNoDelay();
    if (TCPNoDelay) {
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpSetSockopt(asyncContext->socketfd_,
            IPPROTO_TCP, TCP_NODELAY, (void *) &TCPNoDelay, sizeof (TCPNoDelay));
    }

    bool on = asyncContext->tcpExtraOptions_.GetSocketLingerOn();
    int32_t intLinger = asyncContext->tcpExtraOptions_.GetSocketLingerLinger();
    if (on) {
        struct linger linger;
        linger.l_onoff = on;
        linger.l_linger = intLinger;
        asyncContext->errorCode_ = asyncContext->tcpSocket_->TcpSetSockopt(asyncContext->socketfd_,
            SOL_SOCKET, SO_LINGER, (void *) &linger, sizeof (linger));
    }

    if (asyncContext->errorCode_ < 0) {
        std::string error = strerror(errno);
        EmitTcpEvent(asyncContext->tcpSocket_, "error",  error);
    } else {
        asyncContext->errorString_.clear();
        asyncContext->resolved_ = true;
        std::string message("message");
        EmitTcpEvent(asyncContext->tcpSocket_, "message",  message);
    }
}

static void TcpSetExtraOptionsCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("TcpSetExtraOptionsCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<TcpBaseContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        napi_create_object(env, &callbackValue);
        NapiUtil::SetPropertyInt32(env, callbackValue, "errorCode", asyncContext->errorCode_);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "tcp socket SetExtraOptions  failed");
    }
    if (asyncContext->callbackRef_ != nullptr) {
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(env, asyncContext->callbackRef_, &callbackFunc);
        napi_value callbackValues[] = {nullptr, nullptr};
        callbackValues[0] = asyncContext->resolved_ ? NapiUtil::CreateUndefined(env) : callbackValue;
        callbackValues[1] = asyncContext->resolved_ ? callbackValue : NapiUtil::CreateUndefined(env);
        napi_value undefined = nullptr;
        napi_value callback = nullptr;
        napi_value result = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef_, &callback));
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, undefined, callback, std::size(callbackValues), callbackValues, &result));
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, asyncContext->callbackRef_));
    } else if (asyncContext->deferred_ != nullptr) {
        if (asyncContext->resolved_) {
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }

    napi_delete_async_work(env, asyncContext->work_);
}

napi_value CreateTCPSocket(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    std::size_t argc = 2;
    napi_value args[2] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thisVar, nullptr));

    napi_value result = nullptr;
    napi_value argvArray[] = {nullptr};
    napi_new_instance(env, g_TcpSocketConstructorJS, 0, argvArray, &result);

    return result;
}

napi_value TcpBind(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpSocketInstances add udp socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpBind", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpBind, TcpBindCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Tcp bind Async Work Successful");
    }

    return result;
}

napi_value TcpConnect(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpSocketInstances add udp socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpConnect", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpConnect, TcpConnectCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Tcp connect Async Work Successful");
    }

    return result;
}

napi_value TcpSend(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpSocketInstances add udp socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpBind", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpSend, TcpSendCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp bind Async Work Successful");
    }

    return result;
}

napi_value TcpClose(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpClose not find socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    struct sockaddr_in addr;
    objectInfo->GetSocketInfo(addr, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpClose", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpClose, TcpCloseCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Udp close Async Work Successful");
    }

    return result;
}

napi_value TcpGetRemoteAddress(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpGetRemoteAddress not find socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpGetRemoteAddress", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpGetRemoteAddress, TcpGetRemoteAddressCallback,
            (void *)asyncContext, &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("GetRemoteAddress Async Work Successful");
    }

    return result;
}

napi_value TcpGetState(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpGetState not find  socket pointer");
        return nullptr;
    }

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpGetState", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpGetState, TcpGetStateCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("tcpGetState Async Work Successful");
    }

    return result;
}

napi_value TcpSetExtraOptions(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpSetExtraOptions not find socket pointer");
        return nullptr;
    }
    
    asyncContext->ipAddress = "255.255.255.255";
    asyncContext->broadcast = true;

    objectInfo->GetJSParameter(env, parameters, asyncContext);

    objectInfo->GetExOpGetJSParameter(env, parameters, asyncContext);

    if (parameterCount == PARAMS_COUNT) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        }
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "tcpSetExtraOptions", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeTcpSetExtraOptions, TcpSetExtraOptionsCallback,
            (void *)asyncContext, &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("tcpSetExtraOptions Async Work Successful");
    }
    return result;
}

napi_value TcpOn(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpSocketInstances add udp socket pointer");
        return nullptr;
    }

    char eventTypeChars[OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH] = { 0 };
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], eventTypeChars, OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH - 1, &strLen));

    napi_ref callbackRef = nullptr;

    if (parameterCount == PARAMS_COUNT) {
        napi_create_reference(env, parameters[1], 1, &callbackRef);
    }
    napi_value result = nullptr;
    uint32_t eventType = GetSocketEventType(eventTypeChars);

    struct TcpEventListener listener = {env, eventType, true, callbackRef, objectInfo};
    if (eventType != NONE_EVENT_TYPE) {
        g_tcpEventListenerList.push_back(listener);
        result = thisVar;
    }

    return thisVar;
}

napi_value TcpOff(napi_env env, napi_callback_info info)
{
    std::size_t parameterCount = 2;
    napi_value parameters[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &parameterCount, parameters, &thisVar, &data));

    TcpBaseContext *asyncContext = nullptr;
    TCPSocket *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);

    auto requestKey = tcpSocketInstances.find(objectInfo);
    if (requestKey != tcpSocketInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("tcpOff not find socket pointer");
        return nullptr;
    }

    char eventTypeChars[OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH] = {0};
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], eventTypeChars, OHOS::NetManagerStandard::EVENT_ARRAY_LENGTH - 1, &strLen));

    napi_ref callbackRef = nullptr;
    if (parameterCount == PARAMS_COUNT) {
        napi_create_reference(env, parameters[1], 1, &callbackRef);
    }
    napi_value result = nullptr;
    uint32_t eventType = GetSocketEventType(eventTypeChars);
    struct TcpEventListener listener = {env, eventType, true, callbackRef, objectInfo};
    if (eventType != NONE_EVENT_TYPE) {
        napi_delete_reference(env, listener.callbackRef_);
        g_tcpEventListenerList.remove_if([objectInfo, eventType](TcpEventListener listener)->bool {
            return (listener.tcpSocket_ == objectInfo && listener.eventType_ == eventType);
        });
        result = thisVar;
    }

    return thisVar;
}

napi_value TcpRequestConstructor(napi_env env, napi_callback_info info)
{
    std::size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));

    auto asyncContext = new TcpBaseContext();
    auto objectInfo = new TCPSocket(*asyncContext);

    if (tcpSocketInstances.size() <= MAX_SOCKET_OBJ_COUNT) {
        asyncContext->tcpSocket_ = objectInfo;
        tcpSocketInstances[objectInfo] = asyncContext;
    } else {
        return thisVar;
    }

    napi_wrap(env,
        thisVar,
        objectInfo,
        [](napi_env env, void *data, void *hint) {
            TCPSocket *objectInfo = (TCPSocket *)data;
            if (objectInfo) {
                delete objectInfo;
                objectInfo = nullptr;
            }
        },
        nullptr,
        nullptr);
    return thisVar;
}

EXTERN_C_START
/*
 * UDP Socket register
 */
napi_value RegisterUdpObjectFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("bind", UdpBind),
        DECLARE_NAPI_FUNCTION("connect", UdpConnect),
        DECLARE_NAPI_FUNCTION("send", UdpSend),
        DECLARE_NAPI_FUNCTION("close", UdpClose),
        DECLARE_NAPI_FUNCTION("getState", UdpGetState),
        DECLARE_NAPI_FUNCTION("setExtraOptions", UdpSetExtraOptions),
        DECLARE_NAPI_FUNCTION("on", UdpOn),
        DECLARE_NAPI_FUNCTION("off", UdpOff),
    };

    NAPI_CALL(env,
        napi_define_class(env,
            "UDPSocket",
            NAPI_AUTO_LENGTH,
            UdpRequestConstructor,
            nullptr,
            sizeof(desc) / sizeof(desc[0]),
            desc,
            &g_UdpSocketConstructorJS));
    return exports;
}

napi_value CreateUdpObjectFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("constructUDPSocketInstance", CreateUDPSocket),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return exports;
}

/*
 * TCP Socket register
 */
napi_value RegisterTcpObjectFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("bind", TcpBind),
        DECLARE_NAPI_FUNCTION("connect", TcpConnect),
        DECLARE_NAPI_FUNCTION("send", TcpSend),
        DECLARE_NAPI_FUNCTION("close", TcpClose),
        DECLARE_NAPI_FUNCTION("getRemoteAddress", TcpGetRemoteAddress),
        DECLARE_NAPI_FUNCTION("getState", TcpGetState),
        DECLARE_NAPI_FUNCTION("setExtraOptions", TcpSetExtraOptions),
        DECLARE_NAPI_FUNCTION("on", TcpOn),
        DECLARE_NAPI_FUNCTION("off", TcpOff),
    };

    NAPI_CALL(env,
        napi_define_class(env,
            "TCPSocket",
            NAPI_AUTO_LENGTH,
            TcpRequestConstructor,
            nullptr,
            sizeof(desc) / sizeof(desc[0]),
            desc,
            &g_TcpSocketConstructorJS));
    return exports;
}

napi_value CreateTcpObjectFunction(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("constructTCPSocketInstance", CreateTCPSocket),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    return exports;
}
/*
 * Module export function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    RegisterUdpObjectFunction(env, exports);
    CreateUdpObjectFunction(env, exports);
    RegisterTcpObjectFunction(env, exports);
    CreateTcpObjectFunction(env, exports);

    return exports;
}

EXTERN_C_END

static napi_module g_socketModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "net.socket",
    .nm_priv = ((void *)0),
    .reserved = {(void *)0},
};
/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterSocketModule(void)
{
    napi_module_register(&g_socketModule);
}
} // namespace NetManagerStandard
} // namespace OHOS