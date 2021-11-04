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

#include "http_napi.h"

#include <algorithm>
#include <vector>
#include <string>

namespace OHOS {
namespace NetManagerStandard {

static int32_t FindMethodIndex(const std::string &key)
{
    std::vector<std::string> methodVector = {
        "OPTIONS ", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"};

    int32_t result = -1;
    std::vector<std::string>::iterator it = find(methodVector.begin(), methodVector.end(), key);
    if (it == methodVector.end()) {
        NETMGR_LOGE("Get Method enum error");
    } else {
        result = distance(methodVector.begin(), it);
    }
    return result;
}

static void GetRequestInfo(napi_env env, napi_value objValue, HttpRequestOptionsContext *asyncContext)
{
    enum RequestMethod method = GET;
    bool result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_string, "method");
    if (result) {
        method = static_cast<RequestMethod>(FindMethodIndex(NapiUtil::GetStringProperty(env, objValue, "method")));
    }
    asyncContext->SetRequestMethod(method);

    std::string extraData = "";
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_string, "extraData");
    if (result) {
        extraData = NapiUtil::GetStringProperty(env, objValue, "extraData");
    }
    asyncContext->SetExtraData(extraData);

    std::string header = std::string("'content-type': 'application/json'");
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_string, "header");
    if (result) {
        header = NapiUtil::GetStringProperty(env, objValue, "header");
    }
    asyncContext->SetHeader(header);

    int32_t readTimeout = 60;
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_number, "readTimeout");
    if (result) {
        readTimeout = NapiUtil::GetIntProperty(env, objValue, "readTimeout");
    }
    asyncContext->SetReadTimeout(readTimeout);

    int32_t connectTimeout = 60;
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_number, "connectTimeout");
    if (result) {
        connectTimeout = NapiUtil::GetIntProperty(env, objValue, "connectTimeout");
    }
    asyncContext->SetConnectTimeout(connectTimeout);

    int32_t ifModifiedSince = 0;
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_number, "ifModifiedSince");
    if (result) {
        ifModifiedSince = NapiUtil::GetIntProperty(env, objValue, "ifModifiedSince");
    }
    asyncContext->SetIfModifiedSince(ifModifiedSince);

    bool usingCache = true;
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_number, "usingCache");
    if (result) {
        usingCache = NapiUtil::GetIntProperty(env, objValue, "usingCache");
    }
    asyncContext->SetUsingCache(usingCache);

    int32_t fixedLengthStreamingMode = -1;
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_number, "fixedLengthStreamingMode");
    if (result) {
        fixedLengthStreamingMode = NapiUtil::GetIntProperty(env, objValue, "fixedLengthStreamingMode");
    }
    asyncContext->SetFixedLengthStreamingMode(fixedLengthStreamingMode);

    std::string caFile = std::string("/etc/ssl/cacert.pem");
    result = NapiUtil::HasNamedTypeProperty(env, objValue, napi_string, "caFile");
    if (result) {
        caFile = NapiUtil::GetStringProperty(env, objValue, "caFile");
    }
    asyncContext->SetCaFile(caFile);
}

/*
 * native request
 */
static void NativeRequest(napi_env env, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("NativeRequest formal parameter data is null");
        return;
    }
    auto asyncContext = static_cast<HttpRequestOptionsContext *>(data);
    asyncContext->resolved_ = asyncContext->httpRequestInfo_->NativeRequest(asyncContext);
}

/*
 * request callback
 */
static void RequestCallback(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        NETMGR_LOGE("RequestCallback data parameter address is nullptr");
        return;
    }
    auto asyncContext = static_cast<HttpRequestOptionsContext *>(data);
    napi_value callbackValue = nullptr;

    if (asyncContext->resolved_) {
        /*
        Assemble return values into object  callbackValue
        */
        napi_create_object(env, &callbackValue);
        std::string result = asyncContext->GetResponseData().GetResult();
        ResponseCode responseCode = asyncContext->GetResponseData().GetResponseCode();
        std::string header = asyncContext->GetResponseData().GetHeader();
        std::vector<std::string> cookie;

        NapiUtil::SetPropertyStringUtf8(env, callbackValue, "result", result);
        NapiUtil::SetPropertyInt32(env, callbackValue, "responseCode", responseCode);
        NapiUtil::SetPropertyStringUtf8(env, callbackValue, "header", header);
        NapiUtil::SetPropertyArray(env, callbackValue, "cookie", cookie);
    } else {
        callbackValue = NapiUtil::CreateErrorMessage(env, "Request failed");
        NETMGR_LOGE("Request failed");
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
            NETMGR_LOGD("Resolves  deferred");
            napi_resolve_deferred(env, asyncContext->deferred_, callbackValue);
        } else {
            NETMGR_LOGD("Rejects  deferred");
            napi_reject_deferred(env, asyncContext->deferred_, callbackValue);
        }
    }
    napi_delete_async_work(env, asyncContext->work_);
}

napi_value CreateHttp(napi_env env, napi_callback_info info)
{
    size_t argc = CREATE_MAX_PARA;
    napi_value argv[CREATE_MAX_PARA];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    napi_value result = nullptr;
    napi_value argvArray[] = {nullptr};
    napi_new_instance(env, g_HttpRequestConstructorJS, 0, argvArray, &result);

    return result;
}

/*
 * http Request interface
 */
napi_value Request(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t paraCount = 3;
    napi_value parameters[3] = {nullptr, nullptr, nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &paraCount, parameters, &thisVar, nullptr));
    NAPI_ASSERT(env, NapiUtil::MatchHttpRequestDataParameters(env, parameters, paraCount), "type mismatch");

    HttpRequest *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    if (objectInfo == nullptr) {
        NETMGR_LOGE("Http Request address is null");
        return nullptr;
    }
    NETMGR_LOGD("Http address is %{public}p", objectInfo);

    char url[OHOS::NetManagerStandard::URL_ARRAY_LENGTH] = {0};
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], url, OHOS::NetManagerStandard::URL_ARRAY_LENGTH - 1, &strLen));

    HttpRequestOptionsContext *asyncContext = nullptr;
    {
        auto requestKey = httpRequestInstances.find(objectInfo);
        if (requestKey != httpRequestInstances.end()) {
            asyncContext = requestKey->second;
        } else {
            NETMGR_LOGE("httpRequestInstances add HttpRequest pointer");
            return nullptr;
        }
    }

    asyncContext->SetUrl(std::string(url, strLen));

    if (paraCount == 2) {
        if (NapiUtil::MatchValueType(env, parameters[1], napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, parameters[1], 1, &(asyncContext->callbackRef_)));
        } else if (NapiUtil::MatchValueType(env, parameters[1], napi_object)) {
            GetRequestInfo(env, parameters[1], asyncContext);
        }
    } else if (paraCount == 3 && NapiUtil::MatchValueType(env, parameters[1], napi_object)) {
        GetRequestInfo(env, parameters[2], asyncContext);
        NAPI_CALL(env, napi_create_reference(env, parameters[2], 1, &(asyncContext->callbackRef_)));
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef_ == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred_, &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "Request", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env,
        napi_create_async_work(env, nullptr, resourceName, NativeRequest, RequestCallback, (void *)asyncContext,
            &(asyncContext->work_)));
    napi_status resultStatus = napi_queue_async_work(env, asyncContext->work_);
    if (resultStatus == napi_ok) {
        NETMGR_LOGD("Queue Async Work Successful");
    }
    return result;
}

/*
 * http Destroy interface
 */
napi_value Destroy(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t paraCount = 2;
    napi_value parameters[2] = {nullptr, nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &paraCount, parameters, &thisVar, nullptr));
    NAPI_ASSERT(env, NapiUtil::MatchHttpOnDataParameters(env, parameters, paraCount), "type mismatch");

    HttpRequest *objectInfo = nullptr;
    napi_valuetype valuetype;

    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    if (objectInfo == nullptr) {
        NETMGR_LOGE("Destroy address is null");
        return nullptr;
    }

    HttpRequestOptionsContext *asyncContext = nullptr;
    auto requestKey = httpRequestInstances.find(objectInfo);
    if (requestKey != httpRequestInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("Destroy add HttpRequest pointer");
        return thisVar;
    }
    HttpRequest *httpRequest = requestKey->first;
    httpRequestInstances.erase(requestKey);
    g_eventListenerList.remove_if([objectInfo](EventListener listener)->bool {
        napi_delete_reference(listener.env_, listener.callbackRef_);
        return listener.httpRequestInfo_ == objectInfo;
    });

    delete asyncContext;
    delete httpRequest;

    return thisVar;
}

bool MatchEventType(const std::string &type, const std::string &goalTypeStr)
{
    return goalTypeStr.compare(type) == 0;
}

int32_t GetEventType(const std::string &type)
{
    if (MatchEventType(type, HEADER_RECEIVE)) {
        return LISTEN_HTTP_WORK_STATE;
    }
    return NONE_EVENT_TYPE;
}

/*
 * http On interface
 */
napi_value On(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t paraCount = 2;
    napi_value parameters[2] = {nullptr, nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &paraCount, parameters, &thisVar, nullptr));
    NAPI_ASSERT(env, NapiUtil::MatchHttpOnDataParameters(env, parameters, paraCount), "type mismatch");

    HttpRequest *objectInfo = nullptr;
    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    if (objectInfo == nullptr) {
        NETMGR_LOGE("On address is null");
        return nullptr;
    }

    HttpRequestOptionsContext *asyncContext = nullptr;
    auto requestKey = httpRequestInstances.find(objectInfo);
    if (requestKey != httpRequestInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("On add HttpRequest pointer");
        return thisVar;
    }

    char eventTypeChars[OHOS::NetManagerStandard::URL_ARRAY_LENGTH] = {0};
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], eventTypeChars, OHOS::NetManagerStandard::URL_ARRAY_LENGTH - 1, &strLen));
    NETMGR_LOGD("On Start napi_get_cb_info %{public}s, %{public}d", eventTypeChars, (int32_t)strLen);
    napi_ref callbackRef = nullptr;

    if (paraCount == 2) {
        napi_create_reference(env, parameters[1], 1, &callbackRef);
    }
    napi_value result = nullptr;
    uint32_t eventType = GetEventType(eventTypeChars);
    struct EventListener listener = {env, eventType, true, callbackRef, objectInfo};
    if (eventType != NONE_EVENT_TYPE) {
        g_eventListenerList.push_back(listener);
        result = thisVar;
        NETMGR_LOGD("ON Finish = %{public}d", (int32_t)g_eventListenerList.size());
    }

    return thisVar;
}

/*
 * http Off interface
 */
napi_value Off(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t paraCount = 2;
    napi_value parameters[2] = {nullptr, nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &paraCount, parameters, &thisVar, nullptr));
    NAPI_ASSERT(env, NapiUtil::MatchHttpOnDataParameters(env, parameters, paraCount), "type mismatch");

    HttpRequest *objectInfo = nullptr;
    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, thisVar, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_object, "Wrong argument type for arg0. Subscribe expected.");
    napi_unwrap(env, thisVar, (void **)&objectInfo);
    if (objectInfo == nullptr) {
        NETMGR_LOGE("Off address is null");
        return nullptr;
    }

    HttpRequestOptionsContext *asyncContext = nullptr;
    auto requestKey = httpRequestInstances.find(objectInfo);
    if (requestKey != httpRequestInstances.end()) {
        asyncContext = requestKey->second;
    } else {
        NETMGR_LOGE("Off add HttpRequest pointer");
        return thisVar;
    }

    char eventTypeChars[OHOS::NetManagerStandard::URL_ARRAY_LENGTH] = {0};
    size_t strLen = 0;

    NAPI_CALL(env,
        napi_get_value_string_utf8(
            env, parameters[0], eventTypeChars, OHOS::NetManagerStandard::URL_ARRAY_LENGTH - 1, &strLen));

    napi_ref callbackRef = nullptr;
    if (paraCount == 2) {
        napi_create_reference(env, parameters[1], 1, &callbackRef);
    }
    napi_value result = nullptr;
    uint32_t eventType = GetEventType(eventTypeChars);
    struct EventListener listener = {env, eventType, true, callbackRef, objectInfo};
    if (eventType != NONE_EVENT_TYPE) {
        napi_delete_reference(env, listener.callbackRef_);
        g_eventListenerList.remove_if([objectInfo](EventListener listener)->bool {
            return listener.httpRequestInfo_ == objectInfo;
        });
        result = thisVar;
    }

    return thisVar;
}

napi_value HttpRequestConstructor(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    auto objectInfo = new HttpRequest();
    auto asyncContext = new HttpRequestOptionsContext();
    if (httpRequestInstances.size() <= MAX_HTTP_OBJ_COUNT) {
        asyncContext->httpRequestInfo_ = objectInfo;
        httpRequestInstances[objectInfo] = asyncContext;
    } else {
        NETMGR_LOGE("HTTP object count max 100");
        return thisVar;
    }
    napi_wrap(
        env, thisVar, objectInfo,
        [](napi_env env, void *data, void *hint) {
            HttpRequest *objectInfo = (HttpRequest *)data;
            if (objectInfo) {
                delete objectInfo;
                objectInfo = nullptr;
            }
        },
        nullptr, nullptr);

    return thisVar;
}

EXTERN_C_START
napi_value HttpFunctionInit(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("request", Request),
        DECLARE_NAPI_FUNCTION("destroy", Destroy),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };
    NAPI_CALL(env,
        napi_define_class(env, "HttpRequest", NAPI_AUTO_LENGTH, HttpRequestConstructor, nullptr,
            sizeof(properties) / sizeof(*properties), properties, &g_HttpRequestConstructorJS));

    return exports;
}

napi_value HttpPropertyInit(napi_env env, napi_value exports)
{
    napi_value ok = nullptr;
    napi_value created = nullptr;
    napi_value accepted = nullptr;
    napi_value not_authoritative = nullptr;
    napi_value no_content = nullptr;
    napi_value reset = nullptr;
    napi_value partial = nullptr;
    napi_value mult_choice = nullptr;
    napi_value moved_perm = nullptr;
    napi_value moved_temp = nullptr;
    napi_value see_other = nullptr;
    napi_value not_modified = nullptr;
    napi_value use_proxy = nullptr;
    napi_value bad_request = nullptr;
    napi_value unauthorized = nullptr;
    napi_value payment_required = nullptr;
    napi_value forbidden = nullptr;
    napi_value not_found = nullptr;
    napi_value bad_method = nullptr;
    napi_value not_acceptable = nullptr;
    napi_value proxy_auth = nullptr;
    napi_value client_timeou = nullptr;
    napi_value conflict = nullptr;
    napi_value gone = nullptr;
    napi_value length_required = nullptr;
    napi_value precon_failed = nullptr;
    napi_value entity_too_large = nullptr;
    napi_value req_too_long = nullptr;
    napi_value unsupported = nullptr;
    napi_value internal = nullptr;
    napi_value not_implemented = nullptr;
    napi_value bad_gateway = nullptr;
    napi_value unavailable = nullptr;
    napi_value gateway_timeout = nullptr;
    napi_value version = nullptr;

    napi_create_int32(env, OK, &ok);
    napi_create_int32(env, CREATED, &created);
    napi_create_int32(env, ACCEPTED, &accepted);
    napi_create_int32(env, NOT_AUTHORITATIVE, &not_authoritative);
    napi_create_int32(env, NO_CONTENT, &no_content);
    napi_create_int32(env, RESET, &reset);
    napi_create_int32(env, PARTIAL, &partial);
    napi_create_int32(env, MULT_CHOICE, &mult_choice);
    napi_create_int32(env, MOVED_PERM, &moved_perm);
    napi_create_int32(env, MOVED_TEMP, &moved_temp);
    napi_create_int32(env, SEE_OTHER, &see_other);
    napi_create_int32(env, NOT_MODIFIED, &not_modified);
    napi_create_int32(env, USE_PROXY, &use_proxy);
    napi_create_int32(env, BAD_REQUEST, &bad_request);
    napi_create_int32(env, UNAUTHORIZED, &unauthorized);
    napi_create_int32(env, PAYMENT_REQUIRED, &payment_required);
    napi_create_int32(env, FORBIDDEN, &forbidden);
    napi_create_int32(env, NOT_FOUND, &not_found);
    napi_create_int32(env, BAD_METHOD, &bad_method);
    napi_create_int32(env, NOT_ACCEPTABLE, &not_acceptable);
    napi_create_int32(env, PROXY_AUTH, &proxy_auth);
    napi_create_int32(env, CLIENT_TIMEOUT, &client_timeou);
    napi_create_int32(env, CONFLICT, &conflict);
    napi_create_int32(env, GONE, &gone);
    napi_create_int32(env, LENGTH_REQUIRED, &length_required);
    napi_create_int32(env, PRECON_FAILED, &precon_failed);
    napi_create_int32(env, ENTITY_TOO_LARGE, &entity_too_large);
    napi_create_int32(env, REQ_TOO_LONG, &req_too_long);
    napi_create_int32(env, UNSUPPORTED_TYPE, &unsupported);
    napi_create_int32(env, INTERNAL_ERROR, &internal);
    napi_create_int32(env, NOT_IMPLEMENTED, &not_implemented);
    napi_create_int32(env, BAD_GATEWAY, &bad_gateway);
    napi_create_int32(env, UNAVAILABLE, &unavailable);
    napi_create_int32(env, GATEWAY_TIMEOUT, &gateway_timeout);
    napi_create_int32(env, VERSION, &version);

    napi_property_descriptor desc[] = {DECLARE_NAPI_FUNCTION("createHttp", CreateHttp),
        DECLARE_NAPI_STATIC_PROPERTY("OK", ok), DECLARE_NAPI_STATIC_PROPERTY("CREATED", created),
        DECLARE_NAPI_STATIC_PROPERTY("ACCEPTED", accepted),
        DECLARE_NAPI_STATIC_PROPERTY("NOT_AUTHORITATIVE", not_authoritative),
        DECLARE_NAPI_STATIC_PROPERTY("NO_CONTENT", no_content), DECLARE_NAPI_STATIC_PROPERTY("RESET", reset),
        DECLARE_NAPI_STATIC_PROPERTY("PARTIAL", partial), DECLARE_NAPI_STATIC_PROPERTY("MULT_CHOICE", mult_choice),
        DECLARE_NAPI_STATIC_PROPERTY("MOVED_PERM", moved_perm),
        DECLARE_NAPI_STATIC_PROPERTY("MOVED_TEMP", moved_temp),
        DECLARE_NAPI_STATIC_PROPERTY("SEE_OTHER", see_other),
        DECLARE_NAPI_STATIC_PROPERTY("NOT_MODIFIED", not_modified),
        DECLARE_NAPI_STATIC_PROPERTY("USE_PROXY", use_proxy),
        DECLARE_NAPI_STATIC_PROPERTY("BAD_REQUEST", bad_request),
        DECLARE_NAPI_STATIC_PROPERTY("UNAUTHORIZED", unauthorized),
        DECLARE_NAPI_STATIC_PROPERTY("PAYMENT_REQUIRED", payment_required),
        DECLARE_NAPI_STATIC_PROPERTY("FORBIDDEN", forbidden), DECLARE_NAPI_STATIC_PROPERTY("NOT_FOUND", not_found),
        DECLARE_NAPI_STATIC_PROPERTY("BAD_METHOD", bad_method),
        DECLARE_NAPI_STATIC_PROPERTY("NOT_ACCEPTABLE", not_acceptable),
        DECLARE_NAPI_STATIC_PROPERTY("PROXY_AUTH", proxy_auth),
        DECLARE_NAPI_STATIC_PROPERTY("CLIENT_TIMEOUT", client_timeou),
        DECLARE_NAPI_STATIC_PROPERTY("CONFLICT", conflict), DECLARE_NAPI_STATIC_PROPERTY("GONE", gone),
        DECLARE_NAPI_STATIC_PROPERTY("LENGTH_REQUIRED", length_required),
        DECLARE_NAPI_STATIC_PROPERTY("PRECON_FAILED", precon_failed),
        DECLARE_NAPI_STATIC_PROPERTY("ENTITY_TOO_LARGE", entity_too_large),
        DECLARE_NAPI_STATIC_PROPERTY("REQ_TOO_LONG", req_too_long),
        DECLARE_NAPI_STATIC_PROPERTY("UNSUPPORTED_TYPE", unsupported),
        DECLARE_NAPI_STATIC_PROPERTY("INTERNAL_ERROR", internal),
        DECLARE_NAPI_STATIC_PROPERTY("NOT_IMPLEMENTED", not_implemented),
        DECLARE_NAPI_STATIC_PROPERTY("BAD_GATEWAY", bad_gateway),
        DECLARE_NAPI_STATIC_PROPERTY("UNAVAILABLE", unavailable),
        DECLARE_NAPI_STATIC_PROPERTY("GATEWAY_TIMEOUT", gateway_timeout),
        DECLARE_NAPI_STATIC_PROPERTY("VERSION", version)};

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    NETMGR_LOGD("HttpPropertyInit End");
    return exports;
}

/*
 * Module export function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    /*
     * Propertise define
     */
    HttpFunctionInit(env, exports);
    HttpPropertyInit(env, exports);

    return exports;
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module g_httpModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "net.http",
    .nm_priv = ((void *)0),
    .reserved = {(void *)0},
};

extern "C" __attribute__((constructor)) void RegisterHttpModule(void)
{
    napi_module_register(&g_httpModule);
}
} // namespace NetManagerStandard
} // namespace OHOS
