/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "http_exec.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <thread>
#include <unistd.h>
#include <pthread.h>
#ifdef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#endif
#if HAS_NETMANAGER_BASE
#include <netdb.h>
#endif

#ifdef HTTP_PROXY_ENABLE
#include "parameter.h"
#endif
#ifdef HAS_NETMANAGER_BASE
#include "http_proxy.h"
#include "net_conn_client.h"
#endif
#include "base64_utils.h"
#include "cache_proxy.h"
#include "constant.h"
#if HAS_NETMANAGER_BASE
#include "epoll_request_handler.h"
#endif
#include "event_list.h"
#if HAS_NETMANAGER_BASE
#include "hitrace_meter.h"
#endif
#include "http_async_work.h"
#include "http_time.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "secure_char.h"

#define NETSTACK_CURL_EASY_SET_OPTION(handle, opt, data, asyncContext)                                   \
    do {                                                                                                 \
        CURLcode result = curl_easy_setopt(handle, opt, data);                                           \
        if (result != CURLE_OK) {                                                                        \
            const char *err = curl_easy_strerror(result);                                                \
            NETSTACK_LOGE("Failed to set option: %{public}s, %{public}s %{public}d", #opt, err, result); \
            (asyncContext)->SetErrorCode(result);                                                        \
            return false;                                                                                \
        }                                                                                                \
    } while (0)

namespace OHOS::NetStack::Http {
#if !HAS_NETMANAGER_BASE
static constexpr int CURL_TIMEOUT_MS = 20;
static constexpr int CONDITION_TIMEOUT_S = 3600;
static constexpr int CURL_MAX_WAIT_MSECS = 10;
static constexpr int CURL_HANDLE_NUM = 10;
#endif
static constexpr const uint32_t EVENT_PARAM_ZERO = 0;
static constexpr const uint32_t EVENT_PARAM_ONE = 1;
static constexpr const uint32_t EVENT_PARAM_TWO = 2;
static constexpr const char *TLS12_SECURITY_CIPHER_SUITE = R"(DEFAULT:!eNULL:!EXPORT)";
#if !HAS_NETMANAGER_BASE
static constexpr const char *HTTP_TASK_RUN_THREAD = "OS_NET_TaskHttp";
static constexpr const char *HTTP_CLIENT_TASK_THREAD = "OS_NET_HttpJs";
#endif

#if HAS_NETMANAGER_BASE
static constexpr const char *HTTP_REQ_TRACE_NAME = "HttpRequest";
#endif

#ifdef HTTP_MULTIPATH_CERT_ENABLE
static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;
static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";
static constexpr const char *USER_CERT_ROOT_PATH = "/data/certificates/user_cacerts/0/";
static const std::string USER_CERT_PATH = BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR);
static constexpr int32_t SYSPARA_MAX_SIZE = 128;
static constexpr const char *DEFAULT_HTTP_PROXY_HOST = "NONE";
static constexpr const char *DEFAULT_HTTP_PROXY_PORT = "0";
static constexpr const char *DEFAULT_HTTP_PROXY_EXCLUSION_LIST = "NONE";
static constexpr const char *HTTP_PROXY_HOST_KEY = "persist.netmanager_base.http_proxy.host";
static constexpr const char *HTTP_PROXY_PORT_KEY = "persist.netmanager_base.http_proxy.port";
static constexpr const char *HTTP_PROXY_EXCLUSIONS_KEY = "persist.netmanager_base.http_proxy.exclusion_list";
#endif

static void RequestContextDeleter(RequestContext *context)
{
    context->DeleteReference();
    delete context;
    context = nullptr;
}

static void AsyncWorkRequestInStreamCallback(napi_env env, napi_status status, void *data)
{
    if (status != napi_ok) {
        return;
    }
    std::unique_ptr<RequestContext, decltype(&RequestContextDeleter)> context(static_cast<RequestContext *>(data),
                                                                              RequestContextDeleter);
    napi_value undefined = NapiUtils::GetUndefined(env);
    napi_value argv[EVENT_PARAM_TWO] = {nullptr};
    if (context->IsParseOK() && context->IsExecOK()) {
        context->Emit(ON_DATA_END, std::make_pair(undefined, undefined));
        argv[EVENT_PARAM_ZERO] = undefined;
        argv[EVENT_PARAM_ONE] = HttpExec::RequestInStreamCallback(context.get());
        if (argv[EVENT_PARAM_ONE] == nullptr) {
            return;
        }
    } else {
        argv[EVENT_PARAM_ZERO] =
            NapiUtils::CreateErrorMessage(env, context->GetErrorCode(), context->GetErrorMessage());
        if (argv[EVENT_PARAM_ZERO] == nullptr) {
            return;
        }

        argv[EVENT_PARAM_ONE] = undefined;
    }

    if (context->GetDeferred() != nullptr) {
        if (context->IsExecOK()) {
            napi_resolve_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ONE]);
        } else {
            napi_reject_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ZERO]);
        }
        return;
    }
    napi_value func = context->GetCallback();
    if (NapiUtils::GetValueType(env, func) == napi_function) {
        (void)NapiUtils::CallFunction(env, undefined, func, EVENT_PARAM_TWO, argv);
    }
}

static void AsyncWorkRequestCallback(napi_env env, napi_status status, void *data)
{
    if (status != napi_ok) {
        return;
    }
    std::unique_ptr<RequestContext, decltype(&RequestContextDeleter)> context(static_cast<RequestContext *>(data),
                                                                              RequestContextDeleter);
    napi_value argv[EVENT_PARAM_TWO] = {nullptr};
    if (context->IsParseOK() && context->IsExecOK()) {
        argv[EVENT_PARAM_ZERO] = NapiUtils::GetUndefined(env);
        argv[EVENT_PARAM_ONE] = HttpExec::RequestCallback(context.get());
        if (argv[EVENT_PARAM_ONE] == nullptr) {
            return;
        }
    } else {
        argv[EVENT_PARAM_ZERO] =
            NapiUtils::CreateErrorMessage(env, context->GetErrorCode(), context->GetErrorMessage());
        if (argv[EVENT_PARAM_ZERO] == nullptr) {
            return;
        }

        argv[EVENT_PARAM_ONE] = NapiUtils::GetUndefined(env);
    }
    napi_value undefined = NapiUtils::GetUndefined(env);
    if (context->GetDeferred() != nullptr) {
        if (context->IsExecOK()) {
            napi_resolve_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ONE]);
        } else {
            napi_reject_deferred(env, context->GetDeferred(), argv[EVENT_PARAM_ZERO]);
        }
        return;
    }
    napi_value func = context->GetCallback();
    if (NapiUtils::GetValueType(env, func) == napi_function) {
        (void)NapiUtils::CallFunction(env, undefined, func, EVENT_PARAM_TWO, argv);
    }
}

bool HttpExec::AddCurlHandle(CURL *handle, RequestContext *context)
{
#if HAS_NETMANAGER_BASE
    if (handle == nullptr) {
#else
    if (handle == nullptr || staticVariable_.curlMulti == nullptr) {
#endif
        NETSTACK_LOGE("handle nullptr");
        return false;
    }

#if HAS_NETMANAGER_BASE
    StartAsyncTrace(HITRACE_TAG_NET, HTTP_REQ_TRACE_NAME, context->GetTaskId());
    SetServerSSLCertOption(handle, context);

    static HttpOverCurl::EpollRequestHandler requestHandler;

    static auto startedCallback = +[](CURL *easyHandle, void *opaqueData) {
        char *url = nullptr;
        curl_easy_getinfo(easyHandle, CURLINFO_EFFECTIVE_URL, &url);
    };

    static auto responseCallback = +[](CURLMsg *curlMessage, void *opaqueData) {
        auto context = static_cast<RequestContext *>(opaqueData);
        HttpExec::HandleCurlData(curlMessage, context);
        if (curlMessage->easy_handle) {
            (void)curl_easy_cleanup(curlMessage->easy_handle);
        }
    };

    requestHandler.Process(handle, startedCallback, responseCallback, context);
    return true;
#else
    std::thread([context, handle] {
        std::lock_guard guard(staticVariable_.curlMultiMutex);
        // Do SetServerSSLCertOption here to avoid blocking the main thread.
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
        pthread_setname_np(HTTP_CLIENT_TASK_THREAD);
#else
        pthread_setname_np(pthread_self(), HTTP_CLIENT_TASK_THREAD);
#endif
        SetServerSSLCertOption(handle, context);
        staticVariable_.infoQueue.emplace(context, handle);
        staticVariable_.conditionVariable.notify_all();
    }).detach();

    return true;
#endif
}

#if !HAS_NETMANAGER_BASE
HttpExec::StaticVariable HttpExec::staticVariable_; /* NOLINT */
#endif

bool HttpExec::RequestWithoutCache(RequestContext *context)
{
#if !HAS_NETMANAGER_BASE
    if (!staticVariable_.initialized) {
        NETSTACK_LOGE("curl not init");
        return false;
    }
#endif

    auto handle = curl_easy_init();
    if (!handle) {
        NETSTACK_LOGE("Failed to create fetch task");
        return false;
    }

#if HAS_NETMANAGER_BASE
    NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_PRIVATE, context, context);
#endif

    std::vector<std::string> vec;
    std::for_each(context->options.GetHeader().begin(), context->options.GetHeader().end(),
                  [&vec](const std::pair<std::string, std::string> &p) {
                      if (!p.second.empty()) {
                          vec.emplace_back(p.first + HttpConstant::HTTP_HEADER_SEPARATOR + p.second);
                      } else {
                          vec.emplace_back(p.first + HttpConstant::HTTP_HEADER_BLANK_SEPARATOR);
                      }
                  });
    context->SetCurlHeaderList(MakeHeaders(vec));

    if (!SetOption(handle, context, context->GetCurlHeaderList())) {
        NETSTACK_LOGE("set option failed");
        return false;
    }

    context->response.SetRequestTime(HttpTime::GetNowTimeGMT());

    if (!AddCurlHandle(handle, context)) {
        NETSTACK_LOGE("add handle failed");
        return false;
    }

    return true;
}

bool HttpExec::GetCurlDataFromHandle(CURL *handle, RequestContext *context, CURLMSG curlMsg, CURLcode result)
{
    if (curlMsg != CURLMSG_DONE) {
        NETSTACK_LOGE("CURLMSG %{public}s", std::to_string(curlMsg).c_str());
        context->SetErrorCode(NapiUtils::NETSTACK_NAPI_INTERNAL_ERROR);
        return false;
    }

    if (result != CURLE_OK) {
        context->SetErrorCode(result);
        NETSTACK_LOGE("CURLcode result %{public}s", std::to_string(result).c_str());
        return false;
    }

    context->response.SetResponseTime(HttpTime::GetNowTimeGMT());

    int64_t responseCode;
    CURLcode code = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &responseCode);
    if (code != CURLE_OK) {
        context->SetErrorCode(code);
        return false;
    }
    context->response.SetResponseCode(responseCode);
    if (context->response.GetResponseCode() == static_cast<uint32_t>(ResponseCode::NOT_MODIFIED)) {
        NETSTACK_LOGI("cache is NOT_MODIFIED, we use the cache");
        context->SetResponseByCache();
        return true;
    }
    NETSTACK_LOGD("responseCode is %{public}s", std::to_string(responseCode).c_str());

    struct curl_slist *cookies = nullptr;
    code = curl_easy_getinfo(handle, CURLINFO_COOKIELIST, &cookies);
    if (code != CURLE_OK) {
        context->SetErrorCode(code);
        return false;
    }

    std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)> cookiesHandle(cookies, curl_slist_free_all);
    while (cookies) {
        context->response.AppendCookies(cookies->data, strlen(cookies->data));
        if (cookies->next != nullptr) {
            context->response.AppendCookies(HttpConstant::HTTP_LINE_SEPARATOR,
                                            strlen(HttpConstant::HTTP_LINE_SEPARATOR));
        }
        cookies = cookies->next;
    }
    return true;
}

double HttpExec::GetTimingFromCurl(CURL *handle, CURLINFO info)
{
    time_t timing;
    CURLcode result = curl_easy_getinfo(handle, info, &timing);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to get timing: %{public}d, %{public}s", info, curl_easy_strerror(result));
        return 0;
    }
    return Timing::TimeUtils::Microseconds2Milliseconds(timing);
}

curl_off_t HttpExec::GetSizeFromCurl(CURL *handle, RequestContext *context)
{
    auto info = CURLINFO_SIZE_DOWNLOAD_T;
    auto method = context->options.GetMethod();
    NETSTACK_LOGD("method is %{public}s", method.c_str());
    if (MethodForPost(method)) {
        info = CURLINFO_SIZE_UPLOAD_T;
    }

    curl_off_t size = 0;
    CURLcode result = curl_easy_getinfo(handle, info, &size);
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to get timing: %{public}d, %{public}s", info, curl_easy_strerror(result));
        return 0;
    }
    return size;
}

void HttpExec::CacheCurlPerformanceTiming(CURL *handle, RequestContext *context)
{
    auto dnsTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_NAMELOOKUP_TIME_T);
    auto connectTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_CONNECT_TIME_T);
    auto tlsTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_APPCONNECT_TIME_T);
    auto firstSendTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_PRETRANSFER_TIME_T);
    auto firstRecvTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_STARTTRANSFER_TIME_T);
    auto totalTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_TOTAL_TIME_T);
    auto redirectTime = HttpExec::GetTimingFromCurl(handle, CURLINFO_REDIRECT_TIME_T);

    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_DNS_TIMING, dnsTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_TCP_TIMING, connectTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_TLS_TIMING, tlsTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_FIRST_SEND_TIMING, firstSendTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_FIRST_RECEIVE_TIMING, firstRecvTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_TOTAL_FINISH_TIMING, totalTime);
    context->CachePerformanceTimingItem(HttpConstant::RESPONSE_REDIRECT_TIMING, redirectTime);

    NETSTACK_LOGI(
        "taskid=%{public}d"
        ", size:%{public}" CURL_FORMAT_CURL_OFF_T
        ", dns:%{public}.3f"
        ", connect:%{public}.3f"
        ", tls:%{public}.3f"
        ", firstSend:%{public}.3f"
        ", firstRecv:%{public}.3f"
        ", total:%{public}.3f"
        ", redirect:%{public}.3f",
        context->GetTaskId(), GetSizeFromCurl(handle, context), dnsTime, connectTime == 0 ? 0 : connectTime - dnsTime,
        tlsTime == 0 ? 0 : tlsTime - connectTime,
        firstSendTime == 0 ? 0 : firstSendTime - std::max({dnsTime, connectTime, tlsTime}),
        firstRecvTime == 0 ? 0 : firstRecvTime - firstSendTime, totalTime, redirectTime);
}

#if HAS_NETMANAGER_BASE
void HttpExec::HandleCurlData(CURLMsg *msg, RequestContext *context)
#else
void HttpExec::HandleCurlData(CURLMsg *msg)
#endif
{
    if (msg == nullptr) {
        return;
    }

    auto handle = msg->easy_handle;
    if (handle == nullptr) {
        return;
    }

#if !HAS_NETMANAGER_BASE
    auto it = staticVariable_.contextMap.find(handle);
    if (it == staticVariable_.contextMap.end()) {
        NETSTACK_LOGE("can not find context");
        return;
    }

    auto context = it->second;
    staticVariable_.contextMap.erase(it);
    if (context == nullptr) {
        NETSTACK_LOGE("can not find context");
        return;
    }
#endif
    NETSTACK_LOGD("priority = %{public}d", context->options.GetPriority());
    context->SetExecOK(GetCurlDataFromHandle(handle, context, msg->msg, msg->data.result));
    CacheCurlPerformanceTiming(handle, context);
    if (context->IsExecOK()) {
        CacheProxy proxy(context->options);
        proxy.WriteResponseToCache(context->response);
    }
    if (context->GetManager() == nullptr) {
        NETSTACK_LOGE("can not find context manager");
        return;
    }
#if HAS_NETMANAGER_BASE
    FinishAsyncTrace(HITRACE_TAG_NET, HTTP_REQ_TRACE_NAME, context->GetTaskId());
#endif
    if (context->IsRequestInStream()) {
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(AsyncWorkRequestInStreamCallback, context->GetEnv(), napi_ok, context),
            context->GetModuleId());
    } else {
        NapiUtils::CreateUvQueueWorkByModuleId(context->GetEnv(),
                                               std::bind(AsyncWorkRequestCallback, context->GetEnv(), napi_ok, context),
                                               context->GetModuleId());
    }
}

bool HttpExec::ExecRequest(RequestContext *context)
{
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->IsAtomicService() &&
        !CommonUtils::IsAllowedHostname(context->GetBundleName(), context->options.GetUrl())) {
        context->SetNoAllowedHost(true);
        return false;
    }
    if (context->GetManager()->IsEventDestroy()) {
        return false;
    }
    context->options.SetRequestTime(HttpTime::GetNowTimeGMT());
    CacheProxy proxy(context->options);
    if (context->IsUsingCache() && proxy.ReadResponseFromCache(context)) {
        return true;
    }

    if (!RequestWithoutCache(context)) {
        context->SetErrorCode(NapiUtils::NETSTACK_NAPI_INTERNAL_ERROR);
        if (EventManager::IsManagerValid(context->GetManager())) {
            if (context->IsRequestInStream()) {
                NapiUtils::CreateUvQueueWorkByModuleId(
                    context->GetEnv(), std::bind(AsyncWorkRequestInStreamCallback, context->GetEnv(), napi_ok, context),
                    context->GetModuleId());
            } else {
                NapiUtils::CreateUvQueueWorkByModuleId(
                    context->GetEnv(), std::bind(AsyncWorkRequestCallback, context->GetEnv(), napi_ok, context),
                    context->GetModuleId());
            }
        }
        return false;
    }

    return true;
}

napi_value HttpExec::BuildRequestCallback(RequestContext *context)
{
    napi_value object = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), object) != napi_object) {
        return nullptr;
    }

    NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESPONSE_CODE,
                                 context->response.GetResponseCode());
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_COOKIES,
                                     context->response.GetCookies());

    napi_value header = MakeResponseHeader(context->GetEnv(), context);
    if (NapiUtils::GetValueType(context->GetEnv(), header) == napi_object) {
        NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_HEADER, header);
    }

    if (context->options.GetHttpDataType() != HttpDataType::NO_DATA_TYPE && ProcByExpectDataType(object, context)) {
        return object;
    }

    auto contentType = CommonUtils::ToLower(const_cast<std::map<std::string, std::string> &>(
        context->response.GetHeader())[HttpConstant::HTTP_CONTENT_TYPE]);
    if (contentType.find(HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM) != std::string::npos ||
        contentType.find(HttpConstant::HTTP_CONTENT_TYPE_IMAGE) != std::string::npos) {
        void *data = nullptr;
        auto body = context->response.GetResult();
        napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), body.size(), &data);
        if (data != nullptr && arrayBuffer != nullptr) {
            if (memcpy_s(data, body.size(), body.c_str(), body.size()) != EOK) {
                NETSTACK_LOGE("memcpy_s failed!");
                return object;
            }
            NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT, arrayBuffer);
        }
        NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                     static_cast<uint32_t>(HttpDataType::ARRAY_BUFFER));
        return object;
    }

    /* now just support utf8 */
    NapiUtils::SetStringPropertyUtf8(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT,
                                     context->response.GetResult());
    NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                 static_cast<uint32_t>(HttpDataType::STRING));
    return object;
}

napi_value HttpExec::RequestCallback(RequestContext *context)
{
    napi_value result = HttpExec::BuildRequestCallback(context);
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_TOTAL_TIMING);
    context->SetPerformanceTimingToResult(result);
    return result;
}

napi_value HttpExec::RequestInStreamCallback(OHOS::NetStack::Http::RequestContext *context)
{
    napi_value number = NapiUtils::CreateUint32(context->GetEnv(), context->response.GetResponseCode());
    if (NapiUtils::GetValueType(context->GetEnv(), number) != napi_number) {
        return nullptr;
    }
    return number;
}

std::string HttpExec::MakeUrl(const std::string &url, std::string param, const std::string &extraParam)
{
    if (param.empty()) {
        param += extraParam;
    } else {
        param += HttpConstant::HTTP_URL_PARAM_SEPARATOR;
        param += extraParam;
    }

    if (param.empty()) {
        return url;
    }

    return url + HttpConstant::HTTP_URL_PARAM_START + param;
}

bool HttpExec::MethodForGet(const std::string &method)
{
    return (method == HttpConstant::HTTP_METHOD_HEAD || method == HttpConstant::HTTP_METHOD_OPTIONS ||
            method == HttpConstant::HTTP_METHOD_TRACE || method == HttpConstant::HTTP_METHOD_GET ||
            method == HttpConstant::HTTP_METHOD_CONNECT);
}

bool HttpExec::MethodForPost(const std::string &method)
{
    return (method == HttpConstant::HTTP_METHOD_POST || method == HttpConstant::HTTP_METHOD_PUT ||
            method == HttpConstant::HTTP_METHOD_DELETE || method.empty());
}

bool HttpExec::EncodeUrlParam(std::string &str)
{
    char encoded[4];
    std::string encodeOut;
    size_t length = strlen(str.c_str());
    for (size_t i = 0; i < length; ++i) {
        auto c = static_cast<uint8_t>(str.c_str()[i]);
        if (IsUnReserved(c)) {
            encodeOut += static_cast<char>(c);
        } else {
            if (sprintf_s(encoded, sizeof(encoded), "%%%02X", c) < 0) {
                return false;
            }
            encodeOut += encoded;
        }
    }

    if (str == encodeOut) {
        return false;
    }
    str = encodeOut;
    return true;
}

#if !HAS_NETMANAGER_BASE
void HttpExec::AddRequestInfo()
{
    std::lock_guard guard(staticVariable_.curlMultiMutex);
    int num = 0;
    while (!staticVariable_.infoQueue.empty()) {
        if (!staticVariable_.runThread || staticVariable_.curlMulti == nullptr) {
            break;
        }

        auto info = staticVariable_.infoQueue.top();
        staticVariable_.infoQueue.pop();
        auto ret = curl_multi_add_handle(staticVariable_.curlMulti, info.handle);
        if (ret == CURLM_OK) {
            staticVariable_.contextMap[info.handle] = info.context;
        }

        ++num;
        if (num >= CURL_HANDLE_NUM) {
            break;
        }
    }
}
#endif

#if !HAS_NETMANAGER_BASE
void HttpExec::RunThread()
{
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(HTTP_TASK_RUN_THREAD);
#else
    pthread_setname_np(pthread_self(), HTTP_TASK_RUN_THREAD);
#endif
    while (staticVariable_.runThread && staticVariable_.curlMulti != nullptr) {
        AddRequestInfo();
        SendRequest();
        ReadResponse();
        std::this_thread::sleep_for(std::chrono::milliseconds(CURL_TIMEOUT_MS));
        std::unique_lock l(staticVariable_.curlMultiMutex);
        staticVariable_.conditionVariable.wait_for(l, std::chrono::seconds(CONDITION_TIMEOUT_S), [] {
            return !staticVariable_.infoQueue.empty() || !staticVariable_.contextMap.empty();
        });
    }
}

void HttpExec::SendRequest()
{
    std::lock_guard guard(staticVariable_.curlMultiMutex);

    int runningHandle = 0;
    int num = 0;
    do {
        if (!staticVariable_.runThread || staticVariable_.curlMulti == nullptr) {
            break;
        }

        auto ret = curl_multi_perform(staticVariable_.curlMulti, &runningHandle);

        if (runningHandle > 0) {
            ret = curl_multi_poll(staticVariable_.curlMulti, nullptr, 0, CURL_MAX_WAIT_MSECS, nullptr);
        }

        if (ret != CURLM_OK) {
            return;
        }

        ++num;
        if (num >= CURL_HANDLE_NUM) {
            break;
        }
    } while (runningHandle > 0);
}

void HttpExec::ReadResponse()
{
    std::lock_guard guard(staticVariable_.curlMultiMutex);
    CURLMsg *msg = nullptr; /* NOLINT */
    do {
        if (!staticVariable_.runThread || staticVariable_.curlMulti == nullptr) {
            break;
        }

        int leftMsg;
        msg = curl_multi_info_read(staticVariable_.curlMulti, &leftMsg);
        if (msg) {
            if (msg->msg == CURLMSG_DONE) {
                HandleCurlData(msg);
            }
            if (msg->easy_handle) {
                (void)curl_multi_remove_handle(staticVariable_.curlMulti, msg->easy_handle);
                (void)curl_easy_cleanup(msg->easy_handle);
            }
        }
    } while (msg);
}
#endif

void HttpExec::GetGlobalHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions)
{
#ifdef HTTP_PROXY_ENABLE
    char httpProxyHost[SYSPARA_MAX_SIZE] = {0};
    char httpProxyPort[SYSPARA_MAX_SIZE] = {0};
    char httpProxyExclusions[SYSPARA_MAX_SIZE] = {0};
    GetParameter(HTTP_PROXY_HOST_KEY, DEFAULT_HTTP_PROXY_HOST, httpProxyHost, sizeof(httpProxyHost));
    GetParameter(HTTP_PROXY_PORT_KEY, DEFAULT_HTTP_PROXY_PORT, httpProxyPort, sizeof(httpProxyPort));
    GetParameter(HTTP_PROXY_EXCLUSIONS_KEY, DEFAULT_HTTP_PROXY_EXCLUSION_LIST, httpProxyExclusions,
                 sizeof(httpProxyExclusions));

    host = Base64::Decode(httpProxyHost);
    if (host == DEFAULT_HTTP_PROXY_HOST) {
        host = std::string();
    }
    exclusions = httpProxyExclusions;
    if (exclusions == DEFAULT_HTTP_PROXY_EXCLUSION_LIST) {
        exclusions = std::string();
    }

    port = std::atoi(httpProxyPort);
#endif
}

void HttpExec::GetHttpProxyInfo(RequestContext *context, std::string &host, int32_t &port, std::string &exclusions)
{
    if (context->options.GetUsingHttpProxyType() == UsingHttpProxyType::USE_DEFAULT) {
#ifdef HAS_NETMANAGER_BASE
        using namespace NetManagerStandard;
        HttpProxy httpProxy;
        NetConnClient::GetInstance().GetDefaultHttpProxy(httpProxy);
        host = httpProxy.GetHost();
        port = httpProxy.GetPort();
        exclusions = CommonUtils::ToString(httpProxy.GetExclusionList());
#else
        GetGlobalHttpProxyInfo(host, port, exclusions);
#endif
    } else if (context->options.GetUsingHttpProxyType() == UsingHttpProxyType::USE_SPECIFIED) {
        context->options.GetSpecifiedHttpProxy(host, port, exclusions);
    }
}

#if !HAS_NETMANAGER_BASE
bool HttpExec::Initialize()
{
    std::lock_guard<std::mutex> lock(staticVariable_.mutexForInitialize);
    if (staticVariable_.initialized) {
        return true;
    }
    NETSTACK_LOGD("call curl_global_init");
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        NETSTACK_LOGE("Failed to initialize 'curl'");
        return false;
    }

    staticVariable_.curlMulti = curl_multi_init();
    if (staticVariable_.curlMulti == nullptr) {
        NETSTACK_LOGE("Failed to initialize 'curl_multi'");
        return false;
    }

    staticVariable_.workThread = std::thread(RunThread);
    staticVariable_.initialized = true;
    return staticVariable_.initialized;
}
#endif

bool HttpExec::SetOtherOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    std::string url = context->options.GetUrl();
    std::string host, exclusions;
    int32_t port = 0;
    GetHttpProxyInfo(context, host, port, exclusions);
    if (!host.empty() && !CommonUtils::IsHostNameExcluded(url, exclusions, ",")) {
        NETSTACK_LOGD("Set CURLOPT_PROXY: %{public}s:%{public}d, %{public}s", host.c_str(), port, exclusions.c_str());
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXY, host.c_str(), context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYPORT, port, context);
        auto curlTunnelValue = (url.find("https://") != std::string::npos) ? 1L : 0L;
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTPPROXYTUNNEL, curlTunnelValue, context);
        auto proxyType = (host.find("https://") != std::string::npos) ? CURLPROXY_HTTPS : CURLPROXY_HTTP;
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYTYPE, proxyType, context);
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CIPHER_LIST, TLS12_SECURITY_CIPHER_SUITE, context);

#ifdef NETSTACK_PROXY_PASS
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PROXYUSERPWD, NETSTACK_PROXY_PASS, context);
#endif // NETSTACK_PROXY_PASS

#ifdef HTTP_CURL_PRINT_VERBOSE
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_VERBOSE, 1L, context);
#endif

#ifndef WINDOWS_PLATFORM
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_ACCEPT_ENCODING, "", context);
#endif
    return true;
}

bool HttpExec::SetSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
    std::string cert;
    std::string certType;
    std::string key;
    Secure::SecureChar keyPasswd;
    context->options.GetClientCert(cert, certType, key, keyPasswd);
    if (cert.empty()) {
        NETSTACK_LOGD("SetSSLCertOption param is empty.");
        return false;
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLCERT, cert.c_str(), context);
    if (!key.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLKEY, key.c_str(), context);
    }
    if (!certType.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSLCERTTYPE, certType.c_str(), context);
    }
    if (keyPasswd.Length() > 0) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_KEYPASSWD, keyPasswd.Data(), context);
    }
    return true;
}

CURLcode HttpExec::SslCtxFunction(CURL *curl, void *ssl_ctx, void *parm)
{
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    auto certsPath = static_cast<CertsPath *>(parm);
    if (certsPath == nullptr) {
        NETSTACK_LOGE("certsPath is null");
        return CURLE_SSL_CERTPROBLEM;
    }
    if (ssl_ctx == nullptr) {
        NETSTACK_LOGE("ssl_ctx is null");
        return CURLE_SSL_CERTPROBLEM;
    }

    for (const auto &path : certsPath->certPathList) {
        if (path.empty() || access(path.c_str(), F_OK) != 0) {
            NETSTACK_LOGD("certificate directory path is not exist");
            continue;
        }
        if (!SSL_CTX_load_verify_locations(static_cast<SSL_CTX *>(ssl_ctx), nullptr, path.c_str())) {
            NETSTACK_LOGE("loading certificates from directory error.");
            continue;
        }
    }
    if (access(certsPath->certFile.c_str(), F_OK) != 0) {
        NETSTACK_LOGD("certificate directory path is not exist");
    } else if (!SSL_CTX_load_verify_locations(static_cast<SSL_CTX *>(ssl_ctx), certsPath->certFile.c_str(), nullptr)) {
        NETSTACK_LOGE("loading certificates from context cert error.");
    }
#endif // HTTP_MULTIPATH_CERT_ENABLE
    return CURLE_OK;
}

bool HttpExec::SetServerSSLCertOption(CURL *curl, OHOS::NetStack::Http::RequestContext *context)
{
#ifndef NO_SSL_CERTIFICATION
#ifdef HAS_NETMANAGER_BASE
    auto hostname = CommonUtils::GetHostnameFromURL(context->options.GetUrl());
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    std::vector<std::string> certs;
    // add app cert path
    auto ret = NetManagerStandard::NetConnClient::GetInstance().GetTrustAnchorsForHostName(hostname, certs);
    if (ret != 0) {
        NETSTACK_LOGE("GetTrustAnchorsForHostName error. ret [%{public}d]", ret);
    }
#ifdef HTTP_MULTIPATH_CERT_ENABLE
    // add user cert path
    certs.emplace_back(USER_CERT_ROOT_PATH);
    certs.emplace_back(USER_CERT_PATH);
    // add system cert path
    certs.emplace_back(HttpConstant::HTTP_PREPARE_CA_PATH);
    context->SetCertsPath(std::move(certs), context->options.GetCaPath());
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 1L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 2L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_FUNCTION, SslCtxFunction, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_CTX_DATA, &context->GetCertsPath(), context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, nullptr, context);
#else
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, nullptr, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
#endif // HTTP_MULTIPATH_CERT_ENABLE
#else
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
#endif //  !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    // pin trusted certifcate keys.
    std::string pins;
    auto ret1 = NetManagerStandard::NetConnClient::GetInstance().GetPinSetForHostName(hostname, pins);
    if (ret1 != 0 || pins.empty()) {
        NETSTACK_LOGD("Get no pinset by host name[%{public}s]", hostname.c_str());
    } else {
        NETSTACK_LOGD("curl set pin =[%{public}s]", pins.c_str());
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_PINNEDPUBLICKEY, pins.c_str(), context);
    }
#else
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CAINFO, nullptr, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
#endif // HAS_NETMANAGER_BASE
#else
    // in real life, you should buy a ssl certification and rename it to /etc/ssl/cert.pem
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYHOST, 0L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_SSL_VERIFYPEER, 0L, context);
#endif // NO_SSL_CERTIFICATION

    return true;
}

bool HttpExec::SetDnsOption(CURL *curl, RequestContext *context)
{
    std::vector<std::string> dnsServers = context->options.GetDnsServers();
    if (dnsServers.empty()) {
        return true;
    }
    std::string serverList;
    for (auto &server : dnsServers) {
        serverList += server + ",";
        NETSTACK_LOGD("SetDns server: %{public}s", CommonUtils::AnonymizeIp(server).c_str());
    }
    serverList.pop_back();
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DNS_SERVERS, serverList.c_str(), context);
    return true;
}

bool HttpExec::ParseHostAndPortFromUrl(const std::string &url, std::string &host, uint16_t &port)
{
    CURLU *cu = curl_url();
    if (!cu) {
        NETSTACK_LOGE("out of memory");
        return false;
    }
    if (curl_url_set(cu, CURLUPART_URL, url.c_str(), 0)) {
        NETSTACK_LOGD("not a URL: '%{public}s'", url.c_str());
        curl_url_cleanup(cu);
        return false;
    }
    char *chost = nullptr;
    char *cport = nullptr;

    (void)curl_url_get(cu, CURLUPART_HOST, &chost, 0);
    (void)curl_url_get(cu, CURLUPART_PORT, &cport, 0);
    if (chost != nullptr) {
        host = chost;
        NETSTACK_LOGD("parse host: '%{public}s'", host.c_str());
        curl_free(chost);
    }
    if (cport != nullptr) {
        port = atoi(cport);
        NETSTACK_LOGD("parse port: '%{public}u'", port);
        curl_free(cport);
    }
    curl_url_cleanup(cu);
    return !host.empty();
}

bool HttpExec::SetDnsResolvOption(CURL *curl, RequestContext *context)
{
    std::string host = "";
    uint16_t port = 0;
    if (!ParseHostAndPortFromUrl(context->options.GetUrl(), host, port)) {
        NETSTACK_LOGE("get host and port failed");
        return true;
    }
#ifdef HAS_NETMANAGER_BASE
    struct addrinfo *res = nullptr;
    int ret = getaddrinfo_hook(host.c_str(), nullptr, nullptr, &res);
    if (ret < 0) {
        return true;
    }

    struct curl_slist *hostSlist = nullptr;
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void *addr = nullptr;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            addr = &ipv4->sin_addr;
        } else {
            struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
            addr = &ipv6->sin6_addr;
        }
        if (inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr)) == NULL) {
            continue;
        }
        std::string resolvHost = host + ":" + std::to_string(port) + ":" + ipstr;
        NETSTACK_LOGE("dns parse: %{public}s", resolvHost.c_str());
        hostSlist = curl_slist_append(hostSlist, resolvHost.c_str());
    }
    freeaddrinfo(res);
    if (hostSlist == nullptr) {
        NETSTACK_LOGE("no valid ip");
        return true;
    }
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RESOLVE, hostSlist, context);
    context->SetCurlHostList(hostSlist);
#endif
    return true;
}

bool HttpExec::SetRequestOption(CURL *curl, RequestContext *context)
{
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTP_VERSION, context->options.GetHttpVersion(), context);
    const std::string range = context->options.GetRangeString();
    if (range.empty()) {
        // Some servers don't like requests that are made without a user-agent field, so we provide one
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_USERAGENT, HttpConstant::HTTP_DEFAULT_USER_AGENT, context);
    } else {
        // https://curl.se/libcurl/c/CURLOPT_RANGE.html
        if (context->options.GetMethod() == HttpConstant::HTTP_METHOD_PUT) {
            context->SetErrorCode(CURLE_RANGE_ERROR);
            NETSTACK_LOGE("For HTTP PUT uploads this option should not be used, since it may conflict with \
                          other options.");
            return false;
        }
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_RANGE, range.c_str(), context);
    }
    if (!context->options.GetDohUrl().empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DOH_URL, context->options.GetDohUrl().c_str(), context);
    }
    SetDnsOption(curl, context);
    SetSSLCertOption(curl, context);
    SetMultiPartOption(curl, context);
    SetDnsResolvOption(curl, context);
    return true;
}

bool HttpExec::SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader)
{
    const std::string &method = context->options.GetMethod();
    if (!MethodForGet(method) && !MethodForPost(method)) {
        NETSTACK_LOGE("method %{public}s not supported", method.c_str());
        return false;
    }

    if (context->options.GetMethod() == HttpConstant::HTTP_METHOD_HEAD) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOBODY, 1L, context);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_URL, context->options.GetUrl().c_str(), context);
    if (!method.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CUSTOMREQUEST, method.c_str(), context);
    }

    if (MethodForPost(method) && !context->options.GetBody().empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_POST, 1L, context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_POSTFIELDS, context->options.GetBody().c_str(), context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_POSTFIELDSIZE, context->options.GetBody().size(), context);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_XFERINFOFUNCTION, ProgressCallback, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_XFERINFODATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOPROGRESS, 0L, context);

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_WRITEFUNCTION, OnWritingMemoryBody, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_WRITEDATA, context, context);

    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HEADERFUNCTION, OnWritingMemoryHeader, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HEADERDATA, context, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_HTTPHEADER, requestHeader, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_FOLLOWLOCATION, 1L, context);

    /* first #undef CURL_DISABLE_COOKIES in curl config */
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_COOKIEFILE, "", context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_NOSIGNAL, 1L, context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_TIMEOUT_MS, context->options.GetReadTimeout(), context);
    NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_CONNECTTIMEOUT_MS, context->options.GetConnectTimeout(), context);

    if (!SetRequestOption(curl, context)) {
        return false;
    }

    if (!SetOtherOption(curl, context)) {
        return false;
    }
    return true;
}

size_t HttpExec::OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (context->GetManager()->IsEventDestroy()) {
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return 0;
    }
    if (context->IsRequestInStream()) {
        context->SetTempData(data, size * memBytes);
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(OnDataReceive, context->GetEnv(), napi_ok, context), context->GetModuleId());
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return size * memBytes;
    }
    if (context->response.GetResult().size() > context->options.GetMaxLimit() ||
        size * memBytes > context->options.GetMaxLimit()) {
        NETSTACK_LOGE("response data exceeds the maximum limit");
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
        return 0;
    }
    context->response.AppendResult(data, size * memBytes);
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_BODY_TIMING);
    return size * memBytes;
}

static void MakeSetCookieArray(napi_env env, napi_value header,
                               const std::pair<const std::basic_string<char>, std::basic_string<char>> &headerElement)
{
    std::vector<std::string> cookieVec =
        CommonUtils::Split(headerElement.second, HttpConstant::RESPONSE_KEY_SET_COOKIE_SEPARATOR);
    uint32_t index = 0;
    auto len = cookieVec.size();
    auto array = NapiUtils::CreateArray(env, len);
    for (const auto &setCookie : cookieVec) {
        auto str = NapiUtils::CreateStringUtf8(env, setCookie);
        NapiUtils::SetArrayElement(env, array, index, str);
        ++index;
    }
    NapiUtils::SetArrayProperty(env, header, HttpConstant::RESPONSE_KEY_SET_COOKIE, array);
}

static void MakeHeaderWithSetCookieArray(napi_env env, napi_value header, std::map<std::string, std::string> *headerMap)
{
    for (const auto &it : *headerMap) {
        if (!it.first.empty() && !it.second.empty()) {
            if (it.first == HttpConstant::RESPONSE_KEY_SET_COOKIE) {
                MakeSetCookieArray(env, header, it);
                continue;
            }
            NapiUtils::SetStringPropertyUtf8(env, header, it.first, it.second);
        }
    }
}

static void ResponseHeaderCallback(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    napi_env env = workWrapper->env;
    auto headerMap = static_cast<std::map<std::string, std::string> *>(workWrapper->data);
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);
    napi_value header = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, header) == napi_object) {
        MakeHeaderWithSetCookieArray(env, header, headerMap);
    }
    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(env), header};
    workWrapper->manager->Emit(workWrapper->type, arg);
    delete headerMap;
    headerMap = nullptr;
    delete workWrapper;
    workWrapper = nullptr;
    delete work;
    work = nullptr;
}

static std::map<std::string, std::string> MakeHeaderWithSetCookie(RequestContext * context)
{
    std::map<std::string, std::string> tempMap = context->response.GetHeader();
    std::string setCookies;
    size_t loop = 0;
    for (const auto &setCookie : context->response.GetsetCookie()) {
        setCookies += setCookie;
        if (loop + 1 < context->response.GetsetCookie().size()) {
            setCookies += HttpConstant::RESPONSE_KEY_SET_COOKIE_SEPARATOR;
        }
        ++loop;
    }
    tempMap[HttpConstant::RESPONSE_KEY_SET_COOKIE] = setCookies;
    return tempMap;
}

size_t HttpExec::OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (context->GetManager()->IsEventDestroy()) {
        context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_HEADER_TIMING);
        return 0;
    }
    context->response.AppendRawHeader(data, size * memBytes);
    if (CommonUtils::EndsWith(context->response.GetRawHeader(), HttpConstant::HTTP_RESPONSE_HEADER_SEPARATOR)) {
        context->response.ParseHeaders();
        if (context->GetManager() && EventManager::IsManagerValid(context->GetManager())) {
            auto headerMap = new std::map<std::string, std::string>(MakeHeaderWithSetCookie(context));
            context->GetManager()->EmitByUv(ON_HEADER_RECEIVE, headerMap, ResponseHeaderCallback);
            auto headersMap = new std::map<std::string, std::string>(MakeHeaderWithSetCookie(context));
            context->GetManager()->EmitByUv(ON_HEADERS_RECEIVE, headersMap, ResponseHeaderCallback);
        }
    }
    context->StopAndCacheNapiPerformanceTiming(HttpConstant::RESPONSE_HEADER_TIMING);
    return size * memBytes;
}

void HttpExec::OnDataReceive(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<RequestContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return;
    }

    void *buffer = nullptr;
    auto tempData = context->GetTempData();
    context->PopTempData();
    if (tempData.empty()) {
        NETSTACK_LOGI("[GetTempData] tempDate is empty!");
        return;
    }
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), tempData.size(), &buffer);
    if (buffer == nullptr || arrayBuffer == nullptr) {
        return;
    }
    if (memcpy_s(buffer, tempData.size(), tempData.data(), tempData.size()) != EOK) {
        NETSTACK_LOGE("[CreateArrayBuffer] memory copy failed");
        return;
    }
    context->Emit(ON_DATA_RECEIVE, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()), arrayBuffer));
}

void HttpExec::OnDataProgress(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<RequestContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGD("OnDataProgress context is null");
        return;
    }
    auto progress = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), progress) == napi_undefined) {
        return;
    }
    auto dlLen = context->GetDlLen();
    if (dlLen.tLen && dlLen.nLen) {
        NapiUtils::SetUint32Property(context->GetEnv(), progress, "receiveSize", static_cast<uint32_t>(dlLen.nLen));
        NapiUtils::SetUint32Property(context->GetEnv(), progress, "totalSize", static_cast<uint32_t>(dlLen.tLen));

        context->Emit(ON_DATA_RECEIVE_PROGRESS, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()), progress));
    }
}

void HttpExec::OnDataUploadProgress(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<RequestContext *>(data);
    if (context == nullptr) {
        NETSTACK_LOGD("OnDataUploadProgress context is null");
        return;
    }
    auto progress = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), progress) == napi_undefined) {
        NETSTACK_LOGD("OnDataUploadProgress napi_undefined");
        return;
    }
    NapiUtils::SetUint32Property(context->GetEnv(), progress, "sendSize",
                                 static_cast<uint32_t>(context->GetUlLen().nLen));
    NapiUtils::SetUint32Property(context->GetEnv(), progress, "totalSize",
                                 static_cast<uint32_t>(context->GetUlLen().tLen));
    context->Emit(ON_DATA_SEND_PROGRESS, std::make_pair(NapiUtils::GetUndefined(context->GetEnv()), progress));
}

int HttpExec::ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                               curl_off_t ulnow)
{
    auto context = static_cast<RequestContext *>(userData);
    if (context == nullptr) {
        return 0;
    }
    if (ultotal != 0 && ultotal >= ulnow && !context->CompareWithLastElement(ulnow, ultotal)) {
        context->SetUlLen(ulnow, ultotal);
        NapiUtils::CreateUvQueueWorkByModuleId(context->GetEnv(),
                                               std::bind(OnDataUploadProgress, context->GetEnv(), napi_ok, context),
                                               context->GetModuleId());
    }
    if (!context->IsRequestInStream()) {
        return 0;
    }
    if (context->GetManager()->IsEventDestroy()) {
        return 0;
    }
    if (dltotal != 0) {
        context->SetDlLen(dlnow, dltotal);
        NapiUtils::CreateUvQueueWorkByModuleId(
            context->GetEnv(), std::bind(OnDataProgress, context->GetEnv(), napi_ok, context), context->GetModuleId());
    }
    return 0;
}

struct curl_slist *HttpExec::MakeHeaders(const std::vector<std::string> &vec)
{
    struct curl_slist *header = nullptr;
    std::for_each(vec.begin(), vec.end(), [&header](const std::string &s) {
        if (!s.empty()) {
            header = curl_slist_append(header, s.c_str());
        }
    });
    return header;
}

napi_value HttpExec::MakeResponseHeader(napi_env env, void *ctx)
{
    auto context = reinterpret_cast<RequestContext *>(ctx);
    (void)env;
    napi_value header = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), header) == napi_object) {
        for (const auto &it : context->response.GetHeader()) {
            if (!it.first.empty() && !it.second.empty()) {
                NapiUtils::SetStringPropertyUtf8(context->GetEnv(), header, it.first, it.second);
            }
        }
        if (!context->response.GetsetCookie().empty()) {
            uint32_t index = 0;
            auto len = context->response.GetsetCookie().size();
            auto array = NapiUtils::CreateArray(context->GetEnv(), len);
            for (const auto &setCookie : context->response.GetsetCookie()) {
                auto str = NapiUtils::CreateStringUtf8(context->GetEnv(), setCookie);
                NapiUtils::SetArrayElement(context->GetEnv(), array, index, str);
                ++index;
            }
            NapiUtils::SetArrayProperty(context->GetEnv(), header, HttpConstant::RESPONSE_KEY_SET_COOKIE, array);
        }
    }
    return header;
}

bool HttpExec::IsUnReserved(unsigned char in)
{
    if ((in >= '0' && in <= '9') || (in >= 'a' && in <= 'z') || (in >= 'A' && in <= 'Z')) {
        return true;
    }
    switch (in) {
        case '-':
        case '.':
        case '_':
        case '~':
            return true;
        default:
            break;
    }
    return false;
}

bool HttpExec::ProcByExpectDataType(napi_value object, RequestContext *context)
{
    switch (context->options.GetHttpDataType()) {
        case HttpDataType::STRING: {
            NapiUtils::SetStringPropertyUtf8(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT,
                                             context->response.GetResult());
            NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                         static_cast<uint32_t>(HttpDataType::STRING));
            return true;
        }
        case HttpDataType::OBJECT: {
            if (context->response.GetResult().size() > HttpConstant::MAX_JSON_PARSE_SIZE) {
                return false;
            }

            napi_value obj = NapiUtils::JsonParse(context->GetEnv(), context->response.GetResult());
            if (obj) {
                NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT, obj);
                NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                             static_cast<uint32_t>(HttpDataType::OBJECT));
                return true;
            }

            // parse maybe failed
            return false;
        }
        case HttpDataType::ARRAY_BUFFER: {
            void *data = nullptr;
            auto body = context->response.GetResult();
            napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(context->GetEnv(), body.size(), &data);
            if (data != nullptr && arrayBuffer != nullptr) {
                if (memcpy_s(data, body.size(), body.c_str(), body.size()) < 0) {
                    NETSTACK_LOGE("[ProcByExpectDataType] memory copy failed");
                    return true;
                }
                NapiUtils::SetNamedProperty(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT, arrayBuffer);
                NapiUtils::SetUint32Property(context->GetEnv(), object, HttpConstant::RESPONSE_KEY_RESULT_TYPE,
                                             static_cast<uint32_t>(HttpDataType::ARRAY_BUFFER));
            }
            return true;
        }
        default:
            break;
    }
    return false;
}

void HttpExec::AsyncRunRequest(RequestContext *context)
{
    HttpAsyncWork::ExecRequest(context->GetEnv(), context);
}

#if !HAS_NETMANAGER_BASE
bool HttpExec::IsInitialized()
{
    return staticVariable_.initialized;
}

void HttpExec::DeInitialize()
{
    std::lock_guard<std::mutex> lock(staticVariable_.curlMultiMutex);
    staticVariable_.runThread = false;
    staticVariable_.conditionVariable.notify_all();
    if (staticVariable_.workThread.joinable()) {
        staticVariable_.workThread.join();
    }
    if (staticVariable_.curlMulti) {
        curl_multi_cleanup(staticVariable_.curlMulti);
    }
    staticVariable_.initialized = false;
}
#endif

bool HttpResponseCacheExec::ExecFlush(BaseContext *context)
{
    (void)context;
    CacheProxy::FlushCache();
    return true;
}

napi_value HttpResponseCacheExec::FlushCallback(BaseContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

bool HttpResponseCacheExec::ExecDelete(BaseContext *context)
{
    (void)context;
    CacheProxy::StopCacheAndDelete();
    return true;
}

napi_value HttpResponseCacheExec::DeleteCallback(BaseContext *context)
{
    return NapiUtils::GetUndefined(context->GetEnv());
}

bool HttpExec::SetMultiPartOption(CURL *curl, RequestContext *context)
{
    auto header = context->options.GetHeader();
    auto type = CommonUtils::ToLower(header[HttpConstant::HTTP_CONTENT_TYPE]);
    if (type != HttpConstant::HTTP_CONTENT_TYPE_MULTIPART) {
        return true;
    }
    auto multiPartDataList = context->options.GetMultiPartDataList();
    if (multiPartDataList.empty()) {
        return true;
    }
    curl_mime *multipart = curl_mime_init(curl);
    if (multipart == nullptr) {
        return false;
    }
    context->SetMultipart(multipart);
    curl_mimepart *part = nullptr;
    bool hasData = false;
    for (auto &multiFormData : multiPartDataList) {
        if (multiFormData.name.empty()) {
            continue;
        }
        if (multiFormData.data.empty() && multiFormData.filePath.empty()) {
            NETSTACK_LOGE("Failed to set name %{public}s, error no data and filepath at the same time",
                          multiFormData.name.c_str());
            continue;
        }
        part = curl_mime_addpart(multipart);
        SetFormDataOption(multiFormData, part, curl, context);
        hasData = true;
    }
    if (hasData) {
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_MIMEPOST, multipart, context);
    }
    return true;
}

void HttpExec::SetFormDataOption(MultiFormData &multiFormData, curl_mimepart *part, CURL *curl,
                                 RequestContext *context)
{
    CURLcode result = curl_mime_name(part, multiFormData.name.c_str());
    if (result != CURLE_OK) {
        NETSTACK_LOGE("Failed to set name %{public}s, error: %{public}s", multiFormData.name.c_str(),
                      curl_easy_strerror(result));
        return;
    }
    if (!multiFormData.contentType.empty()) {
        result = curl_mime_type(part, multiFormData.contentType.c_str());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set contentType: %{public}s, error: %{public}s", multiFormData.name.c_str(),
                          curl_easy_strerror(result));
        }
    }
    if (!multiFormData.remoteFileName.empty()) {
        result = curl_mime_filename(part, multiFormData.remoteFileName.c_str());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set remoteFileName: %{public}s, error: %{public}s", multiFormData.name.c_str(),
                          curl_easy_strerror(result));
        }
    }
    if (!multiFormData.data.empty()) {
        result = curl_mime_data(part, multiFormData.data.c_str(), multiFormData.data.length());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set data: %{public}s, error: %{public}s", multiFormData.name.c_str(),
                          curl_easy_strerror(result));
        }
    } else {
        result = curl_mime_filedata(part, multiFormData.filePath.c_str());
        if (result != CURLE_OK) {
            NETSTACK_LOGE("Failed to set file data: %{public}s, error: %{public}s", multiFormData.name.c_str(),
                          curl_easy_strerror(result));
        }
    }
}
} // namespace OHOS::NetStack::Http
