/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "request_context.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <utility>

#include "constant.h"
#include "http_exec.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "secure_char.h"
#include "timing.h"

static constexpr const int PARAM_JUST_URL = 1;

static constexpr const int PARAM_JUST_URL_OR_CALLBACK = 1;

static constexpr const int PARAM_URL_AND_OPTIONS_OR_CALLBACK = 2;

static constexpr const int PARAM_URL_AND_OPTIONS_AND_CALLBACK = 3;

static constexpr const uint32_t DNS_SERVER_SIZE = 3;
namespace OHOS::NetStack::Http {
static const std::map<int32_t, const char *> HTTP_ERR_MAP = {
    {HTTP_UNSUPPORTED_PROTOCOL, "Unsupported protocol"},
    {HTTP_URL_MALFORMAT, "URL using bad/illegal format or missing URL"},
    {HTTP_COULDNT_RESOLVE_PROXY, "Couldn't resolve proxy name"},
    {HTTP_COULDNT_RESOLVE_HOST, "Couldn't resolve host name"},
    {HTTP_COULDNT_CONNECT, "Couldn't connect to server"},
    {HTTP_WEIRD_SERVER_REPLY, "Weird server reply"},
    {HTTP_REMOTE_ACCESS_DENIED, "Access denied to remote resource"},
    {HTTP_HTTP2_ERROR, "Error in the HTTP2 framing layer"},
    {HTTP_PARTIAL_FILE, "Transferred a partial file"},
    {HTTP_WRITE_ERROR, "Failed writing received data to disk/application"},
    {HTTP_UPLOAD_FAILED, "Upload failed"},
    {HTTP_READ_ERROR, "Failed to open/read local data from file/application"},
    {HTTP_OUT_OF_MEMORY, "Out of memory"},
    {HTTP_OPERATION_TIMEDOUT, "Timeout was reached"},
    {HTTP_TOO_MANY_REDIRECTS, "Number of redirects hit maximum amount"},
    {HTTP_GOT_NOTHING, "Server returned nothing (no headers, no data)"},
    {HTTP_SEND_ERROR, "Failed sending data to the peer"},
    {HTTP_RECV_ERROR, "Failure when receiving data from the peer"},
    {HTTP_SSL_CERTPROBLEM, "Problem with the local SSL certificate"},
    {HTTP_SSL_CIPHER, "Couldn't use specified SSL cipher"},
    {HTTP_PEER_FAILED_VERIFICATION, "SSL peer certificate or SSH remote key was not OK"},
    {HTTP_BAD_CONTENT_ENCODING, "Unrecognized or bad HTTP Content or Transfer-Encoding"},
    {HTTP_FILESIZE_EXCEEDED, "Maximum file size exceeded"},
    {HTTP_REMOTE_DISK_FULL, "Disk full or allocation exceeded"},
    {HTTP_REMOTE_FILE_EXISTS, "Remote file already exists"},
    {HTTP_SSL_CACERT_BADFILE, "Problem with the SSL CA cert (path? access rights?)"},
    {HTTP_REMOTE_FILE_NOT_FOUND, "Remote file not found"},
    {HTTP_AUTH_ERROR, "An authentication function returned an error"},
    {HTTP_SSL_PINNEDPUBKEYNOTMATCH, "Specified pinned public key did not match"},
    {HTTP_NOT_ALLOWED_HOST, "It is not allowed to visit this host"},
    {HTTP_UNKNOWN_OTHER_ERROR, "Unknown Other Error"},
};
static std::atomic<int32_t> g_currentTaskId = std::numeric_limits<int32_t>::min();
RequestContext::RequestContext(napi_env env, EventManager *manager)
    : BaseContext(env, manager),
      usingCache_(true),
      requestInStream_(false),
      curlHeaderList_(nullptr),
      multipart_(nullptr),
      curlHostList_(nullptr)
{
    taskId_ = g_currentTaskId++;
    isAtomicService_ = false;
    bundleName_ = "";
    StartTiming();
}

void RequestContext::StartTiming()
{
    time_t startTime = Timing::TimeUtils::GetNowTimeMicroseconds();
    timerMap_.RecieveTimer(HttpConstant::RESPONSE_HEADER_TIMING).Start(startTime);
    timerMap_.RecieveTimer(HttpConstant::RESPONSE_BODY_TIMING).Start(startTime);
    timerMap_.RecieveTimer(HttpConstant::RESPONSE_TOTAL_TIMING).Start(startTime);
}

void RequestContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        if (paramsCount == PARAM_JUST_URL_OR_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
                SetCallback(params[0]);
            }
            return;
        }
        if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function) {
                SetCallback(params[1]);
            }
            return;
        }
        if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) == napi_function) {
                SetCallback(params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]);
            }
            return;
        }
        return;
    }

    if (paramsCount == PARAM_JUST_URL) {
        options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]));
        SetParseOK(true);
        return;
    }

    if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), params[1]);
        if (type == napi_function) {
            options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), params[0]));
            SetParseOK(SetCallback(params[1]) == napi_ok);
            return;
        }
        if (type == napi_object) {
            UrlAndOptions(params[0], params[1]);
            return;
        }
        return;
    }

    if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
        if (SetCallback(params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) != napi_ok) {
            return;
        }
        UrlAndOptions(params[0], params[1]);
    }
}

bool RequestContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_URL) {
        // just url
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string;
    }
    if (paramsCount == PARAM_URL_AND_OPTIONS_OR_CALLBACK) {
        // should be url, callback or url, options
        napi_valuetype type = NapiUtils::GetValueType(GetEnv(), params[1]);
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               (type == napi_function || type == napi_object);
    }
    if (paramsCount == PARAM_URL_AND_OPTIONS_AND_CALLBACK) {
        // should be url options and callback
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_string &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[PARAM_URL_AND_OPTIONS_AND_CALLBACK - 1]) == napi_function;
    }
    return false;
}

void RequestContext::ParseNumberOptions(napi_value optionsValue)
{
    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_READ_TIMEOUT)) {
        options.SetReadTimeout(
            NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_READ_TIMEOUT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_MAX_LIMIT)) {
        options.SetMaxLimit(NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_MAX_LIMIT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CONNECT_TIMEOUT)) {
        options.SetConnectTimeout(
            NapiUtils::GetUint32Property(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CONNECT_TIMEOUT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_CACHE)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_CACHE);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_boolean) {
            usingCache_ = NapiUtils::GetBooleanFromValue(GetEnv(), value);
        }
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_PROTOCOL)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_PROTOCOL);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t number = NapiUtils::GetUint32FromValue(GetEnv(), value);
            if (number == static_cast<uint32_t>(HttpProtocol::HTTP1_1) ||
                number == static_cast<uint32_t>(HttpProtocol::HTTP2) ||
                number == static_cast<uint32_t>(HttpProtocol::HTTP3)) {
                options.SetUsingProtocol(static_cast<HttpProtocol>(number));
            }
        }
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE)) {
        napi_value value =
            NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXPECT_DATA_TYPE);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t type = NapiUtils::GetUint32FromValue(GetEnv(), value);
            options.SetHttpDataType(static_cast<HttpDataType>(type));
        }
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_PRIORITY)) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_PRIORITY);
        if (NapiUtils::GetValueType(GetEnv(), value) == napi_number) {
            uint32_t priority = NapiUtils::GetUint32FromValue(GetEnv(), value);
            options.SetPriority(priority);
        }
    }
}

void RequestContext::ParseHeader(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_HEADER)) {
        return;
    }
    napi_value header = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_HEADER);
    if (NapiUtils::GetValueType(GetEnv(), header) != napi_object) {
        return;
    }
    if (HttpExec::MethodForPost(options.GetMethod())) {
        options.SetHeader(CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE),
                          HttpConstant::HTTP_CONTENT_TYPE_JSON); // default
    }
    auto names = NapiUtils::GetPropertyNames(GetEnv(), header);
    std::for_each(names.begin(), names.end(), [header, this](const std::string &name) {
        napi_value value = NapiUtils::GetNamedProperty(GetEnv(), header, name);
        std::string valueStr = NapiUtils::NapiValueToString(GetEnv(), value);
        options.SetHeader(CommonUtils::ToLower(name), valueStr);
    });
}

bool RequestContext::HandleMethodForGet(napi_value extraData)
{
    std::string url = options.GetUrl();
    std::string param;
    auto index = url.find(HttpConstant::HTTP_URL_PARAM_START);
    if (index != std::string::npos) {
        param = url.substr(index + 1);
        url.resize(index);
    }

    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), extraData);
    if (type == napi_string) {
        std::string extraParam = NapiUtils::GetStringFromValueUtf8(GetEnv(), extraData);

        options.SetUrl(HttpExec::MakeUrl(url, param, extraParam));
        return true;
    }
    if (type != napi_object) {
        return true;
    }

    std::string extraParam;
    auto names = NapiUtils::GetPropertyNames(GetEnv(), extraData);
    std::for_each(names.begin(), names.end(), [this, extraData, &extraParam](std::string name) {
        auto value = NapiUtils::GetStringPropertyUtf8(GetEnv(), extraData, name);
        if (!name.empty() && !value.empty()) {
            bool encodeName = HttpExec::EncodeUrlParam(name);
            bool encodeValue = HttpExec::EncodeUrlParam(value);
            if (encodeName || encodeValue) {
                options.SetHeader(CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE),
                                  HttpConstant::HTTP_CONTENT_TYPE_URL_ENCODE);
            }
            extraParam +=
                name + HttpConstant::HTTP_URL_NAME_VALUE_SEPARATOR + value + HttpConstant::HTTP_URL_PARAM_SEPARATOR;
        }
    });
    if (!extraParam.empty()) {
        extraParam.pop_back(); // remove the last &
    }

    options.SetUrl(HttpExec::MakeUrl(url, param, extraParam));
    return true;
}

bool RequestContext::ParseExtraData(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXTRA_DATA)) {
        NETSTACK_LOGD("no extraData");
        return true;
    }

    napi_value extraData = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_EXTRA_DATA);
    if (NapiUtils::GetValueType(GetEnv(), extraData) == napi_undefined ||
        NapiUtils::GetValueType(GetEnv(), extraData) == napi_null) {
        NETSTACK_LOGD("extraData is undefined or null");
        return true;
    }

    if (HttpExec::MethodForGet(options.GetMethod())) {
        return HandleMethodForGet(extraData);
    }

    if (HttpExec::MethodForPost(options.GetMethod())) {
        return GetRequestBody(extraData);
    }
    return false;
}

void RequestContext::ParseUsingHttpProxy(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_HTTP_PROXY)) {
        NETSTACK_LOGD("Use default proxy");
        return;
    }
    napi_value httpProxyValue =
        NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_USING_HTTP_PROXY);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), httpProxyValue);
    if (type == napi_boolean) {
        bool usingProxy = NapiUtils::GetBooleanFromValue(GetEnv(), httpProxyValue);
        UsingHttpProxyType usingType = usingProxy ? UsingHttpProxyType::USE_DEFAULT : UsingHttpProxyType::NOT_USE;
        options.SetUsingHttpProxyType(usingType);
        return;
    }
    if (type != napi_object) {
        return;
    }
    std::string host = NapiUtils::GetStringPropertyUtf8(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_HOST);
    int32_t port = NapiUtils::GetInt32Property(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_PORT);
    std::string exclusionList;
    if (NapiUtils::HasNamedProperty(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_EXCLUSION_LIST)) {
        napi_value exclusionListValue =
            NapiUtils::GetNamedProperty(GetEnv(), httpProxyValue, HttpConstant::HTTP_PROXY_KEY_EXCLUSION_LIST);
        uint32_t listLength = NapiUtils::GetArrayLength(GetEnv(), exclusionListValue);
        for (uint32_t index = 0; index < listLength; ++index) {
            napi_value exclusionValue = NapiUtils::GetArrayElement(GetEnv(), exclusionListValue, index);
            std::string exclusion = NapiUtils::GetStringFromValueUtf8(GetEnv(), exclusionValue);
            if (index != 0) {
                exclusionList = exclusionList + HttpConstant::HTTP_PROXY_EXCLUSIONS_SEPARATOR;
            }
            exclusionList += exclusion;
        }
    }
    options.SetSpecifiedHttpProxy(host, port, exclusionList);
    options.SetUsingHttpProxyType(UsingHttpProxyType::USE_SPECIFIED);
}

bool RequestContext::GetRequestBody(napi_value extraData)
{
    /* if body is empty, return false, or curl will wait for body */

    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), extraData);
    if (type == napi_string) {
        auto body = NapiUtils::GetStringFromValueUtf8(GetEnv(), extraData);
        if (body.empty()) {
            return false;
        }
        options.SetBody(body.c_str(), body.size());
        return true;
    }

    if (NapiUtils::ValueIsArrayBuffer(GetEnv(), extraData)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), extraData, &length);
        if (data == nullptr) {
            return false;
        }
        options.SetBody(data, length);
        return true;
    }

    if (type == napi_object) {
        std::string body = NapiUtils::GetStringFromValueUtf8(GetEnv(), NapiUtils::JsonStringify(GetEnv(), extraData));
        if (body.empty()) {
            return false;
        }
        options.SetBody(body.c_str(), body.length());
        return true;
    }

    NETSTACK_LOGE("only support string arraybuffer and object");
    return false;
}

void RequestContext::ParseCaPath(napi_value optionsValue)
{
    std::string caPath = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CA_PATH);
    if (!caPath.empty()) {
        options.SetCaPath(caPath);
    }
}

void RequestContext::ParseDohUrl(napi_value optionsValue)
{
    std::string dohUrl = NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_DOH_URL);
    if (!dohUrl.empty()) {
        options.SetDohUrl(dohUrl);
    }
}

void RequestContext::ParseResumeFromToNumber(napi_value optionsValue)
{
    napi_env env = GetEnv();
    int64_t from = NapiUtils::GetInt64Property(env, optionsValue, HttpConstant::PARAM_KEY_RESUME_FROM);
    int64_t to = NapiUtils::GetInt64Property(env, optionsValue, HttpConstant::PARAM_KEY_RESUME_TO);
    options.SetRangeNumber(from, to);
}

void RequestContext::UrlAndOptions(napi_value urlValue, napi_value optionsValue)
{
    options.SetUrl(NapiUtils::GetStringFromValueUtf8(GetEnv(), urlValue));

    if (NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD)) {
        napi_value requestMethod = NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD);
        if (NapiUtils::GetValueType(GetEnv(), requestMethod) == napi_string) {
            options.SetMethod(NapiUtils::GetStringPropertyUtf8(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_METHOD));
        }
    }

    ParseNumberOptions(optionsValue);
    ParseUsingHttpProxy(optionsValue);
    ParseClientCert(optionsValue);

    /* parse extra data here to recover header */
    if (!ParseExtraData(optionsValue)) {
        return;
    }

    ParseHeader(optionsValue);
    ParseCaPath(optionsValue);
    ParseDohUrl(optionsValue);
    ParseResumeFromToNumber(optionsValue);
    ParseDnsServers(optionsValue);
    ParseMultiFormData(optionsValue);
    SetParseOK(true);
}

bool RequestContext::IsUsingCache() const
{
    return usingCache_;
}

void RequestContext::SetCurlHeaderList(curl_slist *curlHeaderList)
{
    curlHeaderList_ = curlHeaderList;
}

curl_slist *RequestContext::GetCurlHeaderList()
{
    return curlHeaderList_;
}

void RequestContext::SetCurlHostList(curl_slist *curlHostList)
{
    curlHostList_ = curlHostList;
}

curl_slist *RequestContext::GetCurlHostList()
{
    return curlHostList_;
}

RequestContext::~RequestContext()
{
    if (curlHeaderList_ != nullptr) {
        curl_slist_free_all(curlHeaderList_);
    }
    if (curlHostList_ != nullptr) {
        curl_slist_free_all(curlHostList_);
    }
    if (multipart_ != nullptr) {
        curl_mime_free(multipart_);
        multipart_ = nullptr;
    }
    NETSTACK_LOGD("the destructor of request context is invoked");
}

void RequestContext::SetCacheResponse(const HttpResponse &cacheResponse)
{
    cacheResponse_ = cacheResponse;
}
void RequestContext::SetResponseByCache()
{
    response = cacheResponse_;
}

int32_t RequestContext::GetErrorCode() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }

    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    if (BaseContext::IsNoAllowedHost()) {
        return HTTP_NOT_ALLOWED_HOST;
    }

    if (HTTP_ERR_MAP.find(err + HTTP_ERROR_CODE_BASE) != HTTP_ERR_MAP.end()) {
        return err + HTTP_ERROR_CODE_BASE;
    }
    return HTTP_UNKNOWN_OTHER_ERROR;
}

std::string RequestContext::GetErrorMessage() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }

    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    if (BaseContext::IsNoAllowedHost()) {
        return HTTP_ERR_MAP.at(HTTP_NOT_ALLOWED_HOST);
    }

    auto pos = HTTP_ERR_MAP.find(err + HTTP_ERROR_CODE_BASE);
    if (pos != HTTP_ERR_MAP.end()) {
        return pos->second;
    }
    return HTTP_ERR_MAP.at(HTTP_UNKNOWN_OTHER_ERROR);
}

void RequestContext::EnableRequestInStream()
{
    requestInStream_ = true;
}

bool RequestContext::IsRequestInStream() const
{
    return requestInStream_;
}

void RequestContext::SetDlLen(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(dlLenLock_);
    LoadBytes dlBytes{nowLen, totalLen};
    dlBytes_.push(dlBytes);
}

void RequestContext::SetCertsPath(std::vector<std::string> &&certPathList, const std::string &certFile)
{
    certsPath_.certPathList = std::move(certPathList);
    certsPath_.certFile = certFile;
}
 
const CertsPath& RequestContext::GetCertsPath()
{
    return certsPath_;
}

LoadBytes RequestContext::GetDlLen()
{
    std::lock_guard<std::mutex> lock(dlLenLock_);
    LoadBytes dlBytes;
    if (!dlBytes_.empty()) {
        dlBytes.nLen = dlBytes_.front().nLen;
        dlBytes.tLen = dlBytes_.front().tLen;
        dlBytes_.pop();
    }
    return dlBytes;
}

void RequestContext::SetUlLen(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    if (!ulBytes_.empty()) {
        ulBytes_.pop();
    }
    LoadBytes ulBytes{nowLen, totalLen};
    ulBytes_.push(ulBytes);
}

LoadBytes RequestContext::GetUlLen()
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    LoadBytes ulBytes;
    if (!ulBytes_.empty()) {
        ulBytes.nLen = ulBytes_.back().nLen;
        ulBytes.tLen = ulBytes_.back().tLen;
    }
    return ulBytes;
}

bool RequestContext::CompareWithLastElement(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    if (ulBytes_.empty()) {
        return false;
    }
    const LoadBytes &lastElement = ulBytes_.back();
    return nowLen == lastElement.nLen && totalLen == lastElement.tLen;
}

void RequestContext::SetTempData(const void *data, size_t size)
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    std::string tempString;
    tempString.append(reinterpret_cast<const char *>(data), size);
    tempData_.push(tempString);
}

std::string RequestContext::GetTempData()
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    if (!tempData_.empty()) {
        return tempData_.front();
    }
    return {};
}

void RequestContext::PopTempData()
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    if (!tempData_.empty()) {
        tempData_.pop();
    }
}

void RequestContext::ParseDnsServers(napi_value optionsValue)
{
    napi_env env = GetEnv();
    if (!NapiUtils::HasNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_DNS_SERVERS)) {
        NETSTACK_LOGD("ParseDnsServers no data");
        return;
    }
    napi_value dnsServerValue = NapiUtils::GetNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_DNS_SERVERS);
    if (NapiUtils::GetValueType(env, dnsServerValue) != napi_object) {
        return;
    }
    uint32_t dnsLength = NapiUtils::GetArrayLength(env, dnsServerValue);
    if (dnsLength == 0) {
        return;
    }
    std::vector<std::string> dnsServers;
    uint32_t dnsSize = 0;
    for (uint32_t i = 0; i < dnsLength && dnsSize < DNS_SERVER_SIZE; i++) {
        napi_value element = NapiUtils::GetArrayElement(env, dnsServerValue, i);
        std::string dnsServer = NapiUtils::GetStringFromValueUtf8(env, element);
        if (dnsServer.length() == 0) {
            continue;
        }
        if (!CommonUtils::IsValidIPV4(dnsServer) && !CommonUtils::IsValidIPV6(dnsServer)) {
            continue;
        }
        dnsServers.push_back(dnsServer);
        dnsSize++;
    }
    if (dnsSize == 0 || dnsServers.data() == nullptr || dnsServers.empty()) {
        NETSTACK_LOGD("dnsServersArray is empty.");
        return;
    }
    options.SetDnsServers(dnsServers);
    NETSTACK_LOGD("SetDnsServers success");
}

void RequestContext::CachePerformanceTimingItem(const std::string &key, double value)
{
    performanceTimingMap_[key] = value;
}

void RequestContext::StopAndCacheNapiPerformanceTiming(const char *key)
{
    Timing::Timer &timer = timerMap_.RecieveTimer(key);
    timer.Stop();
    CachePerformanceTimingItem(key, timer.Elapsed());
}

void RequestContext::SetPerformanceTimingToResult(napi_value result)
{
    if (performanceTimingMap_.empty()) {
        NETSTACK_LOGD("Get performanceTiming data is empty.");
        return;
    }
    napi_value performanceTimingValue;
    napi_env env = GetEnv();
    napi_create_object(env, &performanceTimingValue);
    for (const auto& pair : performanceTimingMap_) {
        NapiUtils::SetDoubleProperty(env, performanceTimingValue, pair.first, pair.second);
    }
    NapiUtils::SetNamedProperty(env, result, HttpConstant::RESPONSE_PERFORMANCE_TIMING, performanceTimingValue);
}

void RequestContext::ParseClientCert(napi_value optionsValue)
{
    if (!NapiUtils::HasNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CLIENT_CERT)) {
        return;
    }
    napi_value clientCertValue =
        NapiUtils::GetNamedProperty(GetEnv(), optionsValue, HttpConstant::PARAM_KEY_CLIENT_CERT);
    napi_valuetype type = NapiUtils::GetValueType(GetEnv(), clientCertValue);
    if (type != napi_object) {
        return;
    }
    std::string cert = NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_CERT);
    std::string certType =
        NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_CERT_TYPE);
    std::string key = NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_KEY);
    Secure::SecureChar keyPasswd = Secure::SecureChar(
        NapiUtils::GetStringPropertyUtf8(GetEnv(), clientCertValue, HttpConstant::HTTP_CLIENT_KEY_PASSWD));
    options.SetClientCert(cert, certType, key, keyPasswd);
}

void RequestContext::ParseMultiFormData(napi_value optionsValue)
{
    napi_env env = GetEnv();
    if (!NapiUtils::HasNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_MULTI_FORM_DATA_LIST)) {
        NETSTACK_LOGD("ParseMultiFormData multiFormDataList is null.");
        return;
    }
    napi_value multiFormDataListValue =
        NapiUtils::GetNamedProperty(env, optionsValue, HttpConstant::PARAM_KEY_MULTI_FORM_DATA_LIST);
    if (NapiUtils::GetValueType(env, multiFormDataListValue) != napi_object) {
        NETSTACK_LOGD("ParseMultiFormData multiFormDataList type is not object.");
        return;
    }
    uint32_t dataLength = NapiUtils::GetArrayLength(env, multiFormDataListValue);
    if (dataLength == 0) {
        NETSTACK_LOGD("ParseMultiFormData multiFormDataList length is 0.");
        return;
    }
    for (uint32_t i = 0; i < dataLength; i++) {
        napi_value formDataValue = NapiUtils::GetArrayElement(env, multiFormDataListValue, i);
        MultiFormData multiFormData = NapiValue2FormData(formDataValue);
        options.AddMultiFormData(multiFormData);
    }
}

MultiFormData RequestContext::NapiValue2FormData(napi_value formDataValue)
{
    napi_env env = GetEnv();
    MultiFormData multiFormData;
    multiFormData.name = NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_NAME);
    multiFormData.contentType =
        NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_CONTENT_TYPE);
    multiFormData.remoteFileName =
        NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_REMOTE_FILE_NAME);
    RequestContext::SaveFormData(
        env, NapiUtils::GetNamedProperty(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_DATA), multiFormData);
    multiFormData.filePath =
        NapiUtils::GetStringPropertyUtf8(env, formDataValue, HttpConstant::HTTP_MULTI_FORM_DATA_FILE_PATH);
    return multiFormData;
}

void RequestContext::SaveFormData(napi_env env, napi_value dataValue, MultiFormData &multiFormData)
{
    napi_valuetype type = NapiUtils::GetValueType(env, dataValue);
    if (type == napi_string) {
        multiFormData.data = NapiUtils::GetStringFromValueUtf8(GetEnv(), dataValue);
        NETSTACK_LOGD("SaveFormData string");
    } else if (NapiUtils::ValueIsArrayBuffer(GetEnv(), dataValue)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), dataValue, &length);
        if (data == nullptr) {
            return;
        }
        multiFormData.data = std::string(static_cast<const char *>(data), length);
        NETSTACK_LOGD("SaveFormData ArrayBuffer");
    } else if (type == napi_object) {
        multiFormData.data = NapiUtils::GetStringFromValueUtf8(
            GetEnv(), NapiUtils::JsonStringify(GetEnv(), dataValue));
        NETSTACK_LOGD("SaveFormData Object");
    } else {
        NETSTACK_LOGD("only support string, ArrayBuffer and Object");
    }
}

void RequestContext::SetMultipart(curl_mime *multipart)
{
    multipart_ = multipart;
}

int32_t RequestContext::GetTaskId() const
{
    return taskId_;
}

void RequestContext::SetModuleId(uint64_t moduleId)
{
    moduleId_ = moduleId;
}

uint64_t RequestContext::GetModuleId() const
{
    return moduleId_;
}

bool RequestContext::IsAtomicService() const
{
    return isAtomicService_;
}

void RequestContext::SetAtomicService(bool isAtomicService)
{
    isAtomicService_ = isAtomicService;
}

void RequestContext::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

std::string RequestContext::GetBundleName() const
{
    return bundleName_;
}
} // namespace OHOS::NetStack::Http
