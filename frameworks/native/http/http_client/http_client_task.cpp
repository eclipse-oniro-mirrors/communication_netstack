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

#include <iostream>
#include <memory>

#include "http_client_task.h"
#include "http_client.h"
#include "http_client_constant.h"
#include "http_client_time.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

#define NETSTACK_CURL_EASY_SET_OPTION(handle, opt, data)                                                 \
    do {                                                                                                 \
        CURLcode result = curl_easy_setopt(handle, opt, data);                                           \
        if (result != CURLE_OK) {                                                                        \
            const char *err = curl_easy_strerror(result);                                                \
            error_.SetCURLResult(result);                                                                \
            NETSTACK_LOGE("Failed to set option: %{public}s, %{public}s %{public}d", #opt, err, result); \
            return false;                                                                                \
        }                                                                                                \
    } while (0)

namespace OHOS {
namespace NetStack {
namespace HttpClient {

static constexpr size_t MAX_LIMIT = 5 * 1024 * 1024;
std::atomic<uint32_t> HttpClientTask::nextTaskId_(0);

HttpClientTask::HttpClientTask(const HttpClientRequest &request)
    : request_(request),
      type_(DEFAULT),
      status_(IDLE),
      taskId_(nextTaskId_++),
      curlHeaderList_(nullptr),
      canceled_(false)
{
    NETSTACK_LOGI("HttpClientTask::HttpClientTask() taskId_=%{public}d URL=%{public}s", taskId_,
                  request_.GetURL().c_str());

    curlHandle_ = curl_easy_init();
    if (!curlHandle_) {
        NETSTACK_LOGE("Failed to create task!");
        return;
    }

    SetCurlOptions();
}

HttpClientTask::HttpClientTask(const HttpClientRequest &request, TaskType type, const std::string &filePath)
    : request_(request),
      type_(type),
      status_(IDLE),
      taskId_(nextTaskId_++),
      curlHeaderList_(nullptr),
      canceled_(false),
      filePath_(filePath)
{
    NETSTACK_LOGI(
        "HttpClientTask::HttpClientTask() taskId_=%{public}d URL=%{public}s type=%{public}d filePath=%{public}s",
        taskId_, request_.GetURL().c_str(), type_, filePath_.c_str());

    curlHandle_ = curl_easy_init();
    if (!curlHandle_) {
        NETSTACK_LOGE("Failed to create task!");
        return;
    }

    SetCurlOptions();
}

HttpClientTask::~HttpClientTask()
{
    NETSTACK_LOGD("HttpClientTask::~HttpClientTask()");
    if (curlHeaderList_ != nullptr) {
        curl_slist_free_all(curlHeaderList_);
        curlHeaderList_ = nullptr;
    }

    if (curlHandle_) {
        curl_easy_cleanup(curlHandle_);
        curlHandle_ = nullptr;
    }

    if (file_ != nullptr) {
        fclose(file_);
        file_ = nullptr;
    }
}

uint32_t HttpClientTask::GetHttpVersion(HttpProtocol ptcl) const
{
    if (ptcl == HttpProtocol::HTTP1_1) {
        NETSTACK_LOGD("CURL_HTTP_VERSION_1_1");
        return CURL_HTTP_VERSION_1_1;
    } else if (ptcl == HttpProtocol::HTTP2) {
        NETSTACK_LOGD("CURL_HTTP_VERSION_2_0");
        return CURL_HTTP_VERSION_2_0;
    }
    return CURL_HTTP_VERSION_NONE;
}

void HttpClientTask::GetHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions, std::string &userpwd,
                                      bool &tunnel)
{
    if (request_.GetHttpProxyType() == HttpProxyType::USE_SPECIFIED) {
        HttpProxy proxy = request_.GetHttpProxy();
        host = proxy.host;
        port = proxy.port;
        exclusions = proxy.exclusions;
        userpwd = proxy.userpwd;
        tunnel = proxy.tunnel;
    }
}

bool HttpClientTask::SetOtherCurlOption(CURL *handle)
{
    // set proxy
    std::string host, exclusions, userpwd;
    int32_t port = 0;
    bool tunnel = false;
    GetHttpProxyInfo(host, port, exclusions, userpwd, tunnel);
    if (!host.empty()) {
        NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_PROXY, host.c_str());
        NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_PROXYPORT, port);
        NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        if (!exclusions.empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_NOPROXY, exclusions.c_str());
        }
        if (!userpwd.empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_PROXYUSERPWD, userpwd.c_str());
        }
        if (tunnel) {
            NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_HTTPPROXYTUNNEL, 1L);
        }
    }

#if NO_SSL_CERTIFICATION
    // in real life, you should buy a ssl certification and rename it to /etc/ssl/cert.pem
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_SSL_VERIFYHOST, 0L);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_SSL_VERIFYPEER, 0L);
#else
#ifndef WINDOWS_PLATFORM
    NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_CAINFO, request_.GetCaPath().c_str());
#endif // WINDOWS_PLATFORM
#endif // NO_SSL_CERTIFICATION

#if HTTP_CURL_PRINT_VERBOSE
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_VERBOSE, 1L);
#endif

#ifndef WINDOWS_PLATFORM
    NETSTACK_CURL_EASY_SET_OPTION(handle, CURLOPT_ACCEPT_ENCODING, HttpConstant::HTTP_CONTENT_ENCODING_GZIP);
#endif

    return true;
}

bool HttpClientTask::SetUploadOptions(CURL *handle)
{
    if (filePath_.empty()) {
        NETSTACK_LOGE("HttpClientTask::SetUploadOptions() filePath_ is empty");
        error_.SetErrorCode(HttpErrorCode::HTTP_UPLOAD_FAILED);
        return false;
    }

    file_ = fopen(filePath_.c_str(), "rb");
    if (file_ == nullptr) {
        NETSTACK_LOGE("HttpClientTask::SetUploadOptions() Failed to open file %{public}s", filePath_.c_str());
        error_.SetErrorCode(HttpErrorCode::HTTP_UPLOAD_FAILED);
        return false;
    }

    NETSTACK_LOGI("HttpClientTask::SetUploadOptions() filePath_=%{public}s", filePath_.c_str());
    fseek(file_, 0, SEEK_END);
    long size = ftell(file_);
    rewind(file_);

    // Set the file data and file size to upload
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_READDATA, file_);
    NETSTACK_LOGI("HttpClientTask::SetUploadOptions() CURLOPT_INFILESIZE=%{public}ld", size);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_INFILESIZE, size);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_UPLOAD, 1L);

    return true;
}

bool HttpClientTask::SetCurlOptions()
{
    auto method = request_.GetMethod();
    if (method == HttpConstant::HTTP_METHOD_HEAD) {
        NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_NOBODY, 1L);
    }

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_URL, request_.GetURL().c_str());

    if (type_ == TaskType::UPLOAD) {
        if (!SetUploadOptions(curlHandle_)) {
            return false;
        }
    } else {
        NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_CUSTOMREQUEST, request_.GetMethod().c_str());

        if ((method == HttpConstant::HTTP_METHOD_POST || method == HttpConstant::HTTP_METHOD_PUT) &&
            !request_.GetBody().empty()) {
            NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_POST, 1L);
            NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_POSTFIELDS, request_.GetBody().c_str());
            NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_POSTFIELDSIZE, request_.GetBody().size());
        }
    }

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_XFERINFOFUNCTION, ProgressCallback);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_XFERINFODATA, &taskId_);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_NOPROGRESS, 0L);

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_WRITEFUNCTION, DataReceiveCallback);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_WRITEDATA, &taskId_);

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_HEADERFUNCTION, HeaderReceiveCallback);
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_HEADERDATA, &taskId_);

    if (curlHeaderList_ != nullptr) {
        curl_slist_free_all(curlHeaderList_);
        curlHeaderList_ = nullptr;
    }
    for (auto &header : request_.GetHeaders()) {
        std::string headerStr = header.first + HttpConstant::HTTP_HEADER_SEPARATOR + header.second;
        curlHeaderList_ = curl_slist_append(curlHeaderList_, headerStr.c_str());
    }
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_HTTPHEADER, curlHeaderList_);

    // Some servers don't like requests that are made without a user-agent field, so we provide one
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_USERAGENT, HttpConstant::HTTP_DEFAULT_USER_AGENT);

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_FOLLOWLOCATION, 1L);

    /* first #undef CURL_DISABLE_COOKIES in curl config */
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_COOKIEFILE, "");

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_NOSIGNAL, 1L);

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_TIMEOUT_MS, request_.GetTimeout());
    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_CONNECTTIMEOUT_MS, request_.GetConnectTimeout());

    NETSTACK_CURL_EASY_SET_OPTION(curlHandle_, CURLOPT_HTTP_VERSION, GetHttpVersion(request_.GetHttpProtocol()));

    if (!SetOtherCurlOption(curlHandle_)) {
        return false;
    }

    return true;
}

bool HttpClientTask::Start()
{
    auto task = shared_from_this();
    if (task->GetStatus() != TaskStatus::IDLE) {
        NETSTACK_LOGI("HttpClientTask::Start() task is running, taskId_=%{public}d", task->GetTaskId());
        return false;
    }

    if (!CommonUtils::HasInternetPermission()) {
        NETSTACK_LOGE("HttpClientTask::Start() Don't Has Internet Permission()");
        error_.SetErrorCode(HttpErrorCode::HTTP_PERMISSION_DENIED_CODE);
        return false;
    }

    if (error_.GetErrorCode() != HttpErrorCode::HTTP_NONE_ERR) {
        NETSTACK_LOGE("HttpClientTask::Start() error_.GetErrorCode()=%{public}d", error_.GetErrorCode());
        return false;
    }

    request_.SetRequestTime(HttpTime::GetNowTimeGMT());

    HttpSession &session = HttpSession::GetInstance();
    NETSTACK_LOGD("HttpClientTask::Start() taskId_=%{public}d", taskId_);
    task->canceled_ = false;

    response_.SetRequestTime(HttpTime::GetNowTimeGMT());
    session.StartTask(task);

    return true;
}

void HttpClientTask::Cancel()
{
    canceled_ = true;
}

void HttpClientTask::SetStatus(TaskStatus status)
{
    status_ = status;
}

TaskStatus HttpClientTask::GetStatus()
{
    return status_;
}

TaskType HttpClientTask::GetType()
{
    return type_;
}

const std::string &HttpClientTask::GetFilePath()
{
    return filePath_;
}

unsigned int HttpClientTask::GetTaskId()
{
    return taskId_;
}

void HttpClientTask::OnSuccess(
    const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> &onSucceeded)
{
    onSucceeded_ = onSucceeded;
}

void HttpClientTask::OnCancel(
    const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> &onCanceled)
{
    onCanceled_ = onCanceled;
}

void HttpClientTask::OnFail(
    const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response,
                             const HttpClientError &error)> &onFailed)
{
    onFailed_ = onFailed;
}

void HttpClientTask::OnDataReceive(
    const std::function<void(const HttpClientRequest &request, const uint8_t *data, size_t length)> &onDataReceive)
{
    onDataReceive_ = onDataReceive;
}

void HttpClientTask::OnProgress(const std::function<void(const HttpClientRequest &request, u_long dlTotal, u_long dlNow,
                                                         u_long ulTotal, u_long ulNow)> &onProgress)
{
    onProgress_ = onProgress;
}

size_t HttpClientTask::DataReceiveCallback(const void *data, size_t size, size_t memBytes, void *userData)
{
    unsigned int taskId = *(unsigned int *)userData;
    NETSTACK_LOGD("HttpClientTask::DataReceiveCallback() taskId=%{public}d size=%{public}zu memBytes=%{public}zu",
                  taskId, size, memBytes);

    auto task = HttpSession::GetInstance().GetTaskById(taskId);
    if (task == nullptr) {
        NETSTACK_LOGE("HttpClientTask::DataReceiveCallback() task == nullptr");
        return 0;
    }

    if (task->canceled_) {
        NETSTACK_LOGD("HttpClientTask::DataReceiveCallback() canceled");
        return 0;
    }

    if (task->onDataReceive_) {
        HttpClientRequest request = task->request_;
        task->onDataReceive_(request, (const uint8_t *)data, size * memBytes);
    }

    if (task->response_.GetResult().size() < MAX_LIMIT) {
        task->response_.AppendResult(data, size * memBytes);
    }

    return size * memBytes;
}

int HttpClientTask::ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                     curl_off_t ulnow)
{
    unsigned int taskId = *(unsigned int *)userData;
    NETSTACK_LOGD(
        "HttpClientTask::ProgressCallback() taskId=%{public}d dltotal=%{public}lld dlnow=%{public}lld "
        "ultotal=%{public}lld ulnow=%{public}lld",
        taskId, dltotal, dlnow, ultotal, ulnow);

    auto task = HttpSession::GetInstance().GetTaskById(taskId);
    if (task == nullptr) {
        NETSTACK_LOGE("HttpClientTask::ProgressCallback() task == nullptr");
        return 0;
    }

    if (task->canceled_) {
        NETSTACK_LOGI("HttpClientTask::ProgressCallback() canceled");
        return CURLE_ABORTED_BY_CALLBACK;
    }

    if (task->onProgress_) {
        task->onProgress_(task->request_, dltotal, dlnow, ultotal, ulnow);
    }

    return 0;
}

size_t HttpClientTask::HeaderReceiveCallback(const void *data, size_t size, size_t memBytes, void *userData)
{
    unsigned int taskId = *(unsigned int *)userData;
    NETSTACK_LOGD("HttpClientTask::HeaderReceiveCallback() taskId=%{public}d size=%{public}zu memBytes=%{public}zu",
                  taskId, size, memBytes);

    if (size * memBytes > MAX_LIMIT) {
        NETSTACK_LOGE("HttpClientTask::HeaderReceiveCallback() size * memBytes(%{public}zu) > MAX_LIMIT(%{public}zu)",
                      size * memBytes, MAX_LIMIT);
        return 0;
    }

    auto task = HttpSession::GetInstance().GetTaskById(taskId);
    if (task == nullptr) {
        NETSTACK_LOGE("HttpClientTask::HeaderReceiveCallback() task == nullptr");
        return 0;
    }

    NETSTACK_LOGD("HttpClientTask::HeaderReceiveCallback() (const char *)data=%{public}s", (const char *)data);
    task->response_.AppendHeader((const char *)data, size * memBytes);

    return size * memBytes;
}

void HttpClientTask::ProcessCookie(CURL *handle)
{
    struct curl_slist *cookies = nullptr;
    if (handle == nullptr) {
        NETSTACK_LOGE("HttpClientTask::ProcessCookie() handle == nullptr");
        return;
    }

    CURLcode res = curl_easy_getinfo(handle, CURLINFO_COOKIELIST, &cookies);
    if (res != CURLE_OK) {
        NETSTACK_LOGE("HttpClientTask::ProcessCookie() curl_easy_getinfo() error! res = %{public}d", res);
        return;
    }

    while (cookies) {
        response_.AppendCookies(cookies->data, strlen(cookies->data));
        if (cookies->next != nullptr) {
            response_.AppendCookies(HttpConstant::HTTP_LINE_SEPARATOR, strlen(HttpConstant::HTTP_LINE_SEPARATOR));
        }
        cookies = cookies->next;
    }

    NETSTACK_LOGD("ProcessCookie() GetCookies() = %{public}s", response_.GetCookies().c_str());
    NETSTACK_LOGD("ProcessCookie() GetHeader() = %{public}s", response_.GetHeader().c_str());
}

bool HttpClientTask::ProcessResponseCode()
{
    CURLcode code = CURLE_OK;
    ResponseCode responseCode = ResponseCode::NONE;
    code = curl_easy_getinfo(curlHandle_, CURLINFO_RESPONSE_CODE, &responseCode);
    if (code != CURLE_OK) {
        error_.SetCURLResult(code);
        return false;
    }
    NETSTACK_LOGI("HttpClientTask::ProcessResponseCode() responseCode=%{public}d", responseCode);
    response_.SetResponseCode(responseCode);

    return true;
}

void HttpClientTask::ProcessResponse(CURLMsg *msg)
{
    CURLcode code = msg->data.result;
    NETSTACK_LOGI("HttpClientTask::ProcessResponse() taskid=%{public}d code=%{public}d", taskId_, code);
    error_.SetCURLResult(code);
    response_.SetResponseTime(HttpTime::GetNowTimeGMT());

    if (CURLE_ABORTED_BY_CALLBACK == code) {
        (void)ProcessResponseCode();
        if (onCanceled_) {
            onCanceled_(request_, response_);
        }
        return;
    }

    if (code != CURLE_OK) {
        if (onFailed_) {
            onFailed_(request_, response_, error_);
        }
        return;
    }

    ProcessCookie(curlHandle_);
    response_.ParseHeaders();

    if (ProcessResponseCode()) {
        if (onSucceeded_) {
            onSucceeded_(request_, response_);
        }
    } else if (onFailed_) {
        onFailed_(request_, response_, error_);
    }
}

void HttpClientTask::SetResponse(const HttpClientResponse &response)
{
    response_ = response;
}
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS
