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


namespace OHOS {
namespace NetStack {
namespace HttpClient {

std::atomic<uint32_t> HttpClientTask::nextTaskId_(0);

HttpClientTask::HttpClientTask(const HttpClientRequest &request)
    : request_(request),
      type_(DEFAULT),
      status_(IDLE),
      taskId_(nextTaskId_++),
      curlHeaderList_(nullptr),
      canceled_(false)
{
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
}

HttpClientTask::~HttpClientTask()
{
}

uint32_t HttpClientTask::GetHttpVersion(HttpProtocol ptcl) const
{
    return CURL_HTTP_VERSION_NONE;
}

void HttpClientTask::GetHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions, std::string &userpwd,
                                      bool &tunnel)
{
}

bool HttpClientTask::SetOtherCurlOption(CURL *handle)
{
    return true;
}

bool HttpClientTask::SetUploadOptions(CURL *handle)
{
    return true;
}

bool HttpClientTask::SetCurlOptions()
{
    return true;
}

bool HttpClientTask::Start()
{
    return true;
}

void HttpClientTask::Cancel()
{
}

void HttpClientTask::SetStatus(TaskStatus status)
{
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
}

void HttpClientTask::OnCancel(
    const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> &onCanceled)
{
}

void HttpClientTask::OnFail(
    const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response,
                             const HttpClientError &error)> &onFailed)
{
}

void HttpClientTask::OnDataReceive(
    const std::function<void(const HttpClientRequest &request, const uint8_t *data, size_t length)> &onDataReceive)
{
}

void HttpClientTask::OnProgress(const std::function<void(const HttpClientRequest &request, u_long dlTotal, u_long dlNow,
                                                         u_long ulTotal, u_long ulNow)> &onProgress)
{
}

size_t HttpClientTask::DataReceiveCallback(const void *data, size_t size, size_t memBytes, void *userData)
{
    return size * memBytes;
}

int HttpClientTask::ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                     curl_off_t ulnow)
{
    return 0;
}

size_t HttpClientTask::HeaderReceiveCallback(const void *data, size_t size, size_t memBytes, void *userData)
{
    return size * memBytes;
}

void HttpClientTask::ProcessCookie(CURL *handle)
{
}

bool HttpClientTask::ProcessResponseCode()
{
    return true;
}

void HttpClientTask::ProcessResponse(CURLMsg *msg)
{
}

void HttpClientTask::SetResponse(const HttpClientResponse &response)
{
}
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS
