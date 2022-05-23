/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "constant.h"
#include "curl/curl.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

#include "http_request_options.h"

namespace OHOS::NetStack {
HttpRequestOptions::HttpRequestOptions()
    : method_(HttpConstant::HTTP_METHOD_GET),
      readTimeout_(HttpConstant::DEFAULT_READ_TIMEOUT),
      connectTimeout_(HttpConstant::DEFAULT_CONNECT_TIMEOUT),
      usingProtocol_(HttpProtocol::HTTP_NONE)
{
    header_[CommonUtils::ToLower(HttpConstant::HTTP_CONTENT_TYPE)] = HttpConstant::HTTP_CONTENT_TYPE_JSON; // default
}

void HttpRequestOptions::SetUrl(const std::string &url)
{
    url_ = url;
}

void HttpRequestOptions::SetMethod(const std::string &method)
{
    method_ = method;
}

void HttpRequestOptions::SetBody(const void *data, size_t length)
{
    body_.append(static_cast<const char *>(data), length);
}

void HttpRequestOptions::SetHeader(const std::string &key, const std::string &val)
{
    header_[key] = val;
}

void HttpRequestOptions::SetReadTimeout(uint32_t readTimeout)
{
    readTimeout_ = readTimeout;
}

void HttpRequestOptions::SetConnectTimeout(uint32_t connectTimeout)
{
    connectTimeout_ = connectTimeout;
}

const std::string &HttpRequestOptions::GetUrl() const
{
    return url_;
}

const std::string &HttpRequestOptions::GetMethod() const
{
    return method_;
}

const std::string &HttpRequestOptions::GetBody() const
{
    return body_;
}

const std::map<std::string, std::string> &HttpRequestOptions::GetHeader() const
{
    return header_;
}

uint32_t HttpRequestOptions::GetReadTimeout() const
{
    return readTimeout_;
}

uint32_t HttpRequestOptions::GetConnectTimeout() const
{
    return connectTimeout_;
}

void HttpRequestOptions::SetUsingProtocol(HttpProtocol httpProtocol)
{
    usingProtocol_ = httpProtocol;
}

uint32_t HttpRequestOptions::GetHttpVersion() const
{
    if (usingProtocol_ == HttpProtocol::HTTP2) {
        NETSTACK_LOGI("CURL_HTTP_VERSION_2_0");
        return CURL_HTTP_VERSION_2_0;
    }
    if (usingProtocol_ == HttpProtocol::HTTP1_1) {
        NETSTACK_LOGI("CURL_HTTP_VERSION_1_1");
        return CURL_HTTP_VERSION_1_1;
    }
    NETSTACK_LOGI("CURL_HTTP_VERSION_NONE");
    return CURL_HTTP_VERSION_NONE;
}
} // namespace OHOS::NetStack