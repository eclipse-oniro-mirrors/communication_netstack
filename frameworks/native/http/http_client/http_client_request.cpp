/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <vector>
#include <algorithm>
#include <cctype>

#include "http_client_request.h"
#include "http_client_constant.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
static constexpr const uint32_t HTTP_MIN_PRIORITY = 1;
static constexpr const uint32_t HTTP_DEFAULT_PRIORITY = 500;
static constexpr const uint32_t HTTP_MAX_PRIORITY = 1000;
static constexpr const uint32_t HTTP_DEFAULT_RANGE = 0;

HttpClientRequest::HttpClientRequest()
    : method_(HttpConstant::HTTP_METHOD_GET),
      timeout_(HttpConstant::DEFAULT_READ_TIMEOUT),
      connectTimeout_(HttpConstant::DEFAULT_CONNECT_TIMEOUT),
      protocol_(HttpProtocol::HTTP_NONE),
      proxyType_(HttpProxyType::NOT_USE),
      priority_(HTTP_DEFAULT_PRIORITY),
      resumeFrom_(HTTP_DEFAULT_RANGE),
      resumeTo_(HTTP_DEFAULT_RANGE),
      sslType_(SslType::TLS)
{
}

void HttpClientRequest::SetURL(const std::string &url)
{
    url_ = url;
}

void HttpClientRequest::SetHeader(const std::string &key, const std::string &val)
{
    headers_[CommonUtils::ToLower(key)] = val;
}

bool HttpClientRequest::MethodForGet(const std::string &method)
{
    return (method == HttpConstant::HTTP_METHOD_HEAD || method == HttpConstant::HTTP_METHOD_OPTIONS ||
            method == HttpConstant::HTTP_METHOD_TRACE || method == HttpConstant::HTTP_METHOD_GET ||
            method == HttpConstant::HTTP_METHOD_CONNECT);
}

bool HttpClientRequest::MethodForPost(const std::string &method)
{
    return (method == HttpConstant::HTTP_METHOD_POST || method == HttpConstant::HTTP_METHOD_PUT ||
            method == HttpConstant::HTTP_METHOD_DELETE);
}

void HttpClientRequest::SetMethod(const std::string &method)
{
    if (!MethodForGet(method) && !MethodForPost(method) && !method.empty()) {
        NETSTACK_LOGE("HttpClientRequest::SetMethod method %{public}s not supported", method.c_str());
        return;
    }

    method_ = method;
}

void HttpClientRequest::SetBody(const void *data, size_t length)
{
    body_.append(static_cast<const char *>(data), length);
}

void HttpClientRequest::SetTimeout(unsigned int timeout)
{
    timeout_ = timeout;
}

void HttpClientRequest::SetConnectTimeout(unsigned int timeout)
{
    connectTimeout_ = timeout;
}

void HttpClientRequest::SetHttpProtocol(HttpProtocol protocol)
{
    protocol_ = protocol;
}

void HttpClientRequest::SetHttpProxyType(HttpProxyType type)
{
    proxyType_ = type;
}

void HttpClientRequest::SetCaPath(const std::string &path)
{
    if (path.empty()) {
        NETSTACK_LOGE("HttpClientRequest::SetCaPath path is empty");
        return;
    }
    caPath_ = path;
}

void HttpClientRequest::SetPriority(unsigned int priority)
{
    if (priority < HTTP_MIN_PRIORITY || priority > HTTP_MAX_PRIORITY) {
        NETSTACK_LOGE("HttpClientRequest::SetPriority priority %{public}d is invalid", priority);
        return;
    }
    priority_ = priority;
}

const std::string &HttpClientRequest::GetURL() const
{
    return url_;
}

const std::string &HttpClientRequest::GetMethod() const
{
    return method_;
}

const std::string &HttpClientRequest::GetBody() const
{
    return body_;
}

const std::map<std::string, std::string> &HttpClientRequest::GetHeaders() const
{
    return headers_;
}

unsigned int HttpClientRequest::GetTimeout()
{
    return timeout_;
}

unsigned int HttpClientRequest::GetConnectTimeout()
{
    return connectTimeout_;
}

HttpProtocol HttpClientRequest::GetHttpProtocol()
{
    return protocol_;
}

HttpProxyType HttpClientRequest::GetHttpProxyType()
{
    return proxyType_;
}

const std::string &HttpClientRequest::GetCaPath()
{
    return caPath_;
}

uint32_t HttpClientRequest::GetPriority() const
{
    return priority_;
}

void HttpClientRequest::SetHttpProxy(const HttpProxy &proxy)
{
    proxy_ = proxy;
}

const HttpProxy &HttpClientRequest::GetHttpProxy() const
{
    return proxy_;
}

void HttpClientRequest::SetRequestTime(const std::string &time)
{
    requestTime_ = time;
}

const std::string &HttpClientRequest::GetRequestTime() const
{
    return requestTime_;
}

void HttpClientRequest::SetResumeFrom(int64_t resumeFrom)
{
    if (resumeFrom >= MIN_RESUM_NUMBER && resumeFrom <= MAX_RESUM_NUMBER) {
        resumeFrom_ = resumeFrom;
    }
}

void HttpClientRequest::SetResumeTo(int64_t resumeTo)
{
    if (resumeTo >= MIN_RESUM_NUMBER && resumeTo <= MAX_RESUM_NUMBER) {
        resumeTo_ = resumeTo;
    }
}

int64_t HttpClientRequest::GetResumeFrom() const
{
    return resumeFrom_;
}

int64_t HttpClientRequest::GetResumeTo() const
{
    return resumeTo_;
}

void HttpClientRequest::SetClientCert(const HttpClientCert &clientCert)
{
    clientCert_ = clientCert;
}

const HttpClientCert &HttpClientRequest::GetClientCert() const
{
    return clientCert_;
}

void HttpClientRequest::SetAddressFamily(const std::string &addressFamily)
{
    addressFamily_ = addressFamily;
}

const std::string &HttpClientRequest::GetAddressFamily() const
{
    return addressFamily_;
}

void HttpClientRequest::SetSslType(SslType sslType)
{
    sslType_ = sslType;
}

const SslType &HttpClientRequest::GetSslType() const
{
    return sslType_;
}

void HttpClientRequest::SetClientEncCert(const HttpClientCert &clientEncCert)
{
    clientEncCert_ = clientEncCert;
}

const HttpClientCert &HttpClientRequest::GetClientEncCert() const
{
    return clientEncCert_;
}

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS
