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

#include "constant.h"
#include "curl/curl.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

#include "http_request_options.h"
#include "secure_char.h"

namespace OHOS::NetStack::Http {
static constexpr const uint32_t MIN_PRIORITY = 1;
static constexpr const uint32_t MAX_PRIORITY = 1000;

static constexpr const int64_t MIN_RESUM_NUMBER = 1;
static constexpr const int64_t MAX_RESUM_NUMBER = 4294967296;

HttpRequestOptions::HttpRequestOptions()
    : method_(HttpConstant::HTTP_METHOD_GET),
      readTimeout_(HttpConstant::DEFAULT_READ_TIMEOUT),
      maxLimit_(HttpConstant::DEFAULT_MAX_LIMIT),
      connectTimeout_(HttpConstant::DEFAULT_CONNECT_TIMEOUT),
      usingProtocol_(HttpProtocol::HTTP_NONE),
      dataType_(HttpDataType::NO_DATA_TYPE),
      priority_(MIN_PRIORITY),
      usingHttpProxyType_(UsingHttpProxyType::USE_DEFAULT),
      httpProxyPort_(0),
      resumeFromNumber_(0),
      resumeToNumber_(0)
{
#ifndef WINDOWS_PLATFORM
    caPath_ = HttpConstant::HTTP_DEFAULT_CA_PATH;
#endif // WINDOWS_PLATFORM
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

void HttpRequestOptions::SetMaxLimit(uint32_t maxLimit)
{
    if (maxLimit > HttpConstant::MAX_LIMIT) {
        NETSTACK_LOGD("maxLimit setting exceeds the maximum limit, use max limit");
        maxLimit_ = HttpConstant::MAX_LIMIT;
        return;
    }
    maxLimit_ = maxLimit;
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

uint32_t HttpRequestOptions::GetMaxLimit() const
{
    return maxLimit_;
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
    if (usingProtocol_ == HttpProtocol::HTTP3) {
        NETSTACK_LOGD("CURL_HTTP_VERSION_3");
        return CURL_HTTP_VERSION_3;
    }
    if (usingProtocol_ == HttpProtocol::HTTP2) {
        NETSTACK_LOGD("CURL_HTTP_VERSION_2_0");
        return CURL_HTTP_VERSION_2_0;
    }
    if (usingProtocol_ == HttpProtocol::HTTP1_1) {
        NETSTACK_LOGD("CURL_HTTP_VERSION_1_1");
        return CURL_HTTP_VERSION_1_1;
    }
    return CURL_HTTP_VERSION_NONE;
}

void HttpRequestOptions::SetRequestTime(const std::string &time)
{
    requestTime_ = time;
}

const std::string &HttpRequestOptions::GetRequestTime() const
{
    return requestTime_;
}

void HttpRequestOptions::SetHttpDataType(HttpDataType dataType)
{
    if (dataType != HttpDataType::STRING && dataType != HttpDataType::ARRAY_BUFFER &&
        dataType != HttpDataType::OBJECT) {
        return;
    }
    dataType_ = dataType;
}

HttpDataType HttpRequestOptions::GetHttpDataType() const
{
    return dataType_;
}

void HttpRequestOptions::SetPriority(uint32_t priority)
{
    if (priority < MIN_PRIORITY || priority > MAX_PRIORITY) {
        return;
    }
    priority_ = priority;
}

uint32_t HttpRequestOptions::GetPriority() const
{
    return priority_;
}

void HttpRequestOptions::SetUsingHttpProxyType(UsingHttpProxyType type)
{
    usingHttpProxyType_ = type;
}

UsingHttpProxyType HttpRequestOptions::GetUsingHttpProxyType() const
{
    return usingHttpProxyType_;
}

void HttpRequestOptions::SetSpecifiedHttpProxy(const std::string &host, int32_t port, const std::string &exclusionList)
{
    httpProxyHost_ = host;
    httpProxyPort_ = port;
    httpProxyExclusions_ = exclusionList;
}

void HttpRequestOptions::GetSpecifiedHttpProxy(std::string &host, int32_t &port, std::string &exclusionList)
{
    host = httpProxyHost_;
    port = httpProxyPort_;
    exclusionList = httpProxyExclusions_;
}

void HttpRequestOptions::SetClientCert(
    std::string &cert, std::string &certType, std::string &key, Secure::SecureChar &keyPasswd)
{
    cert_ = cert;
    certType_ = certType;
    key_ = key;
    keyPasswd_ = keyPasswd;
}

void HttpRequestOptions::AddMultiFormData(const MultiFormData &multiFormData)
{
    multiFormDataList_.push_back(multiFormData);
}

void HttpRequestOptions::GetClientCert(
    std::string &cert, std::string &certType, std::string &key, Secure::SecureChar &keyPasswd)
{
    cert = cert_;
    certType = certType_;
    key = key_;
    keyPasswd = keyPasswd_;
}

void HttpRequestOptions::SetCaPath(const std::string &path)
{
    if (path.empty()) {
        return;
    }

    caPath_ = path;
}

const std::string &HttpRequestOptions::GetCaPath() const
{
    return caPath_;
}

void HttpRequestOptions::SetDohUrl(const std::string &dohUrl)
{
    if (dohUrl.empty()) {
        return;
    }
    dohUrl_ = dohUrl;
}

const std::string &HttpRequestOptions::GetDohUrl() const
{
    return dohUrl_;
}

void HttpRequestOptions::SetRangeNumber(int64_t resumeFromNumber, int64_t resumeToNumber)
{
    if (resumeFromNumber >= MIN_RESUM_NUMBER && resumeFromNumber <= MAX_RESUM_NUMBER) {
        resumeFromNumber_ = resumeFromNumber;
    }
    if (resumeToNumber >= MIN_RESUM_NUMBER && resumeToNumber <= MAX_RESUM_NUMBER) {
        resumeToNumber_ = resumeToNumber;
    }
}

std::string HttpRequestOptions::GetRangeString() const
{
    bool isSetFrom = resumeFromNumber_ >= MIN_RESUM_NUMBER;
    bool isSetTo = resumeToNumber_ >= MIN_RESUM_NUMBER;
    if (!isSetTo && !isSetFrom) {
        return "";
    } else if (!isSetTo && isSetFrom) {
        return std::to_string(resumeFromNumber_) + '-';
    } else if (isSetTo && !isSetFrom) {
        return '-' + std::to_string(resumeToNumber_);
    } else if (resumeToNumber_ <= resumeFromNumber_) {
        return "";
    } else {
        return std::to_string(resumeFromNumber_) + '-' + std::to_string(resumeToNumber_);
    }
}

const std::vector<std::string> &HttpRequestOptions::GetDnsServers() const
{
    return dnsServers_;
}

void HttpRequestOptions::SetDnsServers(const std::vector<std::string> &dnsServers)
{
    dnsServers_ = dnsServers;
}

std::vector<MultiFormData> HttpRequestOptions::GetMultiPartDataList()
{
    return multiFormDataList_;
}
} // namespace OHOS::NetStack::Http