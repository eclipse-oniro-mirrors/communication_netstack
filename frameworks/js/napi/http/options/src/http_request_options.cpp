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

#include "http_request_options.h"

#include "constant.h"

namespace OHOS::NetStack {

HttpRequestOptions::HttpRequestOptions()
    : method_(HttpConstant::HTTP_METHOD_GET),
      readTimeout_(HttpConstant::DEFAULT_READ_TIMEOUT),
      connectTimeout_(HttpConstant::DEFAULT_CONNECT_TIMEOUT),
      ifModifiedSince_(HttpConstant::DEFAULT_IF_MODIFIED_SINCE),
      fixedLengthStreamingMode_(HttpConstant::DEFAULT_FIXED_LENGTH_STREAMING_MODE)
{
    header_[HttpConstant::HTTP_CONTENT_TYPE] = HttpConstant::HTTP_CONTENT_TYPE_TEXT; // default
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

void HttpRequestOptions::SetIfModifiedSince(uint32_t ifModifiedSince)
{
    ifModifiedSince_ = ifModifiedSince;
}

void HttpRequestOptions::SetFixedLengthStreamingMode(int32_t fixedLengthStreamingMode)
{
    fixedLengthStreamingMode_ = fixedLengthStreamingMode;
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

uint32_t HttpRequestOptions::GetIfModifiedSince() const
{
    return ifModifiedSince_;
}

int32_t HttpRequestOptions::GetFixedLengthStreamingMode() const
{
    return fixedLengthStreamingMode_;
}

} // namespace OHOS::NetStack