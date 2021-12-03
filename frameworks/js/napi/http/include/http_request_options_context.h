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

#ifndef HTTP_REQUEST_OPTIONS_CONTEXT_H
#define HTTP_REQUEST_OPTIONS_CONTEXT_H

#include "http_base_context.h"
#include "http_enum_define.h"
#include "http_response.h"

namespace OHOS {
namespace NetManagerStandard {
class HttpRequest;
class HttpRequestOptionsContext : public HttpBaseContext {
public:
    HttpRequest *httpRequestInfo_;

public:
    HttpRequestOptionsContext() {}
    ~HttpRequestOptionsContext() {}

    void SetRequestMethod(RequestMethod method)
    {
        this->method_ = method;
    }

    RequestMethod GetRequestMethod()
    {
        return this->method_;
    }

    void SetExtraData(const std::string &extraData)
    {
        this->extraData_ = extraData;
    }

    std::string GetExtraData()
    {
        return this->extraData_;
    }

    void SetHeader(const std::string &header)
    {
        this->header_ = header;
    }

    std::string GetHeader()
    {
        return this->header_;
    }

    void SetReadTimeout(const int32_t &readTimeout)
    {
        this->readTimeout_ = readTimeout;
    }

    int32_t GetReadTimeout()
    {
        return this->readTimeout_;
    }

    void SetConnectTimeout(const int32_t &connectTimeout)
    {
        this->connectTimeout_ = connectTimeout;
    }

    int32_t GetConnectTimeout()
    {
        return this->connectTimeout_;
    }

    void SetIfModifiedSince(const int32_t &ifModifiedSince)
    {
        this->ifModifiedSince_ = ifModifiedSince;
    }

    int32_t GetIfModifiedSince()
    {
        return this->ifModifiedSince_;
    }

    void SetUsingCache(const bool &usingCache)
    {
        this->usingCache_ = usingCache;
    }

    bool GetUsingCache()
    {
        return this->usingCache_;
    }

    void SetFixedLengthStreamingMode(const int32_t &fixedLengthStreamingMode)
    {
        this->fixedLengthStreamingMode_ = fixedLengthStreamingMode;
    }

    int32_t GetFixedLengthStreamingMode()
    {
        return this->fixedLengthStreamingMode_;
    }

    void SetUrl(const std::string &url)
    {
        this->url_ = url;
    }

    std::string GetUrl()
    {
        return this->url_;
    }

    void SetResponseData(HttpResponse &responseData)
    {
        this->responseData_ = responseData;
    }

    HttpResponse GetResponseData()
    {
        return this->responseData_;
    }

    void SetCaFile(const std::string &caFile)
    {
        this->cafile_ = caFile;
    }

    std::string GetCaFile()
    {
        return this->cafile_;
    }
private:
    RequestMethod method_ = RequestMethod::GET;
    std::string extraData_ = "";
    std::string header_ = "";
    int32_t readTimeout_ = 60;
    int32_t connectTimeout_ = 60;
    int32_t ifModifiedSince_ = 0;
    bool usingCache_ = true;
    int32_t fixedLengthStreamingMode_ = -1;
    std::string url_ = "";
    HttpResponse responseData_;
    std::string cafile_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // HTTP_REQUEST_OPTIONS_CONTEXT_H