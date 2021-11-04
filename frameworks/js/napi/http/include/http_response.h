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

#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include "http_base_context.h"

#include <vector>
#include <string>

namespace OHOS {
namespace NetManagerStandard {
class HttpResponse : public HttpBaseContext {
public:
    HttpResponse() {}
    ~HttpResponse() {}

    void SetResult(const std::string &result)
    {
        this->result_ = result;
    }

    std::string GetResult()
    {
        return this->result_;
    }

    void SetResponseCode(ResponseCode responseCode)
    {
        this->responseCode_ = responseCode;
    }

    ResponseCode GetResponseCode()
    {
        return this->responseCode_;
    }

    void SetHeader(const std::string &header)
    {
        this->header_ = header;
    }

    std::string GetHeader()
    {
        return this->header_;
    }

    void SetCookies(const std::vector<std::string> &cookies)
    {
        this->cookies_ = cookies;
    }

    std::vector<std::string> GetCookies()
    {
        return this->cookies_;
    }
private:
    std::string result_ = "";
    enum ResponseCode responseCode_;
    std::string header_ = "";
    std::vector<std::string> cookies_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // HTTP_RESPONSE_H