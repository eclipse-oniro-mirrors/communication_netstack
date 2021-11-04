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

#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "netmgr_log_wrapper.h"
#include "base/security/deviceauth/hals/inc/linux/hc_log.h"

#include "http_request_options_context.h"

#include <curl/curl.h>

#include <map>
#include <mutex>

#define HTTP_CURL_EASY_SET_OPTION(handle, opt, data)                           \
    do {                                                                       \
        CURLcode result = curl_easy_setopt(handle, opt, data);                 \
        if (result != CURLE_OK) {                                              \
            NETMGR_LOGE("curl set option failed! error code %{public}d", result); \
            return false;                                                      \
        }                                                                      \
    } while (0)

namespace OHOS {
namespace NetManagerStandard {
constexpr int32_t URL_PREFIX_LENGTH = 8;

class HttpRequest {
public:
    HttpRequest();
    ~HttpRequest();

    bool Initialize();
    void SetOptionURL(CURL *curl, HttpRequestOptionsContext *asyncContext);
    bool GetCurlWriteData(HttpRequestOptionsContext *asyncContext);
    void SetHeaders(std::string headersStr);
    void SetHeader(CURL *curl);
    void SetMethod(CURL *curl, HttpRequestOptionsContext *asyncContext);
    bool SetOptionForPost(CURL *curl, HttpRequestOptionsContext *asyncContext);
    bool SetOptionForGet(CURL *curl, HttpRequestOptionsContext *asyncContext);
    void EmitHeader(HttpRequest *obj, const std::string &header);

    bool NativeRequest(HttpRequestOptionsContext *asyncContext);
    void NativeDestroy();
    void NativeOn();
    void NativeOff();

private:
    static size_t OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData)
    {
        ((std::string *)userData)->append((char *)data, 0, size * memBytes);
        NETMGR_LOGD("OnWritingMemoryBody");
        return size * memBytes;
    }
    static size_t OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData)
    {
        ((std::string *)userData)->append((char *)data, 0, size * memBytes);
        NETMGR_LOGD("OnWritingMemoryHeader");
        return size * memBytes;
    }
    bool IsCaFile(const std::string &caFlie);
    std::mutex mutex_;
    bool initialized_ = false;
    std::map<std::string, std::string> headers_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // HTTP_REQUEST_H