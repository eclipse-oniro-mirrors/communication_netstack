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

#ifndef COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H
#define COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H

#include <mutex>
#include <vector>

#include "curl/curl.h"
#include "napi/native_api.h"
#include "noncopyable.h"
#include "request_context.h"

namespace OHOS::NetStack {
class HttpExec final {
public:
    ACE_DISALLOW_COPY_AND_MOVE(HttpExec);

    HttpExec() = default;

    ~HttpExec() = default;

    static bool ExecRequest(RequestContext *context);

    static napi_value RequestCallback(RequestContext *context);

    static std::string MakeUrl(const std::string &url, std::string param, const std::string &extraParam);

    static bool MethodForGet(const std::string &method);

    static bool MethodForPost(const std::string &method);

    static bool EncodeUrlParam(std::string &str);

private:
    static bool Initialize();

    static bool SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader);

    static size_t OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData);

    static size_t OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData);

    static struct curl_slist *MakeHeaders(const std::vector<std::string> &vec);

    static napi_value MakeResponseHeader(RequestContext *context);

    static void OnHeaderReceive(RequestContext *context, napi_value header);

    static bool IsUnReserved(unsigned char in);

private:
    static std::mutex mutex_;

    static bool initialized_;
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H */
