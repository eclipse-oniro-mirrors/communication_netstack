/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "curl/curl.h"
#include "napi/native_api.h"
#include "request_context.h"

namespace OHOS::NetStack {
class HttpResponseCacheExec final {
public:
    HttpResponseCacheExec() = default;

    ~HttpResponseCacheExec() = default;

    static bool ExecFlush(BaseContext *context);

    static napi_value FlushCallback(BaseContext *context);

    static bool ExecDelete(BaseContext *context);

    static napi_value DeleteCallback(BaseContext *context);
};

class HttpExec final {
public:
    HttpExec() = default;

    ~HttpExec() = default;

    static bool RequestWithoutCache(RequestContext *context);

    static bool ExecRequest(RequestContext *context);

    static napi_value RequestCallback(RequestContext *context);

    static napi_value Request2Callback(RequestContext *context);

    static std::string MakeUrl(const std::string &url, std::string param, const std::string &extraParam);

    static bool MethodForGet(const std::string &method);

    static bool MethodForPost(const std::string &method);

    static bool EncodeUrlParam(std::string &str);

    static bool Initialize();

    static bool IsInitialized();

    static void DeInitialize();

#ifndef MAC_PLATFORM
    static void AsyncRunRequest(RequestContext *context);
#endif

private:
    static bool SetOption(CURL *curl, RequestContext *context, struct curl_slist *requestHeader);

    static size_t OnWritingMemoryBody(const void *data, size_t size, size_t memBytes, void *userData);

    static size_t OnWritingMemoryHeader(const void *data, size_t size, size_t memBytes, void *userData);

    static struct curl_slist *MakeHeaders(const std::vector<std::string> &vec);

    static napi_value MakeResponseHeader(RequestContext *context);

    static void OnHeaderReceive(RequestContext *context, napi_value header);

    static bool IsUnReserved(unsigned char in);

    static bool ProcByExpectDataType(napi_value object, RequestContext *context);

    static bool AddCurlHandle(CURL *handle, RequestContext *context);

    static void HandleCurlData(CURLMsg *msg);

    static void HandleData();

    static bool GetCurlDataFromHandle(CURL *handle, RequestContext *context, CURLMSG curlMsg, CURLcode result);

    static void RunThread();

    static void SendRequest();

    static void ReadRespond();

    static void GetGlobalHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions);

    static void OnDataReceive(napi_env env, napi_status status, void *data);

    static void OnDataProgress(napi_env env, napi_status status, void *data);

    static void OnDataEnd(napi_env env, napi_status status, void *data);

    static int ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                curl_off_t ulnow);

    struct StaticVariable {
        StaticVariable() : curlMulti(nullptr), initialized(false), runThread(true) {}

        ~StaticVariable()
        {
            if (HttpExec::IsInitialized()) {
                HttpExec::DeInitialize();
            }
        }

        std::mutex mutex;
        std::mutex curlMultiMutex;
        CURLM *curlMulti;
        std::map<CURL *, RequestContext *> contextMap;
        std::thread workThread;
        std::condition_variable conditionVariable;

#ifndef MAC_PLATFORM
        std::atomic_bool initialized;
        std::atomic_bool runThread;
#else
        bool initialized;
        bool runThread;
#endif
    };
    static StaticVariable staticVariable_;
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_HTTP_REQUEST_EXEC_H */
