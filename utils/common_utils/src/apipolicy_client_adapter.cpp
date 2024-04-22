/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <dlfcn.h>

#include "apipolicy_client_adapter.h"
#include "netstack_log.h"

namespace OHOS::NetStack::CommonUtils {
namespace {
    constexpr const char *APIPOLICY_SO_PATH = "/system/lib64/platformsdk/libapipolicy_client.z.so";
}

std::string ApiPolicyAdapter::DOMAIN_TYPE_HTTP_REQUEST = "httpRequest";
std::string ApiPolicyAdapter::DOMAIN_TYPE_WEB_SOCKET = "webSocket";
std::string ApiPolicyAdapter::DOMAIN_TYPE_DOWNLOAD = "download";
std::string ApiPolicyAdapter::DOMAIN_TYPE_UPLOAD = "upload";
std::string ApiPolicyAdapter::DOMAIN_TYPE_WEBVIEW = "webView";

int32_t ApiPolicyAdapter::RESULT_ACCEPT = 0;
int32_t ApiPolicyAdapter::RESULT_REJECT = 1;

ApiPolicyAdapter::ApiPolicyAdapter()
{
    if (isInit) {
        NETSTACK_LOGI("apipolicy so have load");
        return;
    }
    if (libHandle) {
        NETSTACK_LOGI("apipolicy lib handle have load");
        return;
    }
    libHandle = dlopen(APIPOLICY_SO_PATH, RTLD_NOW);
    if (!libHandle) {
        const char *err = dlerror();
        NETSTACK_LOGE("apipolicy so dlopen failed: %{public}s", err ? err : "unknown");
        return;
    }
    NETSTACK_LOGD("apipolicy so dlopen success");
    isInit = true;
}

ApiPolicyAdapter::~ApiPolicyAdapter()
{
    if (libHandle) {
        dlclose(libHandle);
        libHandle = nullptr;
        NETSTACK_LOGD("apipolicy so have dlclose");
    }
    isInit = false;
}

int32_t ApiPolicyAdapter::CheckUrl(std::string bundle_name, std::string domain_type, std::string url)
{
    int32_t res = -1;
    if (!isInit || !libHandle) {
        NETSTACK_LOGE("apipolicy so handle is not init");
        return res;
    }
    using CheckUrlFunc = int32_t (*)(std::string, std::string, std::string);
    auto func = reinterpret_cast<CheckUrlFunc>(dlsym(libHandle, "CheckUrl"));
    if (func == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("apipolicy dlsym CheckUrl failed: %{public}s", err ? err : "unknown");
        return res;
    }
    res = func(bundle_name, domain_type, url);
    return res;
}
};