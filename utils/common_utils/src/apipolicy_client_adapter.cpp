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

namespace OHOS::NetStack::ApiPolicyUtils {
namespace {
static constexpr const char *APIPOLICY_SO_PATH = "/system/lib64/platformsdk/libapipolicy_client.z.so";
static std::string DOMAIN_TYPE_HTTP_REQUEST = "httpRequest";
static constexpr uint32_t RESULT_ACCEPT = 0;
}

bool IsAllowedHostname(const std::string &bundleName, const std::string &hostname)
{
    void *libHandle = dlopen(APIPOLICY_SO_PATH, RTLD_NOW);
    if (!libHandle) {
        const char *err = dlerror();
        NETSTACK_LOGE("apipolicy so dlopen failed: %{public}s", err ? err : "unknown");
        return true;
    }
    using CheckUrlFunc = int32_t (*)(std::string, std::string, std::string);
    auto func = reinterpret_cast<CheckUrlFunc>(dlsym(libHandle, "CheckUrl"));
    if (func == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("apipolicy dlsym CheckUrl failed: %{public}s", err ? err : "unknown");
        return true;
    }
    int32_t res = func(bundleName, DOMAIN_TYPE_HTTP_REQUEST, hostname);
    NETSTACK_LOGD("ApiPolicy CheckHttpUrl result=%{public}d, bundle_name=%{public}s, hostname=%{public}s",
                  res, bundleName.c_str(), hostname.c_str());
    return res == RESULT_ACCEPT;
}
};