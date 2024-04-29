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

#include "netstack_bundle_utils.h"

#include <dlfcn.h>
#include <mutex>

#include "netstack_log.h"
#include "net_bundle.h"

namespace OHOS::NetStack::BundleUtils {

#ifdef __LP64__
    const std::string LIB_NET_BUNDL_UTILS_SO_PATH = "/system/lib64/libnet_bundle_utils.z.so";
#else
    const std::string LIB_NET_BUNDL_UTILS_SO_PATH = "/system/lib/libnet_bundle_utils.z.so";
#endif

using GetNetBundleClass = OHOS::NetManagerStandard::INetBundle *(*)();

__attribute__((no_sanitize("cfi"))) bool IsAtomicService(std::string &bundleName)
{
    void *handler = dlopen(LIB_NET_BUNDL_UTILS_SO_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (handler == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("load failed, reason: %{public}s", err ? err : "unknown");
        return false;
    }
    GetNetBundleClass getNetBundle = (GetNetBundleClass) dlsym(handler, "GetNetBundle");
    if (getNetBundle == nullptr) {
        const char *err = dlerror();
        NETSTACK_LOGE("getNetBundle failed, reason: %{public}s", err ? err : "unknown");
        dlclose(handler);
        return false;
    }
    auto netBundle = getNetBundle();
    if (netBundle == nullptr) {
        NETSTACK_LOGE("netBundle is nullptr");
        dlclose(handler);
        return false;
    }
    auto ret = netBundle->IsAtomicService(bundleName);
    NETSTACK_LOGD("netBundle IsAtomicService result=%{public}d, bundle_name=%{public}s", ret, bundleName.c_str());
    dlclose(handler);
    return ret;
}
}