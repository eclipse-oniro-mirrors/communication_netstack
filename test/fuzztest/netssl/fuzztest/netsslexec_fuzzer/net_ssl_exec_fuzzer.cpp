/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "net_ssl_exec_fuzzer.h"
#include "net_ssl_exec.h"
#include "netstack_log.h"
#include "securec.h"
#include <cstdint>

namespace OHOS {
namespace NetStack {
namespace Ssl {
namespace {
const uint8_t *g_netstackFuzzData = nullptr;
size_t g_netstackFuzzSize = 0;
size_t g_netstackFuzzPos = 0;
template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_netstackFuzzData == nullptr || objectSize > g_netstackFuzzSize - g_netstackFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_netstackFuzzData + g_netstackFuzzPos, objectSize);
    if (ret != EOK) {
        return object;
    }
    g_netstackFuzzPos += objectSize;
    return object;
}

inline void SetGlobalFuzzData(const uint8_t *data, size_t size)
{
    g_netstackFuzzData = data;
    g_netstackFuzzSize = size;
    g_netstackFuzzPos = 0;
}
} // namespace

void ExecVerifyFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    napi_env env(GetData<napi_env>());
    std::shared_ptr<EventManager> manager = nullptr;
    CertContext context(env, manager);

    SslExec::ExecVerify(&context);
}
} // namespace Ssl
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::Ssl::ExecVerifyFuzzTest(data, size);
    return 0;
}
