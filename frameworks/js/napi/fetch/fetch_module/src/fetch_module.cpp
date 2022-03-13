/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "fetch_module.h"

#include "netstack_log.h"

static constexpr const char *FETCH_MODULE_NAME = "fetch";

namespace OHOS::NetStack {
napi_value FetchModule::InitFetchModule(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_FETCH, Fetch),
    };
    NapiUtils::DefineProperties(env, exports, properties);

    return exports;
}

napi_value FetchModule::Fetch(napi_env env, napi_callback_info info)
{
    NETSTACK_LOGI("FetchModule::Fetch is called");
    (void)info;

    return NapiUtils::GetUndefined(env);
}

static napi_module g_fetchModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = FetchModule::InitFetchModule,
    .nm_modname = FETCH_MODULE_NAME,
    .nm_priv = nullptr,
    .reserved = {nullptr},
};

extern "C" __attribute__((constructor)) void RegisterFetchModule(void)
{
    napi_module_register(&g_fetchModule);
}
} // namespace OHOS::NetStack
