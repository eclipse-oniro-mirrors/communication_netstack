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

#include "get_protocol_context.h"

#include "constant.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
GetProtocolContext::GetProtocolContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void GetProtocolContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    if (paramsCount == PARAM_JUST_CALLBACK) {
        SetParseOK(SetCallback(params[ARG_INDEX_0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool GetProtocolContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_NONE) {
        return true;
    }

    if (paramsCount == PARAM_JUST_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_function) {
            NETSTACK_LOGE("GetProtocolContext first param is not function");
            return false;
        }
        return true;
    }
    return false;
}
} // namespace NetStack
} // namespace OHOS
