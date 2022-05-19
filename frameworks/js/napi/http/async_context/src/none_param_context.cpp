/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "none_param_context.h"
#include "netstack_napi_utils.h"

namespace OHOS::NetStack {
static constexpr const int PARAM_NONE = 0;
static constexpr const int PARAM_JUST_CALLBACK = 1;

NoneParamContext::NoneParamContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void NoneParamContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }

    if (paramsCount == PARAM_JUST_CALLBACK) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool NoneParamContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_NONE) {
        return true;
    }

    if (paramsCount == PARAM_JUST_CALLBACK) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function;
    }
    return false;
}
} // namespace OHOS::NetStack
