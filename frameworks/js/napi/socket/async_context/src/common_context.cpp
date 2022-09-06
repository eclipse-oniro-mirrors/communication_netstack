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

#include "common_context.h"

#include "context_key.h"
#include "event_manager.h"
#include "napi_utils.h"

namespace OHOS::NetStack {
CommonContext::CommonContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void CommonContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        return;
    }

    if (paramsCount != PARAM_NONE) {
        SetParseOK(SetCallback(params[0]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

int CommonContext::GetSocketFd() const
{
    return (int)(uint64_t)manager_->GetData();
}

bool CommonContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_NONE) {
        return true;
    }

    if (paramsCount == PARAM_JUST_CALLBACK) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function;
    }
    return false;
}

CloseContext::CloseContext(napi_env env, EventManager *manager) : CommonContext(env, manager) {}

void CloseContext::SetSocketFd(int sock)
{
    manager_->SetData(reinterpret_cast<void *>(sock));
}
} // namespace OHOS::NetStack
