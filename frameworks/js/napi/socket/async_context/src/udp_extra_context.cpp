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

#include "udp_extra_context.h"

#include "context_key.h"
#include "netstack_event_manager.h"
#include "netstack_napi_utils.h"

namespace OHOS::NetStack {
UdpSetExtraOptionsContext::UdpSetExtraOptionsContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void UdpSetExtraOptionsContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        return;
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_RECEIVE_BUFFER_SIZE)) {
        options.SetReceiveBufferSize(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_RECEIVE_BUFFER_SIZE));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SEND_BUFFER_SIZE)) {
        options.SetSendBufferSize(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_SEND_BUFFER_SIZE));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_REUSE_ADDRESS)) {
        options.SetReuseAddress(NapiUtils::GetBooleanProperty(GetEnv(), params[0], KEY_REUSE_ADDRESS));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_SOCKET_TIMEOUT)) {
        options.SetSocketTimeout(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_SOCKET_TIMEOUT));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], KEY_BROADCAST)) {
        options.SetBroadcast(NapiUtils::GetUint32Property(GetEnv(), params[0], KEY_BROADCAST));
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

int UdpSetExtraOptionsContext::GetSocketFd() const
{
    return (int)(uint64_t)manager_->GetData();
}

bool UdpSetExtraOptionsContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function;
    }
    return false;
}
} // namespace OHOS::NetStack