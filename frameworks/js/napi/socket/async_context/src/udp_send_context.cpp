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

#include "udp_send_context.h"

#include "context_key.h"
#include "netstack_log.h"
#include "netstack_napi_utils.h"

namespace OHOS::NetStack {
UdpSendContext::UdpSendContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void UdpSendContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        return;
    }

    napi_value netAddress = NapiUtils::GetNamedProperty(GetEnv(), params[0], KEY_ADDRESS);

    std::string addr = NapiUtils::GetStringPropertyUtf8(GetEnv(), netAddress, KEY_ADDRESS);
    if (addr.empty()) {
        NETSTACK_LOGE("address is empty");
    }
    options.address.SetAddress(addr);
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, KEY_FAMILY)) {
        uint32_t family = NapiUtils::GetUint32Property(GetEnv(), netAddress, KEY_FAMILY);
        options.address.SetFamilyByJsValue(family);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, KEY_PORT)) {
        uint16_t port = static_cast<uint16_t>(NapiUtils::GetUint32Property(GetEnv(), netAddress, KEY_PORT));
        options.address.SetPort(port);
    }
    if (!GetData(params[0])) {
        return;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

int UdpSendContext::GetSocketFd() const
{
    return (int)(uint64_t)manager_->GetData();
}

bool UdpSendContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), NapiUtils::GetNamedProperty(GetEnv(), params[0], KEY_ADDRESS)) ==
                   napi_object;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), NapiUtils::GetNamedProperty(GetEnv(), params[0], KEY_ADDRESS)) ==
                   napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function;
    }
    return false;
}

bool UdpSendContext::GetData(napi_value udpSendOptions)
{
    napi_value jsData = NapiUtils::GetNamedProperty(GetEnv(), udpSendOptions, KEY_DATA);
    if (NapiUtils::GetValueType(GetEnv(), jsData) == napi_string) {
        std::string data = NapiUtils::GetStringFromValueUtf8(GetEnv(), jsData);
        if (data.empty()) {
            NETSTACK_LOGE("string data is empty");
            return false;
        }
        options.SetData(data);
        return true;
    }

    if (NapiUtils::ValueIsArrayBuffer(GetEnv(), jsData)) {
        size_t length = 0;
        void *data = NapiUtils::GetInfoFromArrayBufferValue(GetEnv(), jsData, &length);
        if (data == nullptr) {
            NETSTACK_LOGE("arraybuffer data is empty");
            return false;
        }
        options.SetData(data, length);
        return true;
    }
    return false;
}
} // namespace OHOS::NetStack
