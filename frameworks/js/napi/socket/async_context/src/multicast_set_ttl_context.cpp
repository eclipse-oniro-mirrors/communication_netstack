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

#include "multicast_set_ttl_context.h"

#include "context_key.h"
#include "event_manager.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "socket_constant.h"

namespace OHOS::NetStack::Socket {
MulticastSetTTLContext::MulticastSetTTLContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void MulticastSetTTLContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (!valid) {
        if (paramsCount == PARAM_JUST_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[0]) == napi_function) {
                SetCallback(params[0]);
            }
            return;
        }
        if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
            if (NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function) {
                SetCallback(params[1]);
            }
            return;
        }
        return;
    }

    ttl_ = NapiUtils::GetInt32FromValue(GetEnv(), params[0]);

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool MulticastSetTTLContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_number;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_number &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_function;
    }
    return false;
}

void MulticastSetTTLContext::SetMulticastTTL(int ttl)
{
    ttl_ = ttl;
}

int MulticastSetTTLContext::GetMulticastTTL() const
{
    return ttl_;
}

int MulticastSetTTLContext::GetSocketFd() const
{
    return (int)(uint64_t)manager_->GetData();
}

int32_t MulticastSetTTLContext::GetErrorCode() const
{
    auto err = BaseContext::GetErrorCode();
    if (err == PARSE_ERROR_CODE) {
        return PARSE_ERROR_CODE;
    }

    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

#if defined(IOS_PLATFORM)
    err = ErrCodePlatformAdapter::GetOHOSErrCode(err);
#endif
    return err + SOCKET_ERROR_CODE_BASE;
}

std::string MulticastSetTTLContext::GetErrorMessage() const
{
    if (BaseContext::IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto errCode = BaseContext::GetErrorCode();
    if (errCode == PARSE_ERROR_CODE) {
        return PARSE_ERROR_MSG;
    }
#if defined(IOS_PLATFORM)
    std::string errMessage;
    ErrCodePlatformAdapter::GetOHOSErrMessage(errCode, errMessage);
    return errMessage;
#else
    char err[MAX_ERR_NUM] = {0};
    (void)strerror_r(errCode, err, MAX_ERR_NUM);
    return err;
#endif
}
} // namespace OHOS::NetStack::Socket