/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "http_interceptor.h"
#include "http_interceptor_mgr.h"
#include "netstack_common_utils.h"
#include <cstddef>
#include <cstdint>

int32_t OH_Http_AddInterceptor(struct OH_Http_Interceptor *interceptor)
{
    return OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().AddInterceptor(interceptor);
}

int32_t OH_Http_AddReadOnlyInterceptor(struct OH_Http_Interceptor *interceptor)
{
    if (!OHOS::NetStack::CommonUtils::HasInternetPermission()) {
        return OH_HTTP_PERMISSION_DENIED;
    }
    if (interceptor == nullptr || interceptor->type != OH_TYPE_READ_ONLY || interceptor->stage != OH_STAGE_RESPONSE) {
        return OH_HTTP_PARAMETER_ERROR;
    }
    return OH_Http_AddInterceptor(interceptor);
}

int32_t OH_Http_AddWritableInterceptor(struct OH_Http_Interceptor *interceptor)
{
    if (!OHOS::NetStack::CommonUtils::HasInternetPermission()) {
        return OH_HTTP_PERMISSION_DENIED;
    }
    if (interceptor == nullptr || interceptor->type != OH_TYPE_MODIFY) {
        return OH_HTTP_PARAMETER_ERROR;
    }
    return OH_Http_AddInterceptor(interceptor);
}

int32_t OH_Http_RemoveInterceptor(struct OH_Http_Interceptor *interceptor)
{
    if (!OHOS::NetStack::CommonUtils::HasInternetPermission()) {
        return OH_HTTP_PERMISSION_DENIED;
    }
    return OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().DeleteInterceptor(interceptor);
}

int32_t OH_Http_RemoveAllInterceptors(int32_t groupId)
{
    if (!OHOS::NetStack::CommonUtils::HasInternetPermission()) {
        return OH_HTTP_PERMISSION_DENIED;
    }
    return OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().DeleteAllInterceptor(groupId);
}

int32_t OH_Http_StartAllInterceptors(int32_t groupId)
{
    if (!OHOS::NetStack::CommonUtils::HasInternetPermission()) {
        return OH_HTTP_PERMISSION_DENIED;
    }
    return OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().SetAllInterceptorEnabled(groupId, 1);
}

int32_t OH_Http_StopAllInterceptors(int32_t groupId)
{
    if (!OHOS::NetStack::CommonUtils::HasInternetPermission()) {
        return OH_HTTP_PERMISSION_DENIED;
    }
    return OHOS::NetStack::HttpInterceptor::HttpInterceptorMgr::GetInstance().SetAllInterceptorEnabled(groupId, 0);
}
