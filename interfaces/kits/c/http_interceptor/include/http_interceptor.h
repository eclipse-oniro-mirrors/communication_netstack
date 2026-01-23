/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef HTTP_INTERCEPTOR_H
#define HTTP_INTERCEPTOR_H

#include "http_interceptor_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief add a http global interceptor
 *
 * @param interceptor Http global interceptor configuration, Pointer to {@link Http_Interceptor}.
 * @return 0 if success; non-0 otherwise. For details about error codes, see {@link Http_ErrCode}.
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 24
 */
int32_t OH_Http_AddInterceptor(struct Http_Interceptor *interceptor);

/**
 * @brief delete a http global interceptor
 *
 * @param interceptor Http global interceptor configuration, Pointer to {@link Http_Interceptor}.
 * @return 0 if success; non-0 otherwise. For details about error codes, see {@link Http_ErrCode}.
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 24
 */
int32_t OH_Http_DeleteInterceptor(struct Http_Interceptor *interceptor);

/**
 * @brief delete all http global interceptors
 *
 * @return 0 if success; non-0 otherwise. For details about error codes, see {@link Http_ErrCode}.
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 24
 */
int32_t OH_Http_DeleteAllInterceptors(int32_t groupId);

/**
 * @brief start all http global interceptors
 *
 * @return 0 if success; non-0 otherwise. For details about error codes, see {@link Http_ErrCode}.
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 24
 */
int32_t OH_Http_StartAllInterceptors(int32_t groupId);

/**
 * @brief stop all http global interceptors
 *
 * @return 0 if success; non-0 otherwise. For details about error codes, see {@link Http_ErrCode}.
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 24
 */
int32_t OH_Http_StopAllInterceptors(int32_t groupId);

#ifdef __cplusplus
}
#endif

#endif // HTTP_INTERCEPTOR_H