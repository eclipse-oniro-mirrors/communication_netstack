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

#ifndef HTTP_INTERCEPTOR_TYPE_H
#define HTTP_INTERCEPTOR_TYPE_H

#include "net_http_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines interceptor request
 *
 * @since 23
 */
typedef struct Http_Interceptor_Request {
    char *url;
    char *method;
    Http_Headers *headers;
    Http_Buffer *body;
} Http_Interceptor_Request;

/**
 * @brief Defines interceptor stage
 *
 * @since 23
 */
typedef enum Interceptor_Stage {
    /** http request hook */
    STAGE_REQUEST,
    /** http response hook */
    STAGE_RESPONSE
} Interceptor_Stage;

/**
 * @brief Defines interceptor type
 *
 * @since 23
 */
typedef enum Interceptor_Type {
    /** interceptor will not modify the packet */
    TYPE_READ_ONLY,
    /** interceptor will modify the packet */
    TYPE_MODIFY
} Interceptor_Type;

/**
 * @brief Defines interceptor process result
 *
 * @since 23
 */
typedef enum Interceptor_Result {
    /** interceptor result is continue */
    CONTINUE,
    /** interceptor result is abort this packet */
    ABORT
} Interceptor_Result;

/**
 * @brief Defines interceptor handler
 *
 * @since 23
 */
typedef Interceptor_Result (*OH_Http_InterceptorHandler)(
    /** http request packet */
    Http_Interceptor_Request *request,
    /** http response packet */
    Http_Response *response,
    /** interceptor isModified */
    int32_t *isModified);

/**
 * @brief Defines interceptor configuration
 *
 * @since 23
 */
typedef struct Http_Interceptor {
    /** stage of interceptor */
    Interceptor_Stage stage;
    /** type of interceptor */
    Interceptor_Type type;
    /** handler of interceptor */
    OH_Http_InterceptorHandler handler;
    /** context of interceptor */
    void *context;
} Http_Interceptor;

#ifdef __cplusplus
}
#endif

#endif // HTTP_INTERCEPTOR_TYPE_H