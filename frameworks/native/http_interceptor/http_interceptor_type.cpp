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

#include "http_interceptor_type.h"
#include "securec.h"
#ifdef __cplusplus
extern "C" {
#endif
void InitHttpBuffer(Http_Buffer *src)
{
    if (src == nullptr) {
        return;
    }
    src->buffer = nullptr;
    src->length = 0;
}

void DeepCopyBuffer(Http_Buffer *dst, const Http_Buffer *src)
{
    if (src == nullptr || src->buffer == nullptr || src->length == 0 || dst == nullptr) {
        return;
    }
    // LCOV_EXCL_START
    dst->buffer = static_cast<char *>(malloc(src->length + 1));
    if (dst->buffer == nullptr) {
        dst->length = 0;
        return;
    }
    dst->length = src->length;
    dst->buffer[dst->length] = '\0';
    if (memcpy_s(dst->buffer, dst->length, src->buffer, src->length) != EOK) {
        dst->length = 0;
        free(dst->buffer);
        dst->buffer = nullptr;
    }
    // LCOV_EXCL_STOP
}

Http_Headers *DeepCopyHeaders(Http_Headers *src)
{
    if (src == nullptr) {
        return nullptr;
    }
    Http_Headers *dst = nullptr;
    Http_Headers *tmp = src;
    while (tmp != nullptr) {
        if (tmp->data != nullptr) {
            dst = curl_slist_append(dst, tmp->data);
        }
        tmp = tmp->next;
    }
    return dst;
}

static void DestroyHttpHeaders(Http_Headers *headers)
{
    if (headers == nullptr) {
        return;
    }
    curl_slist_free_all(headers);
}

void DestroyHttpInterceptorRequest(Http_Interceptor_Request *req)
{
    if (req == nullptr) {
        return;
    }
    if (req->url.buffer != nullptr) {
        free(req->url.buffer);
        req->url.buffer = nullptr;
    }
    if (req->method.buffer != nullptr) {
        free(req->method.buffer);
        req->method.buffer = nullptr;
    }
    if (req->body.buffer != nullptr) {
        free(req->body.buffer);
        req->body.buffer = nullptr;
    }
    DestroyHttpHeaders(req->headers);
    free(req);
}

void DestroyHttpInterceptorResponse(Http_Interceptor_Response *resp)
{
    if (resp == nullptr) {
        return;
    }
    if (resp->body.buffer != nullptr) {
        free(resp->body.buffer);
        resp->body.buffer = nullptr;
    }
    DestroyHttpHeaders(resp->headers);
    resp->headers = nullptr;
    free(resp);
}
#ifdef __cplusplus
}
#endif