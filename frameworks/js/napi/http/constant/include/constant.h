/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_CONSTANT_H
#define COMMUNICATIONNETSTACK_CONSTANT_H

#include <cstddef>
#include <cstdint>

namespace OHOS::NetStack {
enum class ResponseCode {
    OK = 200,
    CREATED,
    ACCEPTED,
    NOT_AUTHORITATIVE,
    NO_CONTENT,
    RESET,
    PARTIAL,
    MULT_CHOICE = 300,
    MOVED_PERM,
    MOVED_TEMP,
    SEE_OTHER,
    NOT_MODIFIED,
    USE_PROXY,
    BAD_REQUEST = 400,
    UNAUTHORIZED,
    PAYMENT_REQUIRED,
    FORBIDDEN,
    NOT_FOUND,
    BAD_METHOD,
    NOT_ACCEPTABLE,
    PROXY_AUTH,
    CLIENT_TIMEOUT,
    CONFLICT,
    GONE,
    LENGTH_REQUIRED,
    PRECON_FAILED,
    ENTITY_TOO_LARGE,
    REQ_TOO_LONG,
    UNSUPPORTED_TYPE,
    INTERNAL_ERROR = 500,
    NOT_IMPLEMENTED,
    BAD_GATEWAY,
    UNAVAILABLE,
    GATEWAY_TIMEOUT,
    VERSION,
};

enum class HttpDataType {
    /**
     * The returned type is string.
     */
    STRING,
    /**
     * The returned type is Object.
     */
    OBJECT = 1,
    /**
     * The returned type is ArrayBuffer.
     */
    ARRAY_BUFFER = 2,
    /**
     * The returned type is not set.
     */
    NO_DATA_TYPE = 3,
};

class HttpConstant final {
public:
    /* Http Method */
    static const char *const HTTP_METHOD_GET;
    static const char *const HTTP_METHOD_HEAD;
    static const char *const HTTP_METHOD_OPTIONS;
    static const char *const HTTP_METHOD_TRACE;
    static const char *const HTTP_METHOD_DELETE;
    static const char *const HTTP_METHOD_POST;
    static const char *const HTTP_METHOD_PUT;
    static const char *const HTTP_METHOD_CONNECT;

    /* default options */
    static const uint32_t DEFAULT_READ_TIMEOUT;
    static const uint32_t DEFAULT_CONNECT_TIMEOUT;

    static const size_t MAX_JSON_PARSE_SIZE;

    /* options key */
    static const char *const PARAM_KEY_METHOD;
    static const char *const PARAM_KEY_EXTRA_DATA;
    static const char *const PARAM_KEY_HEADER;
    static const char *const PARAM_KEY_READ_TIMEOUT;
    static const char *const PARAM_KEY_CONNECT_TIMEOUT;
    static const char *const PARAM_KEY_USING_PROTOCOL;
    static const char *const PARAM_KEY_USING_CACHE;
    static const char *const PARAM_KEY_EXPECT_DATA_TYPE;
    static const char *const PARAM_KEY_PRIORITY;

    static const char *const PARAM_KEY_USING_HTTP_PROXY;

    static const char *const HTTP_PROXY_KEY_HOST;
    static const char *const HTTP_PROXY_KEY_PORT;
    static const char *const HTTP_PROXY_KEY_EXCLUSION_LIST;
    static const char *const HTTP_PROXY_EXCLUSIONS_SEPARATOR;

    static const char *const RESPONSE_KEY_RESULT;
    static const char *const RESPONSE_KEY_RESPONSE_CODE;
    static const char *const RESPONSE_KEY_HEADER;
    static const char *const RESPONSE_KEY_COOKIES;
    static const char *const RESPONSE_KEY_RESULT_TYPE;

    static const char *const HTTP_URL_PARAM_START;
    static const char *const HTTP_URL_PARAM_SEPARATOR;
    static const char *const HTTP_URL_NAME_VALUE_SEPARATOR;
    static const char *const HTTP_HEADER_SEPARATOR;
    static const char *const HTTP_LINE_SEPARATOR;

    static const char *const HTTP_DEFAULT_USER_AGENT;
    static const char *const HTTP_DEFAULT_CA_PATH;

    static const char *const HTTP_CONTENT_TYPE;
    static const char *const HTTP_CONTENT_TYPE_URL_ENCODE;
    static const char *const HTTP_CONTENT_TYPE_JSON;
    static const char *const HTTP_CONTENT_TYPE_OCTET_STREAM;
    static const char *const HTTP_CONTENT_TYPE_IMAGE;

    static const char *const HTTP_CONTENT_ENCODING_GZIP;

    static const char *const REQUEST_TIME;
    static const char *const RESPONSE_TIME;
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_CONSTANT_H */
