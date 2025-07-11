/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "curl/curl.h"

namespace OHOS::NetStack::Http {
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
    RANGE_NOT_SATISFIABLE,
    INTERNAL_ERROR = 500,
    NOT_IMPLEMENTED,
    BAD_GATEWAY,
    UNAVAILABLE,
    GATEWAY_TIMEOUT,
    VERSION,
};

enum HttpErrorCode {
    HTTP_ERROR_CODE_BASE = 2300000,
    HTTP_UNSUPPORTED_PROTOCOL = HTTP_ERROR_CODE_BASE + CURLE_UNSUPPORTED_PROTOCOL,
    HTTP_URL_MALFORMAT = HTTP_ERROR_CODE_BASE + CURLE_URL_MALFORMAT,
    HTTP_COULDNT_RESOLVE_PROXY = HTTP_ERROR_CODE_BASE + CURLE_COULDNT_RESOLVE_PROXY,
    HTTP_COULDNT_RESOLVE_HOST = HTTP_ERROR_CODE_BASE + CURLE_COULDNT_RESOLVE_HOST,
    HTTP_COULDNT_CONNECT = HTTP_ERROR_CODE_BASE + CURLE_COULDNT_CONNECT,
    HTTP_WEIRD_SERVER_REPLY = HTTP_ERROR_CODE_BASE + CURLE_WEIRD_SERVER_REPLY,
    HTTP_REMOTE_ACCESS_DENIED = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_ACCESS_DENIED,
    HTTP_HTTP2_ERROR = HTTP_ERROR_CODE_BASE + CURLE_HTTP2,
    HTTP_PARTIAL_FILE = HTTP_ERROR_CODE_BASE + CURLE_PARTIAL_FILE,
    HTTP_WRITE_ERROR = HTTP_ERROR_CODE_BASE + CURLE_WRITE_ERROR,
    HTTP_UPLOAD_FAILED = HTTP_ERROR_CODE_BASE + CURLE_UPLOAD_FAILED,
    HTTP_READ_ERROR = HTTP_ERROR_CODE_BASE + CURLE_READ_ERROR,
    HTTP_OUT_OF_MEMORY = HTTP_ERROR_CODE_BASE + CURLE_OUT_OF_MEMORY,
    HTTP_OPERATION_TIMEDOUT = HTTP_ERROR_CODE_BASE + CURLE_OPERATION_TIMEDOUT,
    HTTP_TOO_MANY_REDIRECTS = HTTP_ERROR_CODE_BASE + CURLE_TOO_MANY_REDIRECTS,
    HTTP_GOT_NOTHING = HTTP_ERROR_CODE_BASE + CURLE_GOT_NOTHING,
    HTTP_SEND_ERROR = HTTP_ERROR_CODE_BASE + CURLE_SEND_ERROR,
    HTTP_RECV_ERROR = HTTP_ERROR_CODE_BASE + CURLE_RECV_ERROR,
    HTTP_SSL_CERTPROBLEM = HTTP_ERROR_CODE_BASE + CURLE_SSL_CERTPROBLEM,
    HTTP_SSL_CIPHER = HTTP_ERROR_CODE_BASE + CURLE_SSL_CIPHER,
    HTTP_PEER_FAILED_VERIFICATION = HTTP_ERROR_CODE_BASE + CURLE_PEER_FAILED_VERIFICATION,
    HTTP_BAD_CONTENT_ENCODING = HTTP_ERROR_CODE_BASE + CURLE_BAD_CONTENT_ENCODING,
    HTTP_FILESIZE_EXCEEDED = HTTP_ERROR_CODE_BASE + CURLE_FILESIZE_EXCEEDED,
    HTTP_REMOTE_DISK_FULL = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_DISK_FULL,
    HTTP_REMOTE_FILE_EXISTS = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_FILE_EXISTS,
    HTTP_SSL_CACERT_BADFILE = HTTP_ERROR_CODE_BASE + CURLE_SSL_CACERT_BADFILE,
    HTTP_REMOTE_FILE_NOT_FOUND = HTTP_ERROR_CODE_BASE + CURLE_REMOTE_FILE_NOT_FOUND,
    HTTP_AUTH_ERROR = HTTP_ERROR_CODE_BASE + CURLE_AUTH_ERROR,
    HTTP_SSL_PINNEDPUBKEYNOTMATCH = HTTP_ERROR_CODE_BASE + CURLE_SSL_PINNEDPUBKEYNOTMATCH,
    HTTP_CLEARTEXT_NOT_PERMITTED = 2300997,
    HTTP_NOT_ALLOWED_HOST = 2300998,
    HTTP_UNKNOWN_OTHER_ERROR = 2300999
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
    static const uint32_t DEFAULT_MAX_LIMIT;
    static const uint32_t MAX_LIMIT;
    static const uint32_t DEFAULT_READ_TIMEOUT;
    static const uint32_t DEFAULT_CONNECT_TIMEOUT;

    static const size_t MAX_JSON_PARSE_SIZE;

    /* options key */
    static const char *const PARAM_KEY_METHOD;
    static const char *const PARAM_KEY_EXTRA_DATA;
    static const char *const PARAM_KEY_HEADER;
    static const char *const PARAM_KEY_MAX_LIMIT;
    static const char *const PARAM_KEY_READ_TIMEOUT;
    static const char *const PARAM_KEY_DNS_SERVERS;
    static const char *const PARAM_KEY_RESUME_FROM;
    static const char *const PARAM_KEY_RESUME_TO;
    static const char *const PARAM_KEY_CONNECT_TIMEOUT;
    static const char *const PARAM_KEY_USING_PROTOCOL;
    static const char *const PARAM_KEY_USING_CACHE;
    static const char *const PARAM_KEY_EXPECT_DATA_TYPE;
    static const char *const PARAM_KEY_PRIORITY;
    static const char *const PARAM_KEY_CA_PATH;
    static const char *const PARAM_KEY_CA_DATA;
    static const char *const PARAM_KEY_DOH_URL;

    static const char *const PARAM_KEY_USING_HTTP_PROXY;
    static const char *const PARAM_KEY_CLIENT_CERT;
    static const char *const PARAM_KEY_MULTI_FORM_DATA_LIST;
    static const char *const PARAM_KEY_CERTIFICATE_PINNING;
    static const char *const PARAM_KEY_REMOTE_VALIDATION;
    static const char *const PARAM_KEY_TLS_OPTION;
    static const char *const PARAM_KEY_SERVER_AUTH;
    static const char *const PARAM_KEY_ADDRESS_FAMILY;

    static const char *const HTTP_PROXY_KEY_HOST;
    static const char *const HTTP_PROXY_KEY_PORT;
    static const char *const HTTP_PROXY_KEY_EXCLUSION_LIST;
    static const char *const HTTP_PROXY_EXCLUSIONS_SEPARATOR;

    static const char *const HTTP_CLIENT_CERT;
    static const char *const HTTP_CLIENT_CERT_TYPE;
    static const char *const HTTP_CLIENT_KEY;
    static const char *const HTTP_CLIENT_KEY_PASSWD;

    static const char *const HTTP_HASH_ALGORITHM;
    static const char *const HTTP_PUBLIC_KEY_HASH;

    static const char *const HTTP_CERT_TYPE_PEM;
    static const char *const HTTP_CERT_TYPE_DER;
    static const char *const HTTP_CERT_TYPE_P12;

    static const char *const TLS_VERSION_1_0;
    static const char *const TLS_VERSION_1_1;
    static const char *const TLS_VERSION_1_2;
    static const char *const TLS_VERSION_1_3;

    static const char *const HTTP_MULTI_FORM_DATA_NAME;
    static const char *const HTTP_MULTI_FORM_DATA_CONTENT_TYPE;
    static const char *const HTTP_MULTI_FORM_DATA_REMOTE_FILE_NAME;
    static const char *const HTTP_MULTI_FORM_DATA_DATA;
    static const char *const HTTP_MULTI_FORM_DATA_FILE_PATH;

    static const char *const RESPONSE_KEY_RESULT;
    static const char *const RESPONSE_KEY_RESPONSE_CODE;
    static const char *const RESPONSE_KEY_HEADER;
    static const char *const RESPONSE_KEY_COOKIES;
    static const char *const RESPONSE_KEY_RESULT_TYPE;
    static const char *const RESPONSE_KEY_SET_COOKIE;
    static const char *const RESPONSE_KEY_SET_COOKIE_SEPARATOR;

    static const char *const RESPONSE_PERFORMANCE_TIMING;
    static const char *const RESPONSE_DNS_TIMING;
    static const char *const RESPONSE_TCP_TIMING;
    static const char *const RESPONSE_TLS_TIMING;
    static const char *const RESPONSE_FIRST_SEND_TIMING;
    static const char *const RESPONSE_FIRST_RECEIVE_TIMING;
    static const char *const RESPONSE_TOTAL_FINISH_TIMING;
    static const char *const RESPONSE_REDIRECT_TIMING;
    static const char *const RESPONSE_HEADER_TIMING;
    static const char *const RESPONSE_BODY_TIMING;
    static const char *const RESPONSE_TOTAL_TIMING;

    static const char *const HTTP_URL_PARAM_START;
    static const char *const HTTP_URL_PARAM_SEPARATOR;
    static const char *const HTTP_URL_NAME_VALUE_SEPARATOR;
    static const char *const HTTP_HEADER_SEPARATOR;
    static const char *const HTTP_HEADER_BLANK_SEPARATOR;
    static const char *const HTTP_LINE_SEPARATOR;
    static const char *const HTTP_RESPONSE_HEADER_SEPARATOR;

    static const char *const HTTP_DEFAULT_USER_AGENT;
    static const char *const HTTP_PREPARE_CA_PATH;

    static const char *const HTTP_CONTENT_TYPE;
    static const char *const HTTP_CONTENT_TYPE_URL_ENCODE;
    static const char *const HTTP_CONTENT_TYPE_JSON;
    static const char *const HTTP_CONTENT_TYPE_OCTET_STREAM;
    static const char *const HTTP_CONTENT_TYPE_IMAGE;
    static const char *const HTTP_CONTENT_TYPE_MULTIPART;

    static const char *const HTTP_CONTENT_ENCODING_GZIP;

    static const char *const REQUEST_TIME;
    static const char *const RESPONSE_TIME;

    static const char *const HTTP_ADDRESS_FAMILY_UNSPEC;
    static const char *const HTTP_ADDRESS_FAMILY_ONLYV4;
    static const char *const HTTP_ADDRESS_FAMILY_ONLYV6;
};
} // namespace OHOS::NetStack::Http

#endif /* COMMUNICATIONNETSTACK_CONSTANT_H */
