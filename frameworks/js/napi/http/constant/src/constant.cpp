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

#include "constant.h"

namespace OHOS::NetStack {
const char *const HttpConstant::HTTP_METHOD_GET = "GET";
const char *const HttpConstant::HTTP_METHOD_HEAD = "HEAD";
const char *const HttpConstant::HTTP_METHOD_OPTIONS = "OPTIONS";
const char *const HttpConstant::HTTP_METHOD_TRACE = "TRACE";
const char *const HttpConstant::HTTP_METHOD_DELETE = "DELETE";
const char *const HttpConstant::HTTP_METHOD_POST = "POST";
const char *const HttpConstant::HTTP_METHOD_PUT = "PUT";
const char *const HttpConstant::HTTP_METHOD_CONNECT = "CONNECT";

const uint32_t HttpConstant::DEFAULT_READ_TIMEOUT = 60000;
const uint32_t HttpConstant::DEFAULT_CONNECT_TIMEOUT = 60000;
const uint32_t HttpConstant::DEFAULT_IF_MODIFIED_SINCE = 0;
const int32_t HttpConstant::DEFAULT_FIXED_LENGTH_STREAMING_MODE = -1;

const char *const HttpConstant::PARAM_KEY_METHOD = "method";
const char *const HttpConstant::PARAM_KEY_EXTRA_DATA = "extraData";
const char *const HttpConstant::PARAM_KEY_HEADER = "header";
const char *const HttpConstant::PARAM_KEY_READ_TIMEOUT = "readTimeout";
const char *const HttpConstant::PARAM_KEY_CONNECT_TIMEOUT = "connectTimeout";
const char *const HttpConstant::PARAM_KEY_IF_MODIFIED_SINCE = "ifModifiedSince";
const char *const HttpConstant::PARAM_KEY_FIXED_LENGTH_STREAMING_MODE = "fixedLengthStreamingMode";

const char *const HttpConstant::RESPONSE_KEY_RESULT = "result";
const char *const HttpConstant::RESPONSE_KEY_RESPONSE_CODE = "responseCode";
const char *const HttpConstant::RESPONSE_KEY_HEADER = "header";
const char *const HttpConstant::RESPONSE_KEY_COOKIES = "cookies";

const char *const HttpConstant::HTTP_URL_PARAM_START = "?";
const char *const HttpConstant::HTTP_URL_PARAM_SEPARATOR = "&";
const char *const HttpConstant::HTTP_URL_NAME_VALUE_SEPARATOR = "=";
const char *const HttpConstant::HTTP_HEADER_SEPARATOR = ":";
const char *const HttpConstant::HTTP_LINE_SEPARATOR = "\r\n";

const char *const HttpConstant::HTTP_DEFAULT_USER_AGENT = "libcurl-agent/1.0";
const char *const HttpConstant::HTTP_DEFAULT_CA_PATH = "/etc/ssl/certs/cacert.pem";

const char *const HttpConstant::HTTP_CONTENT_TYPE = "content-type";
const char *const HttpConstant::HTTP_CONTENT_TYPE_URL_ENCODE = "application/x-www-form-urlencoded";
const char *const HttpConstant::HTTP_CONTENT_TYPE_JSON = "application/json";
const char *const HttpConstant::HTTP_CONTENT_TYPE_OCTET_STREAM = "application/octet-stream";
const char *const HttpConstant::HTTP_CONTENT_TYPE_JPEG_STREAM = "image/jpeg";
} // namespace OHOS::NetStack