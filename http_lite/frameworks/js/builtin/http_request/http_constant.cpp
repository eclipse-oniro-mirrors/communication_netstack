/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace ACELite {
namespace HttpConstant {

int HTTP_RESPONSE_CODE_INVALID = -1;

const char *HTTP_RESPONSE_TYPE_JSON = "json";

const char *HTTP_HEADER_SEPARATOR = ":";

const char *HTTP_DEFAULT_USER_AGENT = "libcurl-agent/1.0";

const char *HTTP_DEFAULT_CONTENT_TYPE = "text/plain";
const char *HTTP_HEADER_KEY_CONTENT_TYPE = "content-type";
const char *HTTP_CONTENT_TYPE_URL_ENCODE = "application/x-www-form-urlencoded";
const char *HTTP_CONTENT_TYPE_JSON = "application/json";

const char *HTTP_URL_PARAM_SEPARATOR = "?";
const char *HTTP_URL_PARAM_DELIMITER = "&";

const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_HEAD = "HEAD";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";

const char *KEY_HTTP_RESPONSE_CODE = "code";
const char *KEY_HTTP_RESPONSE_DATA = "data";
const char *KEY_HTTP_RESPONSE_HEADERS = "headers";

const char *KEY_HTTP_REQUEST_URL = "url";
const char *KEY_HTTP_REQUEST_DATA = "data";
const char *KEY_HTTP_REQUEST_HEADER = "header";
const char *KEY_HTTP_REQUEST_METHOD = "method";
const char *KEY_HTTP_REQUEST_RESPONSE_TYPE = "responseType";

} // namespace HttpConstant
} // namespace ACELite
} // namespace OHOS