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

#ifndef OHOS_ACELITE_HTTP_CONSTANT_H
#define OHOS_ACELITE_HTTP_CONSTANT_H

namespace OHOS {
namespace ACELite {
namespace HttpConstant {

extern const int HTTP_RESPONSE_CODE_INVALID;

extern const char *const HTTP_RESPONSE_TYPE_JSON;

extern const char *const HTTP_HEADER_SEPARATOR;

extern const char *const HTTP_DEFAULT_USER_AGENT;

extern const char *const HTTP_DEFAULT_CONTENT_TYPE;
extern const char *const HTTP_HEADER_KEY_CONTENT_TYPE;
extern const char *const HTTP_CONTENT_TYPE_URL_ENCODE;
extern const char *const HTTP_CONTENT_TYPE_JSON;

extern const char *const HTTP_URL_PARAM_SEPARATOR;
extern const char *const HTTP_URL_PARAM_DELIMITER;

extern const char *const HTTP_METHOD_GET;
extern const char *const HTTP_METHOD_HEAD;
extern const char *const HTTP_METHOD_OPTIONS;
extern const char *const HTTP_METHOD_TRACE;
extern const char *const HTTP_METHOD_DELETE;
extern const char *const HTTP_METHOD_POST;
extern const char *const HTTP_METHOD_PUT;

extern const char *const KEY_HTTP_RESPONSE_CODE;
extern const char *const KEY_HTTP_RESPONSE_DATA;
extern const char *const KEY_HTTP_RESPONSE_HEADERS;

extern const char *const KEY_HTTP_REQUEST_URL;
extern const char *const KEY_HTTP_REQUEST_DATA;
extern const char *const KEY_HTTP_REQUEST_HEADER;
extern const char *const KEY_HTTP_REQUEST_METHOD;
extern const char *const KEY_HTTP_REQUEST_RESPONSE_TYPE;

} // namespace HttpConstant
} // namespace ACELite
} // namespace OHOS

#endif /* OHOS_ACELITE_HTTP_CONSTANT_H */
