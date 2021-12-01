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

#ifndef OHOS_ACELITE_HTTP_REQUEST_UTILS_H
#define OHOS_ACELITE_HTTP_REQUEST_UTILS_H

#include <string>
#include <vector>

#include "ace_log.h"
#include "curl/curl.h"

#define HTTP_REQUEST_INFO(...)                                     \
    do {                                                           \
        HILOG_INFO(HILOG_MODULE_ACE, "[HTTP][INFO] " __VA_ARGS__); \
    } while (0)

#define HTTP_REQUEST_ERROR(...)                                      \
    do {                                                             \
        HILOG_ERROR(HILOG_MODULE_ACE, "[HTTP][ERROR] " __VA_ARGS__); \
    } while (0)

namespace OHOS {
namespace ACELite {

std::vector<std::string> Split(const std::string &str, const std::string &sep);

std::string Strip(const std::string &str, char ch = ' ');

bool MethodForGet(const std::string &method);

bool MethodForPost(const std::string &method);

std::string MakeUrl(const std::string &url, std::string param, const std::string &extraParam);

bool EncodeUrlParam(CURL *curl, std::string &url);
} // namespace ACELite
} // namespace OHOS

#endif /* OHOS_ACELITE_HTTP_REQUEST_UTILS_H */
