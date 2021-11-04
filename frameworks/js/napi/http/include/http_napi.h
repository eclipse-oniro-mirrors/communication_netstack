/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef HTTP_NAPI_H
#define HTTP_NAPI_H

#include "http_event_list.h"
#include "http_request.h"
#include "napi_util.h"

#include <list>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace OHOS {
namespace NetManagerStandard {
const int32_t MAX_URL_LENGTH = 1024;
constexpr int32_t URL_ARRAY_LENGTH = 256;
constexpr int32_t MAX_HTTP_OBJ_COUNT = 100;

constexpr int32_t NONE_EVENT_TYPE = 0;
constexpr int32_t LISTEN_HTTP_WORK_STATE = 1;

constexpr std::int32_t CREATE_MAX_PARA = 2;
constexpr std::int32_t SUBSCRIBE_MAX_PARA = 2;
constexpr std::int32_t UNSUBSCRIBE_MAX_PARA = 2;
constexpr std::int32_t PUBLISH_MAX_PARA_BY_PUBLISHDATA = 3;

const std::string HEADER_RECEIVE = "headerReceive";

static std::mutex g_map_mutex_;

static napi_value g_HttpRequestConstructorJS;
static std::map<HttpRequest *, HttpRequestOptionsContext *> httpRequestInstances;
static std::list<EventListener> g_eventListenerList;

napi_value CreateHttp(napi_env env, napi_callback_info info);
napi_value Request(napi_env env, napi_callback_info info);
napi_value Destroy(napi_env env, napi_callback_info info);
napi_value On(napi_env env, napi_callback_info info);
napi_value Off(napi_env env, napi_callback_info info);
napi_value HttpRequestConstructor(napi_env env, napi_callback_info info);
napi_value CreateHttp(napi_env env, napi_callback_info info);

} // namespace NetManagerStandard
} // namespace OHOS
#endif // HTTP_NAPI_H