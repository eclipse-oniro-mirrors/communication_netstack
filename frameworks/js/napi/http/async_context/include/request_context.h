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

#ifndef COMMUNICATIONNETSTACK_REQUEST_CONTEXT_H
#define COMMUNICATIONNETSTACK_REQUEST_CONTEXT_H

#include "http_request_options.h"
#include "http_response.h"
#include "netstack_base_context.h"
#include "noncopyable.h"

namespace OHOS::NetStack {
class RequestContext final : public BaseContext {
public:
    ACE_DISALLOW_COPY_AND_MOVE(RequestContext);

    RequestContext() = delete;

    explicit RequestContext(napi_env env, EventManager *manager);

    void ParseParams(napi_value *params, size_t paramsCount);

    HttpRequestOptions options;

    HttpResponse response;

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    void ParseNumberOptions(napi_value optionsValue);

    void ParseHeader(napi_value optionsValue);

    bool ParseExtraData(napi_value optionsValue);

    bool GetRequestBody(napi_value extraData);

    void UrlAndOptions(napi_value urlValue, napi_value optionsValue);
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_REQUEST_CONTEXT_H */
