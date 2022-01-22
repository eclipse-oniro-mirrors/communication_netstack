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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_BASE_ASYNC_WORK_H
#define COMMUNICATIONNETSTACK_NETSTACK_BASE_ASYNC_WORK_H

#include <memory>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "netstack_base_context.h"
#include "netstack_napi_utils.h"
#include "noncopyable.h"

static constexpr const int PARSE_PARAM_FAILED = -1;

static constexpr const char *BUSINESS_ERROR_KEY = "code";

namespace OHOS::NetStack {
class BaseAsyncWork final {
public:
    ACE_DISALLOW_COPY_AND_MOVE(BaseAsyncWork);

    BaseAsyncWork() = delete;

    template <class Context, bool (*Executor)(Context *)> static void ExecAsyncWork(napi_env env, void *data)
    {
        static_assert(std::is_base_of<BaseContext, Context>::value);

        (void)env;

        auto context = static_cast<Context *>(data);
        if (!context->IsParseOK()) {
            context->SetErrorCode(PARSE_PARAM_FAILED);
            return;
        }

        if (Executor != nullptr) {
            context->SetExecOK(Executor(context));
        }
        /* do not have async executor, execOK should be set in sync work */
    }

    template <class Context, napi_value (*Callback)(Context *)>
    static void AsyncWorkCallback(napi_env env, napi_status status, void *data)
    {
        static_assert(std::is_base_of<BaseContext, Context>::value);

        if (status != napi_ok) {
            return;
        }
        auto deleter = [](Context *context) { delete context; };
        std::unique_ptr<Context, decltype(deleter)> context(static_cast<Context *>(data), deleter);
        size_t argc = 2;
        napi_value argv[2] = {nullptr};
        if (context->IsExecOK()) {
            argv[0] = NapiUtils::GetUndefined(env);

            if (Callback != nullptr) {
                argv[1] = Callback(context.get());
            } else {
                argv[1] = NapiUtils::GetUndefined(env);
            }
            if (argv[1] == nullptr) {
                return;
            }
        } else {
            argv[0] = NapiUtils::CreateObject(env);
            if (argv[0] == nullptr) {
                return;
            }
            NapiUtils::SetInt32Property(env, argv[0], BUSINESS_ERROR_KEY, context->GetErrorCode());

            argv[1] = NapiUtils::GetUndefined(env);
        }

        if (context->GetDeferred() != nullptr) {
            if (context->IsExecOK()) {
                napi_resolve_deferred(env, context->GetDeferred(), argv[1]);
            } else {
                napi_reject_deferred(env, context->GetDeferred(), argv[0]);
            }
            return;
        }

        napi_value func = context->GetCallback();
        napi_value undefined = NapiUtils::GetUndefined(env);
        (void)NapiUtils::CallFunction(env, undefined, func, argc, argv);
    }
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_NETSTACK_BASE_ASYNC_WORK_H */
