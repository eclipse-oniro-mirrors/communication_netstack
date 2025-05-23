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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_BASE_ASYNC_WORK_H
#define COMMUNICATIONNETSTACK_NETSTACK_BASE_ASYNC_WORK_H

#include <limits>
#include <memory>
#include <securec.h>

#include <napi/native_api.h>
#include <napi/native_common.h>

#include "base_context.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS::NetStack {
class BaseAsyncWork final {
public:
    BaseAsyncWork() = delete;

    template <class Context, bool (*Executor)(Context *)> static void ExecAsyncWork(napi_env env, void *data)
    {
        static_assert(std::is_base_of<BaseContext, Context>::value);

        (void)env;

        auto context = reinterpret_cast<Context *>(data);
        if (context == nullptr || Executor == nullptr) {
            NETSTACK_LOGE("context or Executor is nullptr");
            return;
        }
        if (!context->IsParseOK()) {
            context->SetError(PARSE_ERROR_CODE, PARSE_ERROR_MSG); // if developer not set error, there will set.
            NETSTACK_LOGE("parameter error");
            return;
        }
        context->SetExecOK(Executor(context));
        /* do not have async executor, execOK should be set in sync work */
    }

    template <class Context, napi_value (*Callback)(Context *)>
    static void AsyncWorkCallback(napi_env env, napi_status status, void *data)
    {
        static_assert(std::is_base_of<BaseContext, Context>::value);

        if (!data) {
            return;
        }
        auto baseContext = reinterpret_cast<BaseContext *>(data);
        if (baseContext->GetDeferred() != baseContext->deferredBack1_ ||
            baseContext->GetDeferred() != baseContext->deferredBack2_ ||
            baseContext->GetDeferred() != baseContext->deferredBack3_ ||
            baseContext->GetDeferred() != baseContext->deferredBack4_) {
            return;
        }
        if (baseContext->GetAsyncWork() != baseContext->asyncWorkBack1_ ||
            baseContext->GetAsyncWork() != baseContext->asyncWorkBack2_ ||
            baseContext->GetAsyncWork() != baseContext->asyncWorkBack3_ ||
            baseContext->GetAsyncWork() != baseContext->asyncWorkBack4_) {
            return;
        }

        if (status != napi_ok) {
            return;
        }
        auto deleter = [](Context *context) {
            context->DeleteReference();
            delete context;
            context = nullptr;
        };
        std::unique_ptr<Context, decltype(deleter)> context(static_cast<Context *>(data), deleter);
        size_t argc = 2;
        napi_value argv[2] = {nullptr};
        if (context->IsParseOK() && context->IsExecOK()) {
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
            argv[0] = NapiUtils::CreateErrorMessage(env, context->GetErrorCode(), context->GetErrorMessage());
            if (argv[0] == nullptr) {
                return;
            }

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
        if (NapiUtils::GetValueType(env, func) == napi_function) {
            napi_value undefined = NapiUtils::GetUndefined(env);
            (void)NapiUtils::CallFunction(env, undefined, func, argc, argv);
        }
    }

    template <class Context, napi_value (*Callback)(Context *)>
    static void AsyncWorkCallbackForSystem(napi_env env, napi_status status, void *data)
    {
        static_assert(std::is_base_of<BaseContext, Context>::value);

        if (status != napi_ok) {
            return;
        }
        auto deleter = [](Context *context) { delete context; };
        std::unique_ptr<Context, decltype(deleter)> context(static_cast<Context *>(data), deleter);
        if (Callback != nullptr) {
            (void)Callback(context.get());
        }
    }
};
} // namespace OHOS::NetStack

#endif /* COMMUNICATIONNETSTACK_NETSTACK_BASE_ASYNC_WORK_H */
