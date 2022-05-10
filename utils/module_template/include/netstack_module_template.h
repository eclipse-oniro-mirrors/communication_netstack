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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_MODULE_TEMPLATE_H
#define COMMUNICATIONNETSTACK_NETSTACK_MODULE_TEMPLATE_H

#include <initializer_list>

#include "netstack_base_async_work.h"
#include "netstack_base_context.h"
#include "netstack_log.h"

#define MAX_PARAM_NUM 64

namespace OHOS::NetStack::ModuleTemplate {
typedef void (*Finalizer)(napi_env, void *data, void *);

template <class Context>
napi_value Interface(napi_env env,
                     napi_callback_info info,
                     const std::string &asyncWorkName,
                     bool (*Work)(napi_env, napi_value, Context *),
                     AsyncWorkExecutor executor,
                     AsyncWorkCallback callback)
{
    static_assert(std::is_base_of<BaseContext, Context>::value);

    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    EventManager *manager = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&manager));

    auto context = new Context(env, manager);
    context->ParseParams(params, paramsCount);
    NETSTACK_LOGI("js params parse OK ? %{public}d", context->IsParseOK());
    if (Work != nullptr) {
        if (!Work(env, thisVal, context)) {
            NETSTACK_LOGE("work failed error code = %{public}d", context->GetErrorCode());
        }
    }

    context->CreateAsyncWork(asyncWorkName, executor, callback);
    if (NapiUtils::GetValueType(env, context->GetCallback()) != napi_function && context->IsNeedPromise()) {
        NETSTACK_LOGI("context->CreatePromise()");
        return context->CreatePromise();
    }
    return NapiUtils::GetUndefined(env);
}

template <class Context>
napi_value
    InterfaceWithOutAsyncWork(napi_env env, napi_callback_info info, bool (*Work)(napi_env, napi_value, Context *))
{
    static_assert(std::is_base_of<BaseContext, Context>::value);

    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));

    EventManager *manager = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&manager));

    auto context = new Context(env, manager);
    context->ParseParams(params, paramsCount);
    if (Work != nullptr) {
        if (!Work(env, thisVal, context)) {
            NETSTACK_LOGE("work failed error code = %{public}d", context->GetErrorCode());
        }
    }

    if (NapiUtils::GetValueType(env, context->GetCallback()) != napi_function && context->IsNeedPromise()) {
        return context->CreatePromise();
    }
    return NapiUtils::GetUndefined(env);
}

napi_value
    On(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events, bool asyncCallback);

napi_value
    Once(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events, bool asyncCallback);

napi_value Off(napi_env env, napi_callback_info info, const std::initializer_list<std::string> &events);

void DefineClass(napi_env env,
                 napi_value exports,
                 const std::initializer_list<napi_property_descriptor> &properties,
                 const std::string &className);

napi_value NewInstance(napi_env env, napi_callback_info info, const std::string &className, Finalizer finalizer);
} // namespace OHOS::NetStack::ModuleTemplate
#endif /* COMMUNICATIONNETSTACK_NETSTACK_MODULE_TEMPLATE_H */
