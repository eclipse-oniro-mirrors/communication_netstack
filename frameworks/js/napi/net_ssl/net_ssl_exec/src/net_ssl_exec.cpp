/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "net_ssl_exec.h"

#include "napi_utils.h"
#include "net_ssl_async_work.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Ssl {
template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplate(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);

    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);

    delete workWrapper;
    delete work;
}

bool SslExec::ExecVerify(CertContext *context)
{
    context->SetPermissionDenied(true);

    if (context->GetManager()->IsEventDestroy()) {
        return false;
    }

    if (context->GetErrorCode() == PARSE_ERROR_CODE) {
        return false;
    }

    if (context->GetCertBlob() == nullptr) {
        return false;
    }

    if (context->GetCertBlobClient() == nullptr) {
        context->SetErrorCode(NetStackVerifyCertification(context->GetCertBlob()));
        NETSTACK_LOGD("verifyResult is %{public}d\n", context->GetErrorCode());

        if (context->GetErrorCode() != 0) {
            if (EventManager::IsManagerValid(context->GetManager())) {
                NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, NetSslAsyncWork::VerifyCallback);
            }
            return false;
        }
    } else {
        context->SetErrorCode(NetStackVerifyCertification(context->GetCertBlob(), context->GetCertBlobClient()));
        NETSTACK_LOGD("verifyResult is %{public}d\n", context->GetErrorCode());
        if (context->GetErrorCode() != 0) {
            if (EventManager::IsManagerValid(context->GetManager())) {
                NapiUtils::CreateUvQueueWorkEnhanced(context->GetEnv(), context, NetSslAsyncWork::VerifyCallback);
            }
            return false;
        }
    }

    return true;
}

napi_value SslExec::VerifyCallback(CertContext *context)
{
    napi_value result;
    napi_create_int32(context->GetEnv(), static_cast<int32_t>(context->GetErrorCode()), &result);
    return result;
}

#ifndef MAC_PLATFORM
void SslExec::AsyncRunVerify(CertContext *context)
{
    NetSslAsyncWork::ExecVerify(context->GetEnv(), context);
}
#endif
} // namespace OHOS::NetStack::Ssl
