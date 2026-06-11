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
#include "net_ssl.h"
#include "net_ssl_verify_cert.h"
#include "net_ssl_async_work.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Ssl {
bool SslExec::ExecVerify(CertContext *context)
{
    context->SetPermissionDenied(true);

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
            return false;
        }
    } else {
        context->SetErrorCode(NetStackVerifyCertification(context->GetCertBlob(), context->GetCertBlobClient()));
        NETSTACK_LOGD("verifyResult is %{public}d\n", context->GetErrorCode());
        if (context->GetErrorCode() != 0) {
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

bool SslExec::ExecVerifyCertChain(VerifyCertChainContext *context)
{
    context->SetPermissionDenied(true);

    if (context->GetErrorCode() == PARSE_ERROR_CODE) {
        return false;
    }

    if (context->GetInputCerts() == nullptr || context->GetInputCertCount() == 0) {
        return false;
    }

    CertBlob *sortedChain = nullptr;
    size_t sortedCount = 0;

    uint32_t result = VerifyAndBuildCertChain(
        context->GetInputCerts(),
        context->GetInputCertCount(),
        context->GetCaCert(),
        context->GetHostname(),
        &sortedChain,
        &sortedCount);

    context->SetErrorCode(result);

    if (result == 0) {
        context->SetSortedChain(sortedChain, sortedCount);
        return true;
    }

    return false;
}

napi_value SslExec::VerifyCertChainCallback(VerifyCertChainContext *context)
{
    napi_env env = context->GetEnv();

    if (context->GetErrorCode() != 0) {
        // Error will be handled by AsyncWork callback
        return nullptr;
    }

    // Build return array of CertBlob
    napi_value result;
    napi_create_array_with_length(env, context->GetSortedChainCount(), &result);

    CertBlob *chain = context->GetSortedChain();
    if (chain == nullptr) {
        NETSTACK_LOGE("Sorted chain is nullptr");
        return result;
    }

    for (size_t i = 0; i < context->GetSortedChainCount(); i++) {
        napi_value certObj = NapiUtils::CreateObject(env);

        // Set type
        napi_value typeValue = NapiUtils::CreateUint32(env, static_cast<uint32_t>(chain[i].type));
        NapiUtils::SetNamedProperty(env, certObj, "type", typeValue);

        // Set data
        napi_value dataValue;
        if (chain[i].type == CERT_TYPE_PEM) {
            // PEM data should be null-terminated string
            if (chain[i].data == nullptr || chain[i].size == 0) {
                NETSTACK_LOGE("PEM cert data is nullptr or empty at index %{public}zu", i);
                continue;
            }
            napi_create_string_utf8(env, reinterpret_cast<char *>(chain[i].data),
                                    NAPI_AUTO_LENGTH, &dataValue);
        } else {
            // DER data is binary
            if (chain[i].data == nullptr || chain[i].size == 0) {
                NETSTACK_LOGE("DER cert data is nullptr or empty at index %{public}zu", i);
                continue;
            }
            void *data = nullptr;
            napi_create_arraybuffer(env, chain[i].size, &data, &dataValue);
            if (data != nullptr) {
                std::copy(chain[i].data, chain[i].data + chain[i].size,
                         static_cast<uint8_t *>(data));
            }
        }
        NapiUtils::SetNamedProperty(env, certObj, "data", dataValue);

        napi_set_element(env, result, i, certObj);
    }

    return result;
}

#ifndef MAC_PLATFORM
void SslExec::AsyncRunVerify(CertContext *context)
{
    NetSslAsyncWork::ExecVerify(context->GetEnv(), context);
}

void SslExec::AsyncRunVerifyCertChain(VerifyCertChainContext *context)
{
    NetSslAsyncWork::ExecVerifyCertChain(context->GetEnv(), context);
}
#endif
} // namespace OHOS::NetStack::Ssl
