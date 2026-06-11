/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_VERIFY_CERT_CHAIN_CONTEXT_H
#define COMMUNICATIONNETSTACK_VERIFY_CERT_CHAIN_CONTEXT_H

#include "base_context.h"
#include "net_ssl.h"

namespace OHOS::NetStack::Ssl {

class VerifyCertChainContext final : public BaseContext {
public:
    VerifyCertChainContext() = delete;

    VerifyCertChainContext(napi_env env, const std::shared_ptr<EventManager> &manager);

    ~VerifyCertChainContext() override;

    void ParseParams(napi_value *params, size_t paramsCount) override;

    bool CheckParamsType(napi_value *params, size_t paramsCount);

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    // Getter methods
    CertBlob *GetInputCerts() { return inputCerts_; }
    size_t GetInputCertCount() const { return inputCertCount_; }
    CertBlob *GetCaCert() { return caCert_; }
    const char *GetHostname() const { return hostname_.empty() ? nullptr : hostname_.c_str(); }

    // Setter methods for output
    void SetSortedChain(CertBlob *chain, size_t count);
    CertBlob *GetSortedChain() { return sortedChain_; }
    size_t GetSortedChainCount() const { return sortedChainCount_; }

private:
    CertBlob *ParseCertBlobArray(napi_env env, napi_value value, size_t *count);
    CertBlob *ParseSingleCertBlob(napi_env env, napi_value value);
    CertBlob *ParseCertBlobFromData(napi_env env, napi_value typeValue, napi_value dataValue);
    CertBlob *ParsePemCertBlob(napi_env env, napi_value dataValue);
    CertBlob *ParseDerCertBlob(napi_env env, napi_value dataValue);
    std::string ParseHostname(napi_env env, napi_value value);

    CertBlob *inputCerts_;
    size_t inputCertCount_;
    CertBlob *caCert_;
    std::string hostname_;

    CertBlob *sortedChain_;
    size_t sortedChainCount_;
};

} // namespace OHOS::NetStack::Ssl

#endif // COMMUNICATIONNETSTACK_VERIFY_CERT_CHAIN_CONTEXT_H
