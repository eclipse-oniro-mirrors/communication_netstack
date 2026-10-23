/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATION_NETSTACK_CERT_CHAIN_VERIFY_HELPER_H
#define COMMUNICATION_NETSTACK_CERT_CHAIN_VERIFY_HELPER_H

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace OHOS {
namespace NetStack {
namespace CertChain {

using VerifiedChainCheck = bool (*)(STACK_OF(X509) *chain, void *context);

struct CertVerifyPolicy {
    VerifiedChainCheck check;
    void *context;
};

/**
 * @brief Verify the original chain, then retry isolated issuer paths on failure.
 * @param originalContext Optional TLS handshake context used for the first round.
 * @param verifiedChain On success, caller owns the leaf-to-root chain and frees it
 *                      with sk_X509_pop_free(chain, X509_free).
 * @param verifyError Original verification error if all paths fail.
 * @return 1 on success, 0 on verification failure, -1 on invalid input or internal error.
 */
int VerifyMultiCandidateChains(
    X509 *leaf,
    STACK_OF(X509) *untrusted,
    X509_STORE *store,
    STACK_OF(X509) **verifiedChain,
    int *verifyError,
    X509_STORE_CTX *originalContext = nullptr);

/**
 * @brief Adapter for SSL_CTX_set_cert_verify_callback; arg may be a CertVerifyPolicy.
 *        The policy is checked only after a certificate chain verifies successfully.
 */
int CustomCertVerifyCallback(X509_STORE_CTX *x509StoreCtx, void *arg);

} // namespace CertChain
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATION_NETSTACK_CERT_CHAIN_VERIFY_HELPER_H
