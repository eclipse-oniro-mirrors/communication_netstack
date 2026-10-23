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

#include "cert_chain_verify_helper.h"

#include <vector>

#include <openssl/x509v3.h>

#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace CertChain {

namespace {

constexpr size_t MAX_CANDIDATE_ROUNDS = 32;

STACK_OF(X509) *CloneVerifiedChain(X509_STORE_CTX *ctx)
{
    return X509_STORE_CTX_get1_chain(ctx);
}

STACK_OF(X509) *BuildCandidateStack(
    STACK_OF(X509) *untrusted, const std::vector<int> &path)
{
    STACK_OF(X509) *candidate = sk_X509_new_null();
    if (candidate == nullptr) {
        return nullptr;
    }
    for (int index : path) {
        X509 *cert = sk_X509_value(untrusted, index);
        if (cert == nullptr || X509_up_ref(cert) != 1) {
            sk_X509_pop_free(candidate, X509_free);
            return nullptr;
        }
        if (!sk_X509_push(candidate, cert)) {
            X509_free(cert);
            sk_X509_pop_free(candidate, X509_free);
            return nullptr;
        }
    }
    return candidate;
}

// Build isolated issuer paths so a self-signed duplicate cannot mask a cross-signed path.
void EnumerateIssuerPaths(X509 *child, STACK_OF(X509) *untrusted,
    std::vector<bool> &used, std::vector<int> &path,
    std::vector<std::vector<int>> &paths)
{
    if (paths.size() >= MAX_CANDIDATE_ROUNDS) {
        return;
    }
    int count = sk_X509_num(untrusted);
    for (int i = 0; i < count; ++i) {
        if (used[static_cast<size_t>(i)]) {
            continue;
        }
        X509 *issuer = sk_X509_value(untrusted, i);
        if (issuer == nullptr || X509_check_issued(issuer, child) != X509_V_OK) {
            continue;
        }

        used[static_cast<size_t>(i)] = true;
        path.push_back(i);
        paths.push_back(path);
        // A self-issued certificate terminates this candidate path.
        if (X509_check_issued(issuer, issuer) != X509_V_OK) {
            EnumerateIssuerPaths(issuer, untrusted, used, path, paths);
        }
        path.pop_back();
        used[static_cast<size_t>(i)] = false;
        if (paths.size() >= MAX_CANDIDATE_ROUNDS) {
            return;
        }
    }
}

bool CopyContextSettings(X509_STORE_CTX *destination, X509_STORE_CTX *source)
{
    if (source == nullptr) {
        return true;
    }

    X509_VERIFY_PARAM *sourceParam = X509_STORE_CTX_get0_param(source);
    X509_VERIFY_PARAM *destinationParam = X509_STORE_CTX_get0_param(destination);
    if (sourceParam == nullptr || destinationParam == nullptr ||
        X509_VERIFY_PARAM_set1(destinationParam, sourceParam) != 1) {
        return false;
    }

    X509_STORE_CTX_set_verify_cb(destination, X509_STORE_CTX_get_verify_cb(source));
    int sslIndex = SSL_get_ex_data_X509_STORE_CTX_idx();
    void *ssl = X509_STORE_CTX_get_ex_data(source, sslIndex);
    return ssl == nullptr ||
        X509_STORE_CTX_set_ex_data(destination, sslIndex, ssl) == 1;
}

struct VerificationRoundInput {
    int round;
    X509 *leaf;
    STACK_OF(X509) *candidate;
    X509_STORE *store;
    X509_STORE_CTX *originalContext;
    bool useOriginalContext;
};

X509_STORE_CTX *CreateRoundContext(const VerificationRoundInput &input)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == nullptr) {
        return nullptr;
    }
    if (X509_STORE_CTX_init(ctx, input.store, input.leaf, input.candidate) != 1 ||
        !CopyContextSettings(ctx, input.originalContext)) {
        X509_STORE_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

int RunVerificationRound(const VerificationRoundInput &input,
    STACK_OF(X509) **verifiedChain, int *verifyError)
{
    X509_STORE_CTX *ctx = input.useOriginalContext ?
        input.originalContext : CreateRoundContext(input);
    if (ctx == nullptr) {
        *verifyError = X509_V_ERR_OUT_OF_MEM;
        return -1;
    }

    int result = X509_verify_cert(ctx);
    if (result == 1) {
        STACK_OF(X509) *chain = CloneVerifiedChain(ctx);
        if (!input.useOriginalContext) {
            X509_STORE_CTX_free(ctx);
        }
        if (chain == nullptr) {
            *verifyError = X509_V_ERR_OUT_OF_MEM;
            return -1;
        }
        *verifiedChain = chain;
        *verifyError = X509_V_OK;
        NETSTACK_LOGD("CertChain: verification succeeded in round %{public}d", input.round);
        return 1;
    }

    *verifyError = result < 0 ? X509_V_ERR_OUT_OF_MEM :
        X509_STORE_CTX_get_error(ctx);
    NETSTACK_LOGD("CertChain: round %{public}d failed: %{public}s (depth=%{public}d)",
        input.round, X509_verify_cert_error_string(*verifyError),
        X509_STORE_CTX_get_error_depth(ctx));
    if (!input.useOriginalContext) {
        X509_STORE_CTX_free(ctx);
    }
    return result < 0 ? -1 : 0;
}

int RetryIssuerPaths(X509 *leaf, STACK_OF(X509) *untrusted, X509_STORE *store,
    X509_STORE_CTX *originalContext, STACK_OF(X509) **verifiedChain, int *verifyError)
{
    int count = sk_X509_num(untrusted);
    std::vector<std::vector<int>> paths;
    std::vector<int> path;
    std::vector<bool> used(static_cast<size_t>(count), false);
    EnumerateIssuerPaths(leaf, untrusted, used, path, paths);

    int round = 1;
    for (const auto &candidatePath : paths) {
        STACK_OF(X509) *candidate = BuildCandidateStack(untrusted, candidatePath);
        if (candidate == nullptr) {
            *verifyError = X509_V_ERR_OUT_OF_MEM;
            return -1;
        }
        int candidateError = X509_V_ERR_UNSPECIFIED;
        VerificationRoundInput retryRound = {
            round++, leaf, candidate, store, originalContext, false};
        int result = RunVerificationRound(retryRound, verifiedChain, &candidateError);
        sk_X509_pop_free(candidate, X509_free);
        if (result == 1) {
            *verifyError = X509_V_OK;
            return 1;
        }
        if (result < 0) {
            *verifyError = candidateError;
            return -1;
        }
    }
    return 0;
}

} // namespace

int VerifyMultiCandidateChains(X509 *leaf, STACK_OF(X509) *untrusted,
    X509_STORE *store, STACK_OF(X509) **verifiedChain, int *verifyError,
    X509_STORE_CTX *originalContext)
{
    if (leaf == nullptr || store == nullptr || verifiedChain == nullptr ||
        verifyError == nullptr) {
        return -1;
    }
    *verifiedChain = nullptr;
    *verifyError = X509_V_ERR_UNSPECIFIED;

    // Verify the original chain first; TLS handshakes retain their original context.
    int originalError = X509_V_ERR_UNSPECIFIED;
    VerificationRoundInput originalRound = {
        0, leaf, untrusted, store, originalContext, originalContext != nullptr};
    int result = RunVerificationRound(originalRound, verifiedChain, &originalError);
    if (result != 0) {
        *verifyError = result == 1 ? X509_V_OK : X509_V_ERR_OUT_OF_MEM;
        return result;
    }

    int count = untrusted == nullptr ? 0 : sk_X509_num(untrusted);
    if (count <= 0) {
        *verifyError = originalError;
        return 0;
    }

    result = RetryIssuerPaths(leaf, untrusted, store, originalContext,
        verifiedChain, verifyError);
    if (result != 0) {
        return result;
    }

    // Preserve the original error when every candidate fails.
    *verifyError = originalError;
    return 0;
}

int CustomCertVerifyCallback(X509_STORE_CTX *x509StoreCtx, void *arg)
{
    if (x509StoreCtx == nullptr) {
        return 0;
    }

    X509_STORE *store = X509_STORE_CTX_get0_store(x509StoreCtx);
    X509 *leaf = X509_STORE_CTX_get0_cert(x509StoreCtx);
    STACK_OF(X509) *untrusted =
        X509_STORE_CTX_get0_untrusted(x509StoreCtx);
    if (store == nullptr || leaf == nullptr) {
        return 0;
    }

    STACK_OF(X509) *verifiedChain = nullptr;
    int verifyError = X509_V_ERR_UNSPECIFIED;
    int result = VerifyMultiCandidateChains(leaf, untrusted, store,
        &verifiedChain, &verifyError, x509StoreCtx);
    if (result == 1 && verifiedChain != nullptr) {
        auto policy = static_cast<const CertVerifyPolicy *>(arg);
        if (policy != nullptr && policy->check != nullptr &&
            !policy->check(verifiedChain, policy->context)) {
            sk_X509_pop_free(verifiedChain, X509_free);
            X509_STORE_CTX_set_error(x509StoreCtx, X509_V_ERR_APPLICATION_VERIFICATION);
            return 0;
        }
        X509_STORE_CTX_set0_verified_chain(x509StoreCtx, verifiedChain);
        X509_STORE_CTX_set_error(x509StoreCtx, X509_V_OK);
        return 1;
    }

    sk_X509_pop_free(verifiedChain, X509_free);
    X509_STORE_CTX_set_error(x509StoreCtx, verifyError);
    return 0;
}

} // namespace CertChain
} // namespace NetStack
} // namespace OHOS
