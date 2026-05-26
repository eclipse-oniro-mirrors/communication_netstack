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

#include <fstream>
#include <iostream>
#include <string>

#include "ipc_skeleton.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace Ssl {

const char *const SslConstant::SYSPRECAPATH = "/etc/security/certificates";
const char *const SslConstant::USERINSTALLEDCAPATH = "/data/certificates/user_cacerts";
const int SslConstant::UIDTRANSFORMDIVISOR = 200000;

std::string GetUserInstalledCaPath()
{
    std::string userInstalledCaPath = SslConstant::USERINSTALLEDCAPATH;
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    NETSTACK_LOGD("uid: %{public}d\n", uid);
    uid /= SslConstant::UIDTRANSFORMDIVISOR;
    return userInstalledCaPath.append("/").append(std::to_string(uid).c_str());
}

X509 *PemToX509(const uint8_t *pemCert, size_t pemSize)
{
    BIO *bio = BIO_new_mem_buf(pemCert, pemSize);
    if (bio == nullptr) {
        NETSTACK_LOGE("Failed to create BIO of PEM\n");
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (x509 == nullptr) {
        NETSTACK_LOGE("Failed to convert PEM to X509\n");
        BIO_free(bio);
        bio = nullptr;
        return nullptr;
    }

    BIO_free(bio);
    bio = nullptr;
    return x509;
}

X509 *DerToX509(const uint8_t *derCert, size_t derSize)
{
    BIO *bio = BIO_new_mem_buf(derCert, derSize);
    if (bio == nullptr) {
        NETSTACK_LOGE("Failed to create BIO of DER\n");
        return nullptr;
    }

    X509 *x509 = d2i_X509_bio(bio, nullptr);
    if (x509 == nullptr) {
        NETSTACK_LOGE("Failed to convert DER to X509\n");
        BIO_free(bio);
        bio = nullptr;
        return nullptr;
    }

    BIO_free(bio);
    bio = nullptr;
    return x509;
}

X509 *CertBlobToX509(const CertBlob *cert)
{
    X509 *x509 = nullptr;
    do {
        if (cert == nullptr) {
            continue;
        }
        switch (cert->type) {
            case CERT_TYPE_PEM:
                x509 = PemToX509(cert->data, cert->size);
                if (x509 == nullptr) {
                    NETSTACK_LOGE("x509 of PEM cert is nullptr\n");
                }
                break;
            case CERT_TYPE_DER:
                x509 = DerToX509(cert->data, cert->size);
                if (x509 == nullptr) {
                    NETSTACK_LOGE("x509 of DER cert is nullptr\n");
                }
                break;
            default:
                break;
        }
    } while (false);
    return x509;
}

uint32_t VerifyCert(const CertBlob *cert)
{
    uint32_t verifyResult = SSL_X509_V_ERR_UNSPECIFIED;
    X509 *certX509 = nullptr;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    do {
        certX509 = CertBlobToX509(cert);
        if (certX509 == nullptr) {
            NETSTACK_LOGE("x509 of cert is nullptr\n");
        }
        store = X509_STORE_new();
        if (store == nullptr) {
            continue;
        }
        std::string userInstalledCaPath = GetUserInstalledCaPath();
        if (X509_STORE_load_locations(store, nullptr, SslConstant::SYSPRECAPATH) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("load SYSPRECAPATH store failed\n");
        }
        if (X509_STORE_load_locations(store, nullptr, userInstalledCaPath.c_str()) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGI("load userInstalledCaPath store failed\n");
        }
        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            continue;
        }
        X509_STORE_CTX_init(ctx, store, certX509, nullptr);
        verifyResult = static_cast<uint32_t>(X509_verify_cert(ctx));
        if (verifyResult != VERIFY_RESULT_SUCCESS) {
            verifyResult = static_cast<uint32_t>(X509_STORE_CTX_get_error(ctx) + SSL_ERROR_CODE_BASE);
            NETSTACK_LOGE("failed to verify certificate: %{public}s (%{public}d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        } else {
            verifyResult = X509_V_OK;
            NETSTACK_LOGD("certificate validation succeeded.\n");
        }
    } while (false);

    FreeResources(&certX509, nullptr, &store, &ctx);
    return verifyResult;
}

uint32_t VerifyCert(const CertBlob *cert, const CertBlob *caCert)
{
    uint32_t verifyResult = SSL_X509_V_ERR_UNSPECIFIED;
    X509 *certX509 = nullptr;
    X509 *caX509 = nullptr;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    do {
        certX509 = CertBlobToX509(cert);
        if (certX509 == nullptr) {
            NETSTACK_LOGE("x509 of cert is nullptr\n");
        }
        caX509 = CertBlobToX509(caCert);
        if (caX509 == nullptr) {
            NETSTACK_LOGE("x509 of ca is nullptr\n");
        }
        store = X509_STORE_new();
        if (store == nullptr) {
            continue;
        }
        if (X509_STORE_add_cert(store, caX509) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("add ca to store failed\n");
        }
        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            continue;
        }
        X509_STORE_CTX_init(ctx, store, certX509, nullptr);
        verifyResult = static_cast<uint32_t>(X509_verify_cert(ctx));
        if (verifyResult != VERIFY_RESULT_SUCCESS) {
            verifyResult = static_cast<uint32_t>(X509_STORE_CTX_get_error(ctx) + SSL_ERROR_CODE_BASE);
            NETSTACK_LOGE("failed to verify certificate: %{public}s (%{public}d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        } else {
            verifyResult = X509_V_OK;
            NETSTACK_LOGD("certificate validation succeeded.\n");
        }
    } while (false);

    FreeResources(&certX509, &caX509, &store, &ctx);
    return verifyResult;
}

void FreeResources(X509 **certX509, X509 **caX509, X509_STORE **store, X509_STORE_CTX **ctx)
{
    if (certX509 != nullptr) {
        if (*certX509 != nullptr) {
            X509_free(*certX509);
            *certX509 = nullptr;
        }
    }
    if (caX509 != nullptr) {
        if (*caX509 != nullptr) {
            X509_free(*caX509);
            *caX509 = nullptr;
        }
    }
    if (store != nullptr) {
        if (*store != nullptr) {
            X509_STORE_free(*store);
            *store = nullptr;
        }
    }
    if (ctx != nullptr) {
        if (*ctx != nullptr) {
            X509_STORE_CTX_free(*ctx);
            *ctx = nullptr;
        }
    }
}

uint32_t VerifyHostname(X509 *cert, const char *hostname)
{
    if (cert == nullptr || hostname == nullptr || strlen(hostname) == 0) {
        NETSTACK_LOGE("Invalid parameters for hostname verification\n");
        return SSL_X509_V_ERR_HOSTNAME_MISMATCH;
    }

    // Use X509_check_host for hostname verification
    // Returns: 1 for match, 0 for no match, -1 for internal error, -2 for invalid input
    int result = X509_check_host(cert, hostname, strlen(hostname), 0, nullptr);
    if (result == 1) {
        NETSTACK_LOGD("Hostname verification succeeded for %{public}s\n", hostname);
        return X509_V_OK;
    } else if (result == 0) {
        NETSTACK_LOGE("Hostname verification failed: hostname does not match (expected: %{public}s)\n", hostname);
        return SSL_X509_V_ERR_HOSTNAME_MISMATCH;
    } else if (result == -2) {
        // result == -2: malformed input to X509_check_host
        NETSTACK_LOGE("Hostname verification failed: invalid input to X509_check_host\n");
        return SSL_X509_V_ERR_INVALID_CALL;
    } else {
        // result == -1: internal error in X509_check_host
        NETSTACK_LOGE("Hostname verification failed: X509_check_host internal error\n");
        return SSL_X509_V_ERR_UNSPECIFIED;
    }
}

static CertBlob *X509ToPemCertBlob(X509 *x509, CertBlob *certBlob)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        return nullptr;
    }

    if (PEM_write_bio_X509(bio, x509) != 1) {
        NETSTACK_LOGE("Failed to write X509 to PEM\n");
        BIO_free(bio);
        return nullptr;
    }

    char *pemData = nullptr;
    long pemSize = BIO_get_mem_data(bio, &pemData);
    if (pemSize <= 0 || pemData == nullptr) {
        NETSTACK_LOGE("Failed to get PEM data\n");
        BIO_free(bio);
        return nullptr;
    }

    certBlob->size = static_cast<uint32_t>(pemSize);
    certBlob->data = new (std::nothrow) uint8_t[pemSize + 1];
    if (certBlob->data == nullptr) {
        NETSTACK_LOGE("Failed to allocate PEM data buffer\n");
        BIO_free(bio);
        return nullptr;
    }

    std::copy(pemData, pemData + pemSize, certBlob->data);
    certBlob->data[pemSize] = '\0';
    BIO_free(bio);
    return certBlob;
}

static CertBlob *X509ToDerCertBlob(X509 *x509, CertBlob *certBlob)
{
    int derSize = i2d_X509(x509, nullptr);
    if (derSize <= 0) {
        NETSTACK_LOGE("Failed to get DER size\n");
        return nullptr;
    }

    certBlob->size = static_cast<uint32_t>(derSize);
    certBlob->data = new (std::nothrow) uint8_t[derSize];
    if (certBlob->data == nullptr) {
        NETSTACK_LOGE("Failed to allocate DER data buffer\n");
        return nullptr;
    }

    uint8_t *derData = certBlob->data;
    if (i2d_X509(x509, &derData) <= 0) {
        NETSTACK_LOGE("Failed to convert X509 to DER\n");
        delete[] certBlob->data;
        certBlob->data = nullptr;
        return nullptr;
    }
    return certBlob;
}

CertBlob *X509ToCertBlob(X509 *x509, CertType type)
{
    if (x509 == nullptr) {
        NETSTACK_LOGE("X509 is nullptr\n");
        return nullptr;
    }

    CertBlob *certBlob = new (std::nothrow) CertBlob;
    if (certBlob == nullptr) {
        NETSTACK_LOGE("Failed to allocate CertBlob\n");
        return nullptr;
    }

    certBlob->type = type;

    CertBlob *result = nullptr;
    if (type == CERT_TYPE_PEM) {
        result = X509ToPemCertBlob(x509, certBlob);
    } else {
        result = X509ToDerCertBlob(x509, certBlob);
    }
    if (result == nullptr) {
        delete certBlob;
    }
    return result;
}

static void FreePartialBuiltChain(CertBlob *certChain, int count)
{
    for (int j = 0; j < count; j++) {
        if (certChain[j].data != nullptr) {
            delete[] certChain[j].data;
        }
    }
}

uint32_t BuildSortedChain(X509_STORE_CTX *ctx, CertBlob **outChain, size_t *outCount)
{
    if (ctx == nullptr || outChain == nullptr || outCount == nullptr) {
        NETSTACK_LOGE("Invalid parameters for BuildSortedChain\n");
        return SSL_X509_V_ERR_INVALID_CALL;
    }

    // Get the verified chain from context
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    if (chain == nullptr) {
        NETSTACK_LOGE("Failed to get verified chain\n");
        return SSL_X509_V_ERR_UNSPECIFIED;
    }

    int chainLen = sk_X509_num(chain);
    if (chainLen <= 0) {
        NETSTACK_LOGE("Empty certificate chain\n");
        return SSL_X509_V_ERR_UNSPECIFIED;
    }

    NETSTACK_LOGD("Building sorted chain with %{public}d certificates\n", chainLen);

    // Allocate array for CertBlob chain
    CertBlob *certChain = new (std::nothrow) CertBlob[chainLen];
    if (certChain == nullptr) {
        NETSTACK_LOGE("Failed to allocate cert chain array\n");
        return SSL_X509_V_ERR_OUT_OF_MEMORY_API26;
    }

    // Convert each X509 to CertBlob (chain is already sorted leaf to root)
    for (int i = 0; i < chainLen; i++) {
        X509 *cert = sk_X509_value(chain, i);
        if (cert == nullptr) {
            NETSTACK_LOGE("Certificate at index %{public}d is nullptr\n", i);
            FreePartialBuiltChain(certChain, i);
            delete[] certChain;
            return SSL_X509_V_ERR_UNSPECIFIED;
        }

        CertBlob *blob = X509ToCertBlob(cert, CERT_TYPE_PEM);
        if (blob == nullptr) {
            NETSTACK_LOGE("Failed to convert X509 to CertBlob at index %{public}d\n", i);
            FreePartialBuiltChain(certChain, i);
            delete[] certChain;
            return SSL_X509_V_ERR_UNSPECIFIED;
        }

        certChain[i] = *blob;
        delete blob;
    }

    *outChain = certChain;
    *outCount = static_cast<size_t>(chainLen);

    NETSTACK_LOGD("Successfully built sorted chain with %{public}zu certificates\n", *outCount);
    return X509_V_OK;
}

void FreeCertChain(CertBlob *chain, size_t count)
{
    if (chain == nullptr || count == 0) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (chain[i].data != nullptr) {
            delete[] chain[i].data;
            chain[i].data = nullptr;
        }
    }
    delete[] chain;
}

static STACK_OF(X509) *BuildUntrustedChain(const CertBlob *certs, size_t certCount)
{
    if (certCount <= 1) {
        return nullptr;
    }

    STACK_OF(X509) *chain = sk_X509_new_null();
    if (chain == nullptr) {
        NETSTACK_LOGE("Failed to create untrusted chain\n");
        return nullptr;
    }

    for (size_t i = 1; i < certCount; i++) {
        X509 *cert = CertBlobToX509(&certs[i]);
        if (cert == nullptr) {
            NETSTACK_LOGE("Failed to convert certificate at index %{public}zu\n", i);
            continue;
        }
        sk_X509_push(chain, cert);
    }
    return chain;
}

static bool SetupVerificationStore(X509_STORE *store, const CertBlob *caCert)
{
    if (caCert != nullptr) {
        X509 *caX509 = CertBlobToX509(caCert);
        if (caX509 == nullptr) {
            NETSTACK_LOGE("Failed to convert CA certificate\n");
            return false;
        }
        if (X509_STORE_add_cert(store, caX509) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("Failed to add custom CA to store\n");
            X509_free(caX509);
            return false;
        }
        X509_free(caX509);
    } else {
        std::string userInstalledCaPath = GetUserInstalledCaPath();
        X509_STORE_load_locations(store, nullptr, SslConstant::SYSPRECAPATH);
        X509_STORE_load_locations(store, nullptr, userInstalledCaPath.c_str());
    }
    return true;
}

uint32_t VerifyAndBuildCertChain(
    const CertBlob *certs,
    size_t certCount,
    const CertBlob *caCert,
    const char *hostname,
    CertBlob **outChain,
    size_t *outCount)
{
    if (certs == nullptr || certCount == 0 || outCount == nullptr) {
        NETSTACK_LOGE("Invalid input parameters\n");
        return SSL_X509_V_ERR_INVALID_CALL;
    }

    uint32_t verifyResult = SSL_X509_V_ERR_UNSPECIFIED;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    STACK_OF(X509) *untrustedChain = nullptr;
    X509 *leafCert = nullptr;

    do {
        leafCert = CertBlobToX509(&certs[0]);
        if (leafCert == nullptr) {
            NETSTACK_LOGE("Failed to convert leaf certificate\n");
            break;
        }

        untrustedChain = BuildUntrustedChain(certs, certCount);
        if (certCount > 1 && untrustedChain == nullptr) {
            verifyResult = SSL_X509_V_ERR_OUT_OF_MEMORY_API26;
            break;
        }

        store = X509_STORE_new();
        if (store == nullptr) {
            NETSTACK_LOGE("Failed to create X509 store\n");
            verifyResult = SSL_X509_V_ERR_OUT_OF_MEMORY_API26;
            break;
        }

        if (!SetupVerificationStore(store, caCert)) {
            verifyResult = SSL_X509_V_ERR_INVALID_CA;
            break;
        }

        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            NETSTACK_LOGE("Failed to create X509 store context\n");
            verifyResult = SSL_X509_V_ERR_OUT_OF_MEMORY_API26;
            break;
        }

        if (X509_STORE_CTX_init(ctx, store, leafCert, untrustedChain) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("Failed to initialize X509 store context\n");
            break;
        }

        int result = X509_verify_cert(ctx);
        if (result != VERIFY_RESULT_SUCCESS) {
            verifyResult = static_cast<uint32_t>(X509_STORE_CTX_get_error(ctx) + SSL_ERROR_CODE_BASE);
            NETSTACK_LOGE("Certificate chain verification failed: %{public}s (%{public}d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        }

        NETSTACK_LOGD("Certificate chain verification succeeded\n");

        if (hostname != nullptr && strlen(hostname) > 0) {
            verifyResult = VerifyHostname(leafCert, hostname);
            if (verifyResult != X509_V_OK) {
                NETSTACK_LOGE("Hostname verification failed\n");
                break;
            }
        }

        if (outChain != nullptr) {
            verifyResult = BuildSortedChain(ctx, outChain, outCount);
            if (verifyResult != X509_V_OK) {
                NETSTACK_LOGE("Failed to build sorted chain\n");
                break;
            }
        } else {
            *outCount = 0;
        }

        verifyResult = X509_V_OK;
    } while (false);

    if (leafCert != nullptr) {
        X509_free(leafCert);
    }
    if (untrustedChain != nullptr) {
        sk_X509_pop_free(untrustedChain, X509_free);
    }
    if (store != nullptr) {
        X509_STORE_free(store);
    }
    if (ctx != nullptr) {
        X509_STORE_CTX_free(ctx);
    }

    return verifyResult;
}

} // namespace Ssl
} // namespace NetStack
} // namespace OHOS