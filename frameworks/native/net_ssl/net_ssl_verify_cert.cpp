/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

void GetEnterpriseCaPath(char *enterpriseCaPath)
{
    constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    NETSTACK_LOGD("uid: %{public}d\n", uid);
    uid /= UID_TRANSFORM_DIVISOR;
    strncat(enterpriseCaPath, std::to_string(uid).c_str(), sizeof(std::to_string(uid)));
    char tail[10] = "/cacerts";
    strncat(enterpriseCaPath, tail, strlen(tail));
    NETSTACK_LOGD("enterpriseCaPath: %{public}s\n", enterpriseCaPath);
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
        return nullptr;
    }

    BIO_free(bio);
    return x509;
}

X509 *DerToX509(const unsigned char *derCert, size_t derSize)
{
    // 创建 BIO 对象并将 DER 数据写入其中
    BIO *bio = BIO_new_mem_buf(derCert, derSize);
    if (bio == nullptr) {
        NETSTACK_LOGE("Failed to create BIO of DER\n");
        return nullptr;
    }

    // 从 BIO 对象中读取 DER 数据并转换为 X509 格式
    X509 *x509 = d2i_X509_bio(bio, nullptr);
    if (x509 == nullptr) {
        NETSTACK_LOGE("Failed to convert DER to X509\n");
        BIO_free(bio);
        return nullptr;
    }

    // 释放 BIO 对象
    BIO_free(bio);

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
                    continue;
                }
                break;
            case CERT_TYPE_DER:
                x509 = DerToX509(cert->data, cert->size);
                if (x509 == nullptr) {
                    NETSTACK_LOGE("x509 of DER cert is nullptr\n");
                    continue;
                }
                break;
            default:
                break;
        }
    } while (false);
    return x509;
}

void ProcessResult(uint32_t &verifyResult)
{
    if (verifyResult != X509_V_OK && verifyResult != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT &&
        verifyResult != X509_V_ERR_UNABLE_TO_GET_CRL && verifyResult != X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE &&
        verifyResult != X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE &&
        verifyResult != X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY &&
        verifyResult != X509_V_ERR_CERT_SIGNATURE_FAILURE && verifyResult != X509_V_ERR_CRL_SIGNATURE_FAILURE &&
        verifyResult != X509_V_ERR_CERT_NOT_YET_VALID && verifyResult != X509_V_ERR_CERT_HAS_EXPIRED &&
        verifyResult != X509_V_ERR_CRL_NOT_YET_VALID && verifyResult != X509_V_ERR_CRL_HAS_EXPIRED &&
        verifyResult != X509_V_ERR_CERT_REVOKED && verifyResult != X509_V_ERR_INVALID_CA &&
        verifyResult != X509_V_ERR_CERT_UNTRUSTED) {
        verifyResult = X509_V_ERR_UNSPECIFIED;
    }
}

uint32_t VerifyCert(const CertBlob *cert)
{
    uint32_t verifyResult = X509_V_ERR_UNSPECIFIED;
    X509 *certX509 = nullptr;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    do {
        // 将证书数据转为X509
        certX509 = CertBlobToX509(cert);
        if (certX509 == nullptr) {
            NETSTACK_LOGE("x509 of cert is nullptr\n");
            continue;
        }
        // 创建 X509_STORE 对象，加载 CA 证书
        store = X509_STORE_new();
        if (store == nullptr) {
            continue;
        }
        const char *caCertPath[2] = {"/etc/security/certificates", "/user/0/cacerts"};
        char enterpriseCaPath[1024] = "/user/";
        GetEnterpriseCaPath(enterpriseCaPath);
        if (X509_STORE_load_locations(store, nullptr, caCertPath[0]) != VERIFY_RESULT_SUCCESS &&
            X509_STORE_load_locations(store, nullptr, caCertPath[1]) != VERIFY_RESULT_SUCCESS &&
            X509_STORE_load_locations(store, nullptr, enterpriseCaPath) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("load store failed\n");
            continue;
        }
        // 创建 X509_STORE_CTX 对象，初始化
        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            continue;
        }
        X509_STORE_CTX_init(ctx, store, certX509, nullptr);
        // 进行校验证操作
        verifyResult = X509_verify_cert(ctx);
        if (verifyResult != X509_V_OK) {
            // 验证失败，可以通过 X509_STORE_CTX_get_error() 获取具体错误代码
            verifyResult = X509_STORE_CTX_get_error(ctx);
            ProcessResult(verifyResult);
            NETSTACK_LOGE("failed to verify certificate: %s (%d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        }
        NETSTACK_LOGI("certificate validation succeeded.\n");
    } while (false);

    FreeResources(certX509, nullptr, store, ctx);
    return verifyResult;
}

uint32_t VerifyCert(const CertBlob *cert, const CertBlob *caCert)
{
    uint32_t verifyResult = X509_V_ERR_UNSPECIFIED;
    X509 *certX509 = nullptr;
    X509 *caX509 = nullptr;
    X509_STORE *store = nullptr;
    X509_STORE_CTX *ctx = nullptr;
    do {
        certX509 = CertBlobToX509(cert);
        if (certX509 == nullptr) {
            NETSTACK_LOGE("x509 of cert is nullptr\n");
            continue;
        }
        caX509 = CertBlobToX509(caCert);
        if (caX509 == nullptr) {
            NETSTACK_LOGE("x509 of ca is nullptr\n");
            continue;
        }
        store = X509_STORE_new();
        if (store == nullptr) {
            continue;
        }
        if (X509_STORE_add_cert(store, caX509) != VERIFY_RESULT_SUCCESS) {
            NETSTACK_LOGE("add ca to store failed\n");
            continue;
        }
        ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            continue;
        }
        X509_STORE_CTX_init(ctx, store, certX509, nullptr);
        // 进行校验证操作
        verifyResult = X509_verify_cert(ctx);
        if (verifyResult != X509_V_OK) {
            // 验证失败，可以通过 X509_STORE_CTX_get_error() 获取具体错误代码
            verifyResult = X509_STORE_CTX_get_error(ctx);
            ProcessResult(verifyResult);
            NETSTACK_LOGE("failed to verify certificate: %s (%d)\n",
                          X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), verifyResult);
            break;
        }
        NETSTACK_LOGI("certificate validation succeeded.\n");
    } while (false);

    FreeResources(certX509, caX509, store, ctx);
    return verifyResult;
}

void FreeResources(X509 *certX509, X509 *caX509, X509_STORE *store, X509_STORE_CTX *ctx)
{
    if (certX509 != nullptr) {
        X509_free(certX509);
    }
    if (caX509 != nullptr) {
        X509_free(caX509);
    }
    if (store != nullptr) {
        X509_STORE_free(store);
    }
    if (ctx != nullptr) {
        X509_STORE_CTX_free(ctx);
    }
}
