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

#include <cstring>
#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "net_ssl.h"
#include "net_ssl_verify_cert.h"
#include "verify_cert_chain_context.h"
#include "net_ssl_exec.h"
#include "netstack_log.h"
#include "securec.h"

namespace OHOS::NetStack::Ssl {
namespace {

// Hardcoded certificate PEM strings for testing
// Leaf certificate: CN=chain.test.com, issued by Intermediate CA
static const char kLeafCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDljCCAn6gAwIBAgIUcqRJ9L2iCvP+74gmQQe8VnLZFFswDQYJKoZIhvcNAQEL\n"
    "BQAwZDELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl\n"
    "aWppbmcxFzAVBgNVBAoMDkludGVybWVkaWF0ZUNBMRgwFgYDVQQDDA9JbnRlcm1l\n"
    "ZGlhdGUgQ0EwHhcNMjYwNTI2MTE1NzA0WhcNMjcwNTI2MTE1NzA0WjBvMQswCQYD\n"
    "VQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzEQMA4G\n"
    "A1UECgwHVGVzdE9yZzERMA8GA1UECwwIVGVzdFVuaXQxFzAVBgNVBAMMDmNoYWlu\n"
    "LnRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtlcGNsu2\n"
    "1EpawvSjhDlWjAGTz2IC+Oow40vCOU7QnQ9Xy5T5CUk2FwQ5fgqV/egBc1KbfQPF\n"
    "kvzoUBRxzQ/YcDXTuPe6OSUylTpQD0FfpW8YexmH1HE+p9G09ygHl7XSmNkTQPSl\n"
    "NdtabL9vVx4ZNtXcodhSmm5O46BskPxS5pU4Vwt+rPTjy69F1hBd0ckPzFGVhMY7\n"
    "9VKltpg6jJ5P1A122c4gGdqbbIimgMBizUStynucAY8bzOEkCljOtdJ4pbpcnCzT\n"
    "TLz4L8Z+OEuWFOQBm0y5JuPwKhl7H157HbYEZdGAjSl+8zseZOahtB6z6XxKN+Of\n"
    "OHgctuA3b2tY7wIDAQABozUwMzAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDAZBgNV\n"
    "HREEEjAQgg5jaGFpbi50ZXN0LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAnpFpHEBg\n"
    "rvBS+DULXl8HVmQWJijc35zjq4woM9rnDhSRFK/2YXa8eVPvA5ofEHDrZTYZ82bh\n"
    "IGJS74KaM9fjlFmPkrl0+E/oqmRKeaFpQqorC3SBbP+Fjx3zeccPGxby/HGg4UkE\n"
    "lTC9NrleAHB9LiQAq5tEocT7Kn5+S1uXnip95+J3ulA5aI03K0ezd5ooyG0YTxRS\n"
    "AxaJYPPakGnf0jHnEad3ksIeA1B3W4sVy/UzXwWCUKBR38uuZi3t4bkCldoW5N6V\n"
    "3eCeTmI7ymVPVbfwWgWkpHvRrfzsHAgQGtMqFtwTZcEsAC+S4M3AQi97S9sirc9s\n"
    "Sfj9LgSSKb+QSA==\n"
    "-----END CERTIFICATE-----";

// Intermediate CA certificate
static const char kIntermediateCaPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDYzCCAkugAwIBAgIUOtdY6soXDHPVb3ohGVgTkcPSP5IwDQYJKoZIhvcNAQEL\n"
    "BQAwVDELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl\n"
    "aWppbmcxDzANBgNVBAoMBlJvb3RDQTEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yNjA1\n"
    "MjYxMTU2NTJaFw0zMTA1MjUxMTU2NTJaMGQxCzAJBgNVBAYTAkNOMRAwDgYDVQQI\n"
    "DAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRcwFQYDVQQKDA5JbnRlcm1lZGlh\n"
    "dGVDQTEYMBYGA1UEAwwPSW50ZXJtZWRpYXRlIENBMIIBIjANBgkqhkiG9w0BAQEF\n"
    "AAOCAQ8AMIIBCgKCAQEA6P0Cq7obBIGpDEsm0YqvjjqDDX8mGkhD+ivIrmJw6zxP\n"
    "s4paOA03KsBHf0o4IyQZAJJoyHBnJXMN+mMSpy/3OLzpHnNJp6KZi14AF7nRcb9x\n"
    "++AFGeTp6twIHDzgSesSgKSPfHi3A/3uawZb7NQOvvfRNXt12ynDxK3HdMJdpeZV\n"
    "2tSEG/wUzApEwXCG2Tho8Ey9hC5SMOpLwALJkASykqR8HRVONv1+S4pk12dq9xwS\n"
    "7md+GfiX+Y0lUd5HJfEvnIls4ZAf8yfgijIILyxMgK5R0YAZgWNFK5fUqibi7GJD\n"
    "yDaPFolWweSFiir6A93LNc5k8uGtC0QAOEYya9OTqQIDAQABox0wGzAMBgNVHRME\n"
    "BTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEANvoBZgcp23G3\n"
    "3bHAMqqIi17k34zC8ccapKwNFw4hjuTHhDH/aDhJny8ldAWmUiZSePw2Y24CC1nC\n"
    "RxLG7j3eSCHdAOaBf9FkwodVscg/B5iFbSPXMffb8A6SOmtF9Oy2UAha7zBFtKXH\n"
    "MR6F/Q917/rn4G4oAIwDFByB/I1FrRC3DQv5dVHnlo8E/8/WAqqzbKhhznQG8EA5\n"
    "wwRCmHkizjInElVj17iMaET751hGH4tKs1EyI4b5+0I6efuzYbJmIw/uR92rx2HC\n"
    "gN8UNAlM8ugtsOzA44ZXddYX5hQtEETjOJbkZbpqkyAE6Rg79C0QfN1KEHmrA/7N\n"
    "6sRQ2OdlZA==\n"
    "-----END CERTIFICATE-----";

// Root CA certificate (self-signed)
static const char kRootCaPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDUzCCAjugAwIBAgIUanZKy7n+qiQMKX8CkKM4F+JynvAwDQYJKoZIhvcNAQEL\n"
    "BQAwVDELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl\n"
    "aWppbmcxDzANBgNVBAoMBlJvb3RDQTEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yNjA1\n"
    "MjYxMTU2MzNaFw0zNjA1MjMxMTU2MzNaMFQxCzAJBgNVBAYTAkNOMRAwDgYDVQQI\n"
    "DAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMQ8wDQYDVQQKDAZSb290Q0ExEDAO\n"
    "BgNVBAMMB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDi\n"
    "0ytu5sX83b586aRsFtYSEW3h80uJHnx7b5eWMkH5iliODZ310PayyNeGYvoWfhLk\n"
    "5T9lvsS/vWhgIfOcqHh2i0/vPLrpITyVGb+f2+77nNOCVJkZ9OTRUhmWh5V+pq9y\n"
    "JRDO1ZfoNP2n5wR1LbJo64BcnlFxPLFVLZNFbtDJFlcdufUhQqIf5yQ9hKEesHvO\n"
    "ka9hd8q05Oy7NHjwBMIXSeCH+XyhIMUS6+ng9MN2Y4vK9EvsqpFndiAdBqfGkFMY\n"
    "ZEPJaAsR+wTJKg7H4iggImQ7ayjvQ7Hb2jELpqXy+nc2x3uE3ZnJZS3ONTKJYnqM\n"
    "sHMIgcLJ1ybykwHXLTt3AgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQD\n"
    "AgEGMA0GCSqGSIb3DQEBCwUAA4IBAQDezzkyzFIfxZ5dmUPvyrN3HVyBJKRPAnQn\n"
    "tod/Bqt/mRoXzKoy5iKI5NspTPpxeloSlzGptKK9wP94+1WeVMRpdnESLEenv5J2\n"
    "bl7H7Rb9n21v8/SWmWubTae0K2PM59HQCLwA0Tqi3ZDANIkJ4ZciYYXZMQcoJRI9\n"
    "4vNDkQHLbkOTLZGiAEZ1Vqsg4rf7KJXiM2QTzc+yciKXGwtnveoW1XHZL23bg5tu\n"
    "lK2hczfKuewUZnuqD1BFLAL7qVwFbFtBcjk+bYJTaVL7vE8w5bb15/EL913TK/BU\n"
    "S8rsW3WnkKWMUECl7xUxhxAp3Zoi53fiz89NS477FBwkDx9mqg1Z\n"
    "-----END CERTIFICATE-----";

// Invalid certificate data (not a real cert)
static const char kInvalidCertData[] = "NOT A VALID CERTIFICATE";

class VerifyCertChainTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    static CertBlob *CreateCertBlobFromPem(const char *pemStr, CertType type)
    {
        CertBlob *blob = new CertBlob;
        blob->type = type;
        blob->size = static_cast<uint32_t>(strlen(pemStr));
        blob->data = new uint8_t[blob->size];
        if (memcpy_s(blob->data, blob->size, pemStr, blob->size) != EOK) {
            delete[] blob->data;
            delete blob;
            return nullptr;
        }
        return blob;
    }

    static CertBlob *CreateCertBlobFromPemDer(const char *pemStr)
    {
        CertBlob *pemBlob = CreateCertBlobFromPem(pemStr, CERT_TYPE_PEM);
        if (pemBlob == nullptr) {
            return nullptr;
        }
        X509 *x509 = CertBlobToX509(pemBlob);
        if (x509 == nullptr) {
            delete[] pemBlob->data;
            delete pemBlob;
            return nullptr;
        }
        CertBlob *derBlob = X509ToCertBlob(x509, CERT_TYPE_DER);
        X509_free(x509);
        delete[] pemBlob->data;
        delete pemBlob;
        return derBlob;
    }

    static void FreeCertBlob(CertBlob *blob)
    {
        if (blob != nullptr) {
            if (blob->data != nullptr) {
                delete[] blob->data;
            }
            delete blob;
        }
    }
};

// ==================== VerifyAndBuildCertChain tests ====================

// 001: Null input parameters
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_NullInput_001, testing::ext::TestSize.Level1)
{
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(nullptr, 0, nullptr, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, SSL_X509_V_ERR_INVALID_CALL);
}

// 002: Zero certificate count
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_ZeroCount_002, testing::ext::TestSize.Level1)
{
    CertBlob cert;
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(&cert, 0, nullptr, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, SSL_X509_V_ERR_INVALID_CALL);
}

// 003: Invalid certificate data (malformed cert)
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_InvalidCert_003, testing::ext::TestSize.Level1)
{
    CertBlob cert;
    cert.type = CERT_TYPE_PEM;
    cert.size = static_cast<uint32_t>(strlen(kInvalidCertData));
    cert.data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(kInvalidCertData));

    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(&cert, 1, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);
}

// 004: Single self-signed test cert without CA → must fail (not in system trust)
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_ValidSingleCert_004, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);

    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(leafCert, 1, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);

    FreeCertBlob(leafCert);
}

// 005: leaf + intermediate + root in chain, no custom CA → self-signed root not trusted
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_CertChain_005, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    CertBlob *intermediateCert = CreateCertBlobFromPem(kIntermediateCaPem, CERT_TYPE_PEM);
    CertBlob *rootCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    CertBlob certs[3] = {*leafCert, *intermediateCert, *rootCert};
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(certs, 3, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);

    FreeCertBlob(leafCert);
    FreeCertBlob(intermediateCert);
    FreeCertBlob(rootCert);
}

// 006: leaf + rootCA but missing intermediate → chain incomplete, must fail
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_WithCA_006, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    CertBlob *caCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);
    ASSERT_NE(caCert, nullptr);

    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(leafCert, 1, caCert, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);

    FreeCertBlob(leafCert);
    FreeCertBlob(caCert);
}

// 007: full chain + root CA + matching hostname → succeed
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_WithHostname_007, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    CertBlob *intermediateCert = CreateCertBlobFromPem(kIntermediateCaPem, CERT_TYPE_PEM);
    CertBlob *caCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(caCert, nullptr);

    CertBlob certs[2] = {*leafCert, *intermediateCert};
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(certs, 2, caCert, "chain.test.com", &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);
    EXPECT_NE(outChain, nullptr);

    FreeCertChain(outChain, outCount);
    FreeCertBlob(leafCert);
    FreeCertBlob(intermediateCert);
    FreeCertBlob(caCert);
}

// 008: full chain + root CA + wrong hostname → HOSTNAME_MISMATCH
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_HostnameMismatch_008, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    CertBlob *intermediateCert = CreateCertBlobFromPem(kIntermediateCaPem, CERT_TYPE_PEM);
    CertBlob *caCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(caCert, nullptr);

    CertBlob certs[2] = {*leafCert, *intermediateCert};
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(certs, 2, caCert, "wrong.hostname.com", &outChain, &outCount);
    EXPECT_EQ(result, SSL_X509_V_ERR_HOSTNAME_MISMATCH);

    FreeCertBlob(leafCert);
    FreeCertBlob(intermediateCert);
    FreeCertBlob(caCert);
}

// 009: full chain + root CA + empty hostname → skip hostname check, succeed
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_EmptyHostname_009, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    CertBlob *intermediateCert = CreateCertBlobFromPem(kIntermediateCaPem, CERT_TYPE_PEM);
    CertBlob *caCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(caCert, nullptr);

    CertBlob certs[2] = {*leafCert, *intermediateCert};
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(certs, 2, caCert, "", &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);

    FreeCertChain(outChain, outCount);
    FreeCertBlob(leafCert);
    FreeCertBlob(intermediateCert);
    FreeCertBlob(caCert);
}

// 010: full chain + root CA + nullptr outChain → verify only, outCount == 0
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_NoOutputChain_010, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    CertBlob *intermediateCert = CreateCertBlobFromPem(kIntermediateCaPem, CERT_TYPE_PEM);
    CertBlob *caCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(caCert, nullptr);

    CertBlob certs[2] = {*leafCert, *intermediateCert};
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(certs, 2, caCert, nullptr, nullptr, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(outCount, 0);

    FreeCertBlob(leafCert);
    FreeCertBlob(intermediateCert);
    FreeCertBlob(caCert);
}

// 011: DER leaf + PEM intermediate + root CA → succeed with mixed encoding
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_DERFormat_011, testing::ext::TestSize.Level1)
{
    CertBlob *derLeaf = CreateCertBlobFromPemDer(kLeafCertPem);
    CertBlob *intermediateCert = CreateCertBlobFromPem(kIntermediateCaPem, CERT_TYPE_PEM);
    CertBlob *caCert = CreateCertBlobFromPem(kRootCaPem, CERT_TYPE_PEM);
    if (derLeaf == nullptr) {
        GTEST_SKIP() << "Failed to create DER certificate";
    }
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(caCert, nullptr);

    CertBlob certs[2] = {*derLeaf, *intermediateCert};
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = VerifyAndBuildCertChain(certs, 2, caCert, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);

    FreeCertChain(outChain, outCount);
    FreeCertBlob(derLeaf);
    FreeCertBlob(intermediateCert);
    FreeCertBlob(caCert);
}

// ==================== VerifyHostname tests ====================

// 012: Nullptr certificate
HWTEST_F(VerifyCertChainTest, VerifyHostname_NullCert_012, testing::ext::TestSize.Level1)
{
    uint32_t result = VerifyHostname(nullptr, "example.com");
    EXPECT_EQ(result, SSL_X509_V_ERR_HOSTNAME_MISMATCH);
}

// 013: Nullptr hostname
HWTEST_F(VerifyCertChainTest, VerifyHostname_NullHostname_013, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);

    X509 *x509 = CertBlobToX509(leafCert);
    ASSERT_NE(x509, nullptr);

    uint32_t result = VerifyHostname(x509, nullptr);
    EXPECT_EQ(result, SSL_X509_V_ERR_HOSTNAME_MISMATCH);

    X509_free(x509);
    FreeCertBlob(leafCert);
}

// 014: Empty hostname
HWTEST_F(VerifyCertChainTest, VerifyHostname_EmptyHostname_014, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);

    X509 *x509 = CertBlobToX509(leafCert);
    ASSERT_NE(x509, nullptr);

    uint32_t result = VerifyHostname(x509, "");
    EXPECT_EQ(result, SSL_X509_V_ERR_HOSTNAME_MISMATCH);

    X509_free(x509);
    FreeCertBlob(leafCert);
}

// 015: Matching hostname
HWTEST_F(VerifyCertChainTest, VerifyHostname_Matching_015, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);

    X509 *x509 = CertBlobToX509(leafCert);
    ASSERT_NE(x509, nullptr);

    const char *hostname = "chain.test.com";
    uint32_t result = VerifyHostname(x509, hostname);
    // Should match — leaf cert has SAN DNS:chain.test.com
    EXPECT_EQ(result, X509_V_OK);

    X509_free(x509);
    FreeCertBlob(leafCert);
}

// ==================== BuildSortedChain tests ====================

// 016: Null context
HWTEST_F(VerifyCertChainTest, BuildSortedChain_NullContext_016, testing::ext::TestSize.Level1)
{
    CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = BuildSortedChain(nullptr, &outChain, &outCount);
    EXPECT_EQ(result, SSL_X509_V_ERR_INVALID_CALL);
}

// 017: Null output parameters
HWTEST_F(VerifyCertChainTest, BuildSortedChain_NullOutput_017, testing::ext::TestSize.Level1)
{
    uint32_t result = BuildSortedChain(nullptr, nullptr, nullptr);
    EXPECT_EQ(result, SSL_X509_V_ERR_INVALID_CALL);
}

// ==================== X509ToCertBlob tests ====================

// 018: Null X509
HWTEST_F(VerifyCertChainTest, X509ToCertBlob_NullX509_018, testing::ext::TestSize.Level1)
{
    CertBlob *blob = X509ToCertBlob(nullptr, CERT_TYPE_PEM);
    EXPECT_EQ(blob, nullptr);
}

// 019: PEM conversion
HWTEST_F(VerifyCertChainTest, X509ToCertBlob_PEM_019, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);

    X509 *x509 = CertBlobToX509(leafCert);
    ASSERT_NE(x509, nullptr);

    CertBlob *blob = X509ToCertBlob(x509, CERT_TYPE_PEM);
    ASSERT_NE(blob, nullptr);
    EXPECT_EQ(blob->type, CERT_TYPE_PEM);
    EXPECT_GT(blob->size, 0);
    EXPECT_NE(blob->data, nullptr);

    FreeCertBlob(blob);
    X509_free(x509);
    FreeCertBlob(leafCert);
}

// 020: DER conversion
HWTEST_F(VerifyCertChainTest, X509ToCertBlob_DER_020, testing::ext::TestSize.Level1)
{
    CertBlob *leafCert = CreateCertBlobFromPem(kLeafCertPem, CERT_TYPE_PEM);
    ASSERT_NE(leafCert, nullptr);

    X509 *x509 = CertBlobToX509(leafCert);
    ASSERT_NE(x509, nullptr);

    CertBlob *blob = X509ToCertBlob(x509, CERT_TYPE_DER);
    ASSERT_NE(blob, nullptr);
    EXPECT_EQ(blob->type, CERT_TYPE_DER);
    EXPECT_GT(blob->size, 0);
    EXPECT_NE(blob->data, nullptr);

    FreeCertBlob(blob);
    X509_free(x509);
    FreeCertBlob(leafCert);
}

// ==================== FreeCertChain tests ====================

// 021: Null chain (should not crash)
HWTEST_F(VerifyCertChainTest, FreeCertChain_Null_021, testing::ext::TestSize.Level1)
{
    FreeCertChain(nullptr, 0);
    FreeCertChain(nullptr, 10);
    EXPECT_TRUE(true);
}

// 022: Valid chain
HWTEST_F(VerifyCertChainTest, FreeCertChain_ValidChain_022, testing::ext::TestSize.Level1)
{
    CertBlob *chain = new CertBlob[2];
    chain[0].type = CERT_TYPE_PEM;
    chain[0].size = 10;
    chain[0].data = new uint8_t[10];

    chain[1].type = CERT_TYPE_DER;
    chain[1].size = 20;
    chain[1].data = new uint8_t[20];

    FreeCertChain(chain, 2);
    EXPECT_TRUE(true);
}

// ==================== SslExec tests ====================

// 023: ExecVerifyCertChain with PARSE_ERROR context → return false
HWTEST_F(VerifyCertChainTest, ExecVerifyCertChain_ParseError_023, testing::ext::TestSize.Level1)
{
    auto manager = std::make_shared<EventManager>();
    VerifyCertChainContext context(nullptr, manager);
    context.SetErrorCode(PARSE_ERROR_CODE);

    bool result = SslExec::ExecVerifyCertChain(&context);
    EXPECT_EQ(result, false);
}

// 024: ExecVerifyCertChain with empty certs → return false
HWTEST_F(VerifyCertChainTest, ExecVerifyCertChain_EmptyCerts_024, testing::ext::TestSize.Level1)
{
    auto manager = std::make_shared<EventManager>();
    VerifyCertChainContext context(nullptr, manager);

    bool result = SslExec::ExecVerifyCertChain(&context);
    EXPECT_EQ(result, false);
}

// 025: VerifyCertChainCallback with error context → return nullptr
HWTEST_F(VerifyCertChainTest, VerifyCertChainCallback_Error_025, testing::ext::TestSize.Level1)
{
    auto manager = std::make_shared<EventManager>();
    VerifyCertChainContext context(nullptr, manager);
    context.SetErrorCode(SSL_X509_V_ERR_CERT_HAS_EXPIRED);

    napi_value result = SslExec::VerifyCertChainCallback(&context);
    EXPECT_EQ(result, nullptr);
}

// ==================== Error code tests ====================

// 026: All defined error codes are non-zero (except success)
HWTEST_F(VerifyCertChainTest, ErrorCodeDefinitions_028, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(SSL_NONE_ERR, 0);
    EXPECT_NE(SSL_X509_V_ERR_UNSPECIFIED, 0);
    EXPECT_NE(SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, 0);
    EXPECT_NE(SSL_X509_V_ERR_CERT_HAS_EXPIRED, 0);
    EXPECT_NE(SSL_X509_V_ERR_CERT_UNTRUSTED, 0);
    EXPECT_NE(SSL_X509_V_ERR_HOSTNAME_MISMATCH, 0);
    EXPECT_NE(SSL_X509_V_ERR_INVALID_CALL, 0);
    EXPECT_NE(SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, 0);
    EXPECT_NE(SSL_X509_V_ERR_CERT_REVOKED, 0);
    EXPECT_NE(SSL_X509_V_ERR_INVALID_CA, 0);
}

// 029: null outCount
HWTEST_F(VerifyCertChainTest, VerifyAndBuildCertChain_NullOutCount_029, testing::ext::TestSize.Level1)
{
    CertBlob cert;
    uint32_t result = VerifyAndBuildCertChain(&cert, 1, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(result, SSL_X509_V_ERR_INVALID_CALL);
}

} // namespace
} // namespace OHOS::NetStack::Ssl
