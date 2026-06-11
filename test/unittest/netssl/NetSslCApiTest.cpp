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
#include "net_ssl_c.h"
#include "net_ssl_c_type.h"
#include "net_ssl.h"
#include "net_ssl_verify_cert.h"
#include "securec.h"

namespace {

// Hardcoded PEM certificates for test data
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

static const char kInvalidCert[] = "NOT A VALID CERTIFICATE DATA HERE";

class NetSslCApiTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    static NetStack_CertBlob MakeCertBlob(const char *pemStr, NetStack_CertType type = NETSTACK_CERT_TYPE_PEM)
    {
        NetStack_CertBlob blob;
        blob.type = type;
        blob.size = static_cast<uint32_t>(strlen(pemStr));
        blob.data = new uint8_t[blob.size];
        if (memcpy_s(blob.data, blob.size, pemStr, blob.size) != EOK) {
            delete[] blob.data;
            blob.data = nullptr;
            blob.size = 0;
        }
        return blob;
    }

    static void FreeCertBlob(NetStack_CertBlob &blob)
    {
        if (blob.data != nullptr) {
            delete[] blob.data;
            blob.data = nullptr;
        }
    }
};

// ==================== OH_NetStack_CreateAndVerifySortedCertChain tests ====================

// 001: Nullptr input cert
HWTEST_F(NetSslCApiTest, CreateAndVerify_NullInput_001, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(nullptr, 0, nullptr, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, OHOS::NetStack::Ssl::SSL_X509_V_ERR_INVALID_CALL);
}

// 002: Zero cert count
HWTEST_F(NetSslCApiTest, CreateAndVerify_ZeroCount_002, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert;
    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(&cert, 0, nullptr, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, OHOS::NetStack::Ssl::SSL_X509_V_ERR_INVALID_CALL);
}

// 003: Null outCount
HWTEST_F(NetSslCApiTest, CreateAndVerify_NullOutCount_003, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem);
    NetStack_CertBlob *outChain = nullptr;
    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(&cert, 1, nullptr, nullptr, &outChain, nullptr);
    EXPECT_EQ(result, OHOS::NetStack::Ssl::SSL_X509_V_ERR_INVALID_CALL);
    FreeCertBlob(cert);
}

// 004: Invalid certificate data
HWTEST_F(NetSslCApiTest, CreateAndVerify_InvalidCert_004, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert;
    cert.type = NETSTACK_CERT_TYPE_PEM;
    cert.size = static_cast<uint32_t>(strlen(kInvalidCert));
    cert.data = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(kInvalidCert));

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(&cert, 1, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);
    EXPECT_EQ(outCount, 0);
}

// 005: Single self-signed test cert without CA → must fail (not in system trust)
HWTEST_F(NetSslCApiTest, CreateAndVerify_ValidSingleCert_005, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem);
    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(&cert, 1, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);

    FreeCertBlob(cert);
}

// 006: leaf + intermediate + root in chain without CA → self-signed root not trusted
HWTEST_F(NetSslCApiTest, CreateAndVerify_CertChain_006, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[3];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    certs[2] = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 3, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);

    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(certs[2]);
}

// 007: leaf alone + root CA (no intermediate in chain) → should fail
HWTEST_F(NetSslCApiTest, CreateAndVerify_NoIntermediate_007, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(&cert, 1, &caCert, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);

    FreeCertBlob(cert);
    FreeCertBlob(caCert);
}

// 008: leaf + intermediate chain + root CA → should succeed
HWTEST_F(NetSslCApiTest, CreateAndVerify_ChainWithRootCA_008, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);
    EXPECT_NE(outChain, nullptr);

    OH_NetStack_FreeCertChain(outChain, outCount);
    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// 009: full chain + root CA + wrong hostname → HOSTNAME_MISMATCH
HWTEST_F(NetSslCApiTest, CreateAndVerify_WrongHostname_009, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, "wrong.hostname.com",
                                                                   &outChain, &outCount);
    EXPECT_EQ(result, OHOS::NetStack::Ssl::SSL_X509_V_ERR_HOSTNAME_MISMATCH);

    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// 010: full chain + root CA + empty hostname → skip hostname check, succeed
HWTEST_F(NetSslCApiTest, CreateAndVerify_EmptyHostname_010, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, "", &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);

    OH_NetStack_FreeCertChain(outChain, outCount);
    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// 011: full chain + root CA + nullptr outSortedChain → still reports count
HWTEST_F(NetSslCApiTest, CreateAndVerify_NullOutChain_011, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, nullptr, nullptr, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);

    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// 012: full chain + root CA + matching hostname → succeed
HWTEST_F(NetSslCApiTest, CreateAndVerify_MatchingHostname_012, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, "chain.test.com",
                                                                   &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);
    EXPECT_NE(outChain, nullptr);

    OH_NetStack_FreeCertChain(outChain, outCount);
    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// 013: Output chain content validation using deterministic full chain
HWTEST_F(NetSslCApiTest, CreateAndVerify_OutputContent_013, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;

    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);
    EXPECT_NE(outChain, nullptr);

    for (size_t i = 0; i < outCount; i++) {
        EXPECT_GT(outChain[i].size, 0);
        EXPECT_NE(outChain[i].data, nullptr);
    }
    OH_NetStack_FreeCertChain(outChain, outCount);

    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// ==================== OH_NetStack_FreeCertChain tests ====================

// 014: Free null chain (should not crash)
HWTEST_F(NetSslCApiTest, FreeCertChain_Null_014, testing::ext::TestSize.Level1)
{
    OH_NetStack_FreeCertChain(nullptr, 0);
    OH_NetStack_FreeCertChain(nullptr, 10);
    EXPECT_TRUE(true);
}

// 015: Free valid chain
HWTEST_F(NetSslCApiTest, FreeCertChain_Valid_015, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob *chain = new NetStack_CertBlob[2];
    chain[0].type = NETSTACK_CERT_TYPE_PEM;
    chain[0].size = 10;
    chain[0].data = new uint8_t[10];
    chain[1].type = NETSTACK_CERT_TYPE_DER;
    chain[1].size = 20;
    chain[1].data = new uint8_t[20];

    OH_NetStack_FreeCertChain(chain, 2);
    EXPECT_TRUE(true);
}

// 016: Free chain with zero count
HWTEST_F(NetSslCApiTest, FreeCertChain_ZeroCount_016, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob *chain = new NetStack_CertBlob[1];
    chain[0].type = NETSTACK_CERT_TYPE_PEM;
    chain[0].size = 10;
    chain[0].data = new uint8_t[10];

    OH_NetStack_FreeCertChain(chain, 0);
    // chain not freed by API, clean up manually
    delete[] chain[0].data;
    delete[] chain;
}

// 017: Free chain with partial null data
HWTEST_F(NetSslCApiTest, FreeCertChain_PartialNull_017, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob *chain = new NetStack_CertBlob[3];
    chain[0].type = NETSTACK_CERT_TYPE_PEM;
    chain[0].size = 10;
    chain[0].data = new uint8_t[10];
    chain[1].type = NETSTACK_CERT_TYPE_PEM;
    chain[1].size = 0;
    chain[1].data = nullptr;
    chain[2].type = NETSTACK_CERT_TYPE_DER;
    chain[2].size = 20;
    chain[2].data = new uint8_t[20];

    OH_NetStack_FreeCertChain(chain, 3);
    EXPECT_TRUE(true);
}

// ==================== Type conversion test ====================

// 018: Certificate type enum values match
HWTEST_F(NetSslCApiTest, CertTypeConversion_018, testing::ext::TestSize.Level1)
{
    EXPECT_EQ(static_cast<int>(NETSTACK_CERT_TYPE_PEM),
              static_cast<int>(OHOS::NetStack::Ssl::CERT_TYPE_PEM));
    EXPECT_EQ(static_cast<int>(NETSTACK_CERT_TYPE_DER),
              static_cast<int>(OHOS::NetStack::Ssl::CERT_TYPE_DER));
    EXPECT_EQ(static_cast<int>(NETSTACK_CERT_TYPE_INVALID),
              static_cast<int>(OHOS::NetStack::Ssl::CERT_TYPE_MAX));
}

// ==================== Error code tests ====================

// 019: Invalid cert returns non-zero error
HWTEST_F(NetSslCApiTest, CreateAndVerify_ErrorCode_019, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert;
    cert.type = NETSTACK_CERT_TYPE_PEM;
    cert.size = 5;
    cert.data = new uint8_t[5];
    if (memcpy_s(cert.data, 5, "ERROR", 5) != EOK) {
        delete[] cert.data;
        FAIL() << "memcpy_s failed";
        return;
    }

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(&cert, 1, nullptr, nullptr, &outChain, &outCount);
    EXPECT_NE(result, 0);
    EXPECT_EQ(outCount, 0);

    delete[] cert.data;
}

// 020: leaf + intermediate chain + root CA returns success with properly sorted chain
HWTEST_F(NetSslCApiTest, CreateAndVerify_SuccessResult_020, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob certs[2];
    certs[0] = MakeCertBlob(kLeafCertPem);
    certs[1] = MakeCertBlob(kIntermediateCaPem);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem);

    NetStack_CertBlob *outChain = nullptr;
    size_t outCount = 0;
    uint32_t result = OH_NetStack_CreateAndVerifySortedCertChain(certs, 2, &caCert, nullptr, &outChain, &outCount);
    EXPECT_EQ(result, 0);
    EXPECT_GT(outCount, 0);
    EXPECT_NE(outChain, nullptr);

    OH_NetStack_FreeCertChain(outChain, outCount);
    FreeCertBlob(certs[0]);
    FreeCertBlob(certs[1]);
    FreeCertBlob(caCert);
}

// ==================== OH_NetStack_CertVerification ====================

// 021: cert == nullptr → INVALID_CALL
HWTEST_F(NetSslCApiTest, CertVerification_NullCert_021, testing::ext::TestSize.Level1)
{
    uint32_t result = OH_NetStack_CertVerification(nullptr, nullptr);
    EXPECT_EQ(result, static_cast<uint32_t>(X509_V_ERR_INVALID_CALL));
}

// 022: caCert == nullptr → system CA path
HWTEST_F(NetSslCApiTest, CertVerification_NoCa_022, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem, NETSTACK_CERT_TYPE_PEM);
    uint32_t result = OH_NetStack_CertVerification(&cert, nullptr);
    EXPECT_NE(result, 0);
    FreeCertBlob(cert);
}

// 023: caCert != nullptr → designated CA path
HWTEST_F(NetSslCApiTest, CertVerification_WithCa_023, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem, NETSTACK_CERT_TYPE_PEM);
    NetStack_CertBlob caCert = MakeCertBlob(kRootCaPem, NETSTACK_CERT_TYPE_PEM);
    uint32_t result = OH_NetStack_CertVerification(&cert, &caCert);
    EXPECT_NE(result, 0);
    FreeCertBlob(cert);
    FreeCertBlob(caCert);
}

// 024: DER type → SwitchToCertBlob DER branch
HWTEST_F(NetSslCApiTest, CertVerification_DER_024, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem, NETSTACK_CERT_TYPE_DER);
    uint32_t result = OH_NetStack_CertVerification(&cert, nullptr);
    EXPECT_NE(result, 0);
    FreeCertBlob(cert);
}

// 025: INVALID type → SwitchToCertBlob CERT_TYPE_MAX branch
HWTEST_F(NetSslCApiTest, CertVerification_InvalidType_025, testing::ext::TestSize.Level1)
{
    NetStack_CertBlob cert = MakeCertBlob(kLeafCertPem, NETSTACK_CERT_TYPE_INVALID);
    uint32_t result = OH_NetStack_CertVerification(&cert, nullptr);
    EXPECT_NE(result, 0);
    FreeCertBlob(cert);
}

// ==================== OH_Netstack_DestroyCertificatesContent ====================

// 026: certs == nullptr
HWTEST_F(NetSslCApiTest, DestroyCertificatesContent_Null_026, testing::ext::TestSize.Level1)
{
    OH_Netstack_DestroyCertificatesContent(nullptr);
    EXPECT_TRUE(true);
}

// 027: certs->content == nullptr
HWTEST_F(NetSslCApiTest, DestroyCertificatesContent_NullContent_027, testing::ext::TestSize.Level1)
{
    NetStack_Certificates certs;
    certs.content = nullptr;
    certs.length = 0;
    OH_Netstack_DestroyCertificatesContent(&certs);
    EXPECT_TRUE(true);
}

// 028: valid certs → frees and zeros
HWTEST_F(NetSslCApiTest, DestroyCertificatesContent_Valid_028, testing::ext::TestSize.Level1)
{
    NetStack_Certificates certs;
    certs.length = 2;
    certs.content = (char **)malloc(certs.length * sizeof(char *));
    for (size_t i = 0; i < certs.length; i++) {
        certs.content[i] = strdup("test");
    }

    OH_Netstack_DestroyCertificatesContent(&certs);
    EXPECT_EQ(certs.content, nullptr);
    EXPECT_EQ(certs.length, 0);
}

// ==================== IsCleartext / GetPinSet / GetCertificates (null-param guards) ====================

// 029: OH_Netstack_IsCleartextPermitted(nullptr)
HWTEST_F(NetSslCApiTest, IsCleartextPermitted_Null_029, testing::ext::TestSize.Level1)
{
    int32_t result = OH_Netstack_IsCleartextPermitted(nullptr);
    EXPECT_NE(result, 0);
}

// 030: OH_Netstack_IsCleartextPermittedByHostName hostname==nullptr
HWTEST_F(NetSslCApiTest, IsCleartextPermittedByHostName_NullHostname_030, testing::ext::TestSize.Level1)
{
    bool permitted = false;
    int32_t result = OH_Netstack_IsCleartextPermittedByHostName(nullptr, &permitted);
    EXPECT_NE(result, 0);
}

// 031: OH_Netstack_IsCleartextPermittedByHostName permitted==nullptr
HWTEST_F(NetSslCApiTest, IsCleartextPermittedByHostName_NullPermitted_031, testing::ext::TestSize.Level1)
{
    int32_t result = OH_Netstack_IsCleartextPermittedByHostName("example.com", nullptr);
    EXPECT_NE(result, 0);
}

// 032: OH_Netstack_IsCleartextCfgByComponent component==nullptr
HWTEST_F(NetSslCApiTest, IsCleartextCfgByComponent_NullComponent_032, testing::ext::TestSize.Level1)
{
    bool cfg = false;
    int32_t result = OH_Netstack_IsCleartextCfgByComponent(nullptr, &cfg);
    EXPECT_NE(result, 0);
}

// 033: OH_Netstack_IsCleartextCfgByComponent componentCfg==nullptr
HWTEST_F(NetSslCApiTest, IsCleartextCfgByComponent_NullCfg_033, testing::ext::TestSize.Level1)
{
    int32_t result = OH_Netstack_IsCleartextCfgByComponent("component", nullptr);
    EXPECT_NE(result, 0);
}

// 034: OH_NetStack_GetPinSetForHostName hostname==nullptr
HWTEST_F(NetSslCApiTest, GetPinSetForHostName_NullHostname_034, testing::ext::TestSize.Level1)
{
    NetStack_CertificatePinning pin;
    int32_t result = OH_NetStack_GetPinSetForHostName(nullptr, &pin);
    EXPECT_NE(result, 0);
}

// 035: OH_NetStack_GetPinSetForHostName pin==nullptr
HWTEST_F(NetSslCApiTest, GetPinSetForHostName_NullPin_035, testing::ext::TestSize.Level1)
{
    int32_t result = OH_NetStack_GetPinSetForHostName("example.com", nullptr);
    EXPECT_NE(result, 0);
}

// 036: OH_NetStack_GetCertificatesForHostName hostname==nullptr
HWTEST_F(NetSslCApiTest, GetCertificatesForHostName_NullHostname_036, testing::ext::TestSize.Level1)
{
    NetStack_Certificates certs;
    int32_t result = OH_NetStack_GetCertificatesForHostName(nullptr, &certs);
    EXPECT_NE(result, 0);
}

// 037: OH_NetStack_GetCertificatesForHostName certs==nullptr
HWTEST_F(NetSslCApiTest, GetCertificatesForHostName_NullCerts_037, testing::ext::TestSize.Level1)
{
    int32_t result = OH_NetStack_GetCertificatesForHostName("example.com", nullptr);
    EXPECT_NE(result, 0);
}

// 038: OH_NetStack_GetPinSetForHostName valid params → covers lines 90-122
HWTEST_F(NetSslCApiTest, GetPinSetForHostName_Valid_038, testing::ext::TestSize.Level1)
{
    NetStack_CertificatePinning pin;
    memset(&pin, 0, sizeof(pin));
    int32_t result = OH_NetStack_GetPinSetForHostName("localhost", &pin);
    // should succeed with empty pins (no pin configured for localhost)
    EXPECT_EQ(result, 0);
    if (pin.publicKeyHash != nullptr) {
        free(pin.publicKeyHash);
    }
}

// 039: OH_NetStack_GetCertificatesForHostName valid params → covers lines 132-174
HWTEST_F(NetSslCApiTest, GetCertificatesForHostName_Valid_039, testing::ext::TestSize.Level1)
{
    NetStack_Certificates certs;
    int32_t result = OH_NetStack_GetCertificatesForHostName("localhost", &certs);
    // should succeed with empty certs (no trust anchors configured for localhost)
    EXPECT_EQ(result, 0);
    OH_Netstack_DestroyCertificatesContent(&certs);
}

// 040: OH_Netstack_IsCleartextPermitted valid call → covers line 199
HWTEST_F(NetSslCApiTest, IsCleartextPermitted_Valid_040, testing::ext::TestSize.Level1)
{
    bool permitted = false;
    int32_t result = OH_Netstack_IsCleartextPermitted(&permitted);
    EXPECT_EQ(result, 0);
}

// 041: OH_Netstack_IsCleartextPermittedByHostName valid call → covers lines 208-209
HWTEST_F(NetSslCApiTest, IsCleartextPermittedByHostName_Valid_041, testing::ext::TestSize.Level1)
{
    bool permitted = false;
    int32_t result = OH_Netstack_IsCleartextPermittedByHostName("localhost", &permitted);
    EXPECT_EQ(result, 0);
}

// 042: OH_Netstack_IsCleartextCfgByComponent valid call → covers lines 218-219
HWTEST_F(NetSslCApiTest, IsCleartextCfgByComponent_Valid_042, testing::ext::TestSize.Level1)
{
    bool cfg = false;
    int32_t result = OH_Netstack_IsCleartextCfgByComponent("netstack", &cfg);
    EXPECT_EQ(result, 0);
}

} // namespace
