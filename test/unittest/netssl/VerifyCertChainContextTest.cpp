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

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "verify_cert_chain_context.h"
#include "net_ssl.h"
#include "securec.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Ssl {
namespace {

class VerifyCertChainContextTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

// ==================== Constructor & Destructor tests ====================

// 001: Constructor initializes all members to default
HWTEST_F(VerifyCertChainContextTest, Constructor_001, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    EXPECT_EQ(context.GetInputCerts(), nullptr);
    EXPECT_EQ(context.GetInputCertCount(), 0);
    EXPECT_EQ(context.GetCaCert(), nullptr);
    EXPECT_EQ(context.GetHostname(), nullptr);
    EXPECT_EQ(context.GetSortedChain(), nullptr);
    EXPECT_EQ(context.GetSortedChainCount(), 0);
}

// 002: Destructor called without crash (no allocated data)
HWTEST_F(VerifyCertChainContextTest, Destructor_NoLeak_002, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    {
        VerifyCertChainContext context(env, manager);
    }
    EXPECT_TRUE(true);
}

// ==================== GetErrorCode tests ====================

// 003: GetErrorCode returns PARSE_ERROR_CODE when parse error occurred
HWTEST_F(VerifyCertChainContextTest, GetErrorCode_ParseError_003, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(PARSE_ERROR_CODE);
    EXPECT_EQ(context.GetErrorCode(), PARSE_ERROR_CODE);
}

// 004: GetErrorCode returns specified SSL error code
HWTEST_F(VerifyCertChainContextTest, GetErrorCode_SSLError_004, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(SSL_X509_V_ERR_CERT_HAS_EXPIRED);
    EXPECT_EQ(context.GetErrorCode(), SSL_X509_V_ERR_CERT_HAS_EXPIRED);
}

// 005: GetErrorCode maps unknown error to UNSPECIFIED
HWTEST_F(VerifyCertChainContextTest, GetErrorCode_Unspecified_005, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(999999);
    EXPECT_EQ(context.GetErrorCode(), SSL_X509_V_ERR_UNSPECIFIED);
}

// 006: GetErrorCode with success (0)
HWTEST_F(VerifyCertChainContextTest, GetErrorCode_Success_006, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(0);
    EXPECT_EQ(context.GetErrorCode(), 0);
}

// ==================== GetErrorMessage tests ====================

// 007: GetErrorMessage returns PARSE_ERROR_MSG for parse error
HWTEST_F(VerifyCertChainContextTest, GetErrorMessage_ParseError_007, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(PARSE_ERROR_CODE);
    std::string msg = context.GetErrorMessage();
    EXPECT_EQ(msg, PARSE_ERROR_MSG);
}

// 008: GetErrorMessage returns correct text for known error
HWTEST_F(VerifyCertChainContextTest, GetErrorMessage_KnownError_008, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(SSL_X509_V_ERR_CERT_HAS_EXPIRED);
    std::string msg = context.GetErrorMessage();
    EXPECT_FALSE(msg.empty());

    std::string lowerMsg = msg;
    std::transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);
    EXPECT_NE(lowerMsg.find("expired"), std::string::npos);
}

// 009: GetErrorMessage returns hostname mismatch text
HWTEST_F(VerifyCertChainContextTest, GetErrorMessage_HostnameMismatch_009, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(SSL_X509_V_ERR_HOSTNAME_MISMATCH);
    std::string msg = context.GetErrorMessage();
    EXPECT_FALSE(msg.empty());

    std::string lowerMsg = msg;
    std::transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);
    EXPECT_NE(lowerMsg.find("hostname"), std::string::npos);
}

// 010: GetErrorMessage falls back for unknown error
HWTEST_F(VerifyCertChainContextTest, GetErrorMessage_Fallback_010, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(999999);
    std::string msg = context.GetErrorMessage();
    EXPECT_FALSE(msg.empty());
}

// 011: All defined error codes return non-empty messages
HWTEST_F(VerifyCertChainContextTest, AllErrorMessages_NonEmpty_011, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;

    std::vector<int32_t> errorCodes = {
        SSL_NONE_ERR,
        SSL_X509_V_ERR_UNSPECIFIED,
        SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        SSL_X509_V_ERR_UNABLE_TO_GET_CRL,
        SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
        SSL_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
        SSL_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
        SSL_X509_V_ERR_CERT_SIGNATURE_FAILURE,
        SSL_X509_V_ERR_CRL_SIGNATURE_FAILURE,
        SSL_X509_V_ERR_CERT_NOT_YET_VALID,
        SSL_X509_V_ERR_CERT_HAS_EXPIRED,
        SSL_X509_V_ERR_CRL_NOT_YET_VALID,
        SSL_X509_V_ERR_CRL_HAS_EXPIRED,
        SSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        SSL_X509_V_ERR_CERT_REVOKED,
        SSL_X509_V_ERR_INVALID_CA,
        SSL_X509_V_ERR_CERT_UNTRUSTED,
        SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        SSL_X509_V_ERR_INVALID_CALL,
        SSL_X509_V_ERR_HOSTNAME_MISMATCH
    };

    for (int32_t errorCode : errorCodes) {
        VerifyCertChainContext context(env, manager);
        context.SetErrorCode(errorCode);
        std::string msg = context.GetErrorMessage();
        EXPECT_FALSE(msg.empty()) << "Error code " << errorCode << " has empty message";
    }
}

// ==================== SetSortedChain / GetSortedChain tests ====================

// 012: Set and retrieve sorted chain
HWTEST_F(VerifyCertChainContextTest, SetGetSortedChain_012, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    CertBlob *chain = new CertBlob[2];
    chain[0].type = CERT_TYPE_PEM;
    chain[0].size = 100;
    chain[0].data = new uint8_t[100];
    if (memset_s(chain[0].data, 100, 0xAA, 100) != EOK) {
        delete[] chain[0].data;
        delete[] chain;
        FAIL() << "memset_s failed";
        return;
    }

    chain[1].type = CERT_TYPE_DER;
    chain[1].size = 200;
    chain[1].data = new uint8_t[200];
    if (memset_s(chain[1].data, 200, 0xBB, 200) != EOK) {
        delete[] chain[0].data;
        delete[] chain[1].data;
        delete[] chain;
        FAIL() << "memset_s failed";
        return;
    }

    context.SetSortedChain(chain, 2);
    EXPECT_EQ(context.GetSortedChain(), chain);
    EXPECT_EQ(context.GetSortedChainCount(), 2);
}

// 013: Set nullptr sorted chain
HWTEST_F(VerifyCertChainContextTest, SetSortedChain_Null_013, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetSortedChain(nullptr, 0);
    EXPECT_EQ(context.GetSortedChain(), nullptr);
    EXPECT_EQ(context.GetSortedChainCount(), 0);
}

// 014: Set large chain count
HWTEST_F(VerifyCertChainContextTest, SetSortedChain_LargeCount_014, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    const size_t count = 50;
    CertBlob *chain = new CertBlob[count];
    for (size_t i = 0; i < count; i++) {
        chain[i].type = CERT_TYPE_PEM;
        chain[i].size = 10;
        chain[i].data = new uint8_t[10];
    }

    context.SetSortedChain(chain, count);
    EXPECT_EQ(context.GetSortedChainCount(), count);
}

// 015: Set zero-sized certificiate in chain
HWTEST_F(VerifyCertChainContextTest, SetSortedChain_ZeroSized_015, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    CertBlob *chain = new CertBlob[1];
    chain[0].type = CERT_TYPE_PEM;
    chain[0].size = 0;
    chain[0].data = nullptr;

    context.SetSortedChain(chain, 1);
    EXPECT_EQ(context.GetSortedChainCount(), 1);
}

// ==================== GetInputCerts / GetInputCertCount / GetCaCert / GetHostname tests ====================

// 016: All input getters return default values after construction
HWTEST_F(VerifyCertChainContextTest, InputGetters_Default_016, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    EXPECT_EQ(context.GetInputCerts(), nullptr);
    EXPECT_EQ(context.GetInputCertCount(), 0);
    EXPECT_EQ(context.GetCaCert(), nullptr);
    EXPECT_EQ(context.GetHostname(), nullptr);
}

// ==================== Error code set tests ====================

// 017: Error code sets contain required entries
HWTEST_F(VerifyCertChainContextTest, ErrorCodeSetMembership_017, testing::ext::TestSize.Level1)
{
    EXPECT_NE(SslErrorCodeSetBase.find(SSL_NONE_ERR), SslErrorCodeSetBase.end());
    EXPECT_NE(SslErrorCodeSetBase.find(SSL_X509_V_ERR_CERT_HAS_EXPIRED), SslErrorCodeSetBase.end());
    EXPECT_NE(SslErrorCodeSetBase.find(SSL_X509_V_ERR_CERT_UNTRUSTED), SslErrorCodeSetBase.end());

    EXPECT_NE(SslErrorCodeSetSinceAPI12.find(SSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT),
              SslErrorCodeSetSinceAPI12.end());
    EXPECT_NE(SslErrorCodeSetSinceAPI26.find(SSL_X509_V_ERR_HOSTNAME_MISMATCH),
              SslErrorCodeSetSinceAPI26.end());
}

// ==================== Edge case tests ====================

// 018: Multiple error code overwrites
HWTEST_F(VerifyCertChainContextTest, MultipleErrorOverwrite_018, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(SSL_X509_V_ERR_CERT_HAS_EXPIRED);
    EXPECT_EQ(context.GetErrorCode(), SSL_X509_V_ERR_CERT_HAS_EXPIRED);

    context.SetErrorCode(SSL_X509_V_ERR_CERT_UNTRUSTED);
    EXPECT_EQ(context.GetErrorCode(), SSL_X509_V_ERR_CERT_UNTRUSTED);

    context.SetErrorCode(SSL_X509_V_ERR_HOSTNAME_MISMATCH);
    EXPECT_EQ(context.GetErrorCode(), SSL_X509_V_ERR_HOSTNAME_MISMATCH);
}

// 019: State after parse error
HWTEST_F(VerifyCertChainContextTest, StateAfterParseError_019, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    context.SetErrorCode(PARSE_ERROR_CODE);
    EXPECT_EQ(context.GetErrorCode(), PARSE_ERROR_CODE);
    EXPECT_EQ(context.GetErrorMessage(), PARSE_ERROR_MSG);
    EXPECT_EQ(context.GetInputCerts(), nullptr);
    EXPECT_EQ(context.GetSortedChain(), nullptr);
}

// 020: CheckParamsType with invalid parameter count (0 params)
HWTEST_F(VerifyCertChainContextTest, CheckParamsType_InvalidCount_020, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    napi_value params[4] = {nullptr, nullptr, nullptr, nullptr};
    EXPECT_EQ(context.CheckParamsType(params, 0), false);
    EXPECT_EQ(context.CheckParamsType(params, 4), false);
}

// 021: Memory cleanup with allocated sorted chain data (destructor test)
HWTEST_F(VerifyCertChainContextTest, Destructor_FreesSortedChain_021, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    {
        VerifyCertChainContext context(env, manager);

        CertBlob *chain = new CertBlob[1];
        chain[0].type = CERT_TYPE_PEM;
        chain[0].size = 100;
        chain[0].data = new uint8_t[100];
        if (memset_s(chain[0].data, 100, 0xFF, 100) != EOK) {
            delete[] chain[0].data;
            delete[] chain;
            FAIL() << "memset_s failed";
            return;
        }

        context.SetSortedChain(chain, 1);
    }
    EXPECT_TRUE(true);
}

// 022: Context with mixed certificate types in chain
HWTEST_F(VerifyCertChainContextTest, MixedCertTypes_022, testing::ext::TestSize.Level1)
{
    napi_env env = nullptr;
    std::shared_ptr<EventManager> manager = nullptr;
    VerifyCertChainContext context(env, manager);

    CertBlob *chain = new CertBlob[3];
    chain[0].type = CERT_TYPE_PEM;
    chain[0].size = 100;
    chain[0].data = new uint8_t[100];
    chain[1].type = CERT_TYPE_DER;
    chain[1].size = 200;
    chain[1].data = new uint8_t[200];
    chain[2].type = CERT_TYPE_PEM;
    chain[2].size = 150;
    chain[2].data = new uint8_t[150];

    context.SetSortedChain(chain, 3);
    EXPECT_EQ(context.GetSortedChainCount(), 3);
    EXPECT_EQ(context.GetSortedChain()[0].type, CERT_TYPE_PEM);
    EXPECT_EQ(context.GetSortedChain()[1].type, CERT_TYPE_DER);
    EXPECT_EQ(context.GetSortedChain()[2].type, CERT_TYPE_PEM);
}

} // namespace
} // namespace OHOS::NetStack::Ssl
