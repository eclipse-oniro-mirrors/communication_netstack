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

#include "tls_cert_alias.h"
#include "cert_manager_api.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/rsa.h>

using namespace OHOS::NetStack::TlsSocket;
using namespace testing::ext;

namespace {
constexpr char URI[] = "uri-returned-by-cm";
constexpr size_t CHUNK_SIZE = 16 * 1024;
constexpr size_t DOUBLE_CHUNK_SIZE = CHUNK_SIZE * 2;
constexpr size_t SIGNATURE_BUFFER_SIZE = 256;
constexpr size_t DEFAULT_MESSAGE_SIZE = 40000;
constexpr size_t SHORT_MESSAGE_SIZE = 32;
constexpr uint8_t MESSAGE_FILL_BYTE = 0x5a;
constexpr uint64_t SIGN_HANDLE = 42;
constexpr uint32_t STALE_CERT_COUNT = 99;
constexpr uint8_t SIGNATURE_BYTES[] = {'s', 'i', 'g'};
constexpr uint32_t MOCK_CERT_COUNT = 2;
constexpr char CLIENT_ALIAS[] = " Client ";
constexpr char UNRELATED_ALIAS[] = "unrelated";
struct ApiState {
    int32_t listError = 0;
    int32_t getError = 0;
    int32_t initError = 0;
    int32_t updateError = 0;
    int32_t finishError = 0;
    bool allocateBeforeError = false;
    bool nullList = false;
    bool emptyList = false;
    bool duplicate = false;
    bool overflow = false;
    bool badAlias = false;
    bool badUri = false;
    bool emptyUri = false;
    bool matchSecond = false;
    bool badBlob = false;
    bool emptyBlob = false;
    bool emptyChain = false;
    bool exists = true;
    bool emptySignature = false;
    bool largeSignature = false;
    int failUpdateNumber = 1;
    int inits = 0;
    int updates = 0;
    int finishes = 0;
    int aborts = 0;
    uint32_t digest = CM_DIGEST_SHA256;
    uint32_t padding = CM_PADDING_PSS;
    std::vector<uint8_t> message;
} g_api;
int g_listAllocations = 0;

void CheckUri(const CmBlob *uri)
{
    ASSERT_NE(uri, nullptr);
    ASSERT_EQ(uri->size, sizeof(URI));
    ASSERT_NE(uri->data, nullptr);
    EXPECT_EQ(std::memcmp(uri->data, URI, sizeof(URI)), 0);
}

void CheckHandle(const CmBlob *handle)
{
    ASSERT_NE(handle, nullptr);
    ASSERT_EQ(handle->size, sizeof(uint64_t));
    ASSERT_NE(handle->data, nullptr);
    uint64_t value = 0;
    std::copy_n(handle->data, sizeof(value), reinterpret_cast<uint8_t *>(&value));
    EXPECT_EQ(value, SIGN_HANDLE);
}
} // namespace

extern "C" void *CmMalloc(size_t size)
{
    void *ptr = std::malloc(size);
    if (ptr) {
        ++g_listAllocations;
    }
    return ptr;
}

extern "C" void CmFree(void *ptr)
{
    if (ptr) {
        --g_listAllocations;
    }
    std::free(ptr);
}

extern "C" int32_t CmCallingGetAppCertList(uint32_t store, CredentialList *list)
{
    EXPECT_EQ(store, static_cast<uint32_t>(CM_PRI_CREDENTIAL_STORE));
    EXPECT_EQ(list->credentialAbstract, nullptr);
    EXPECT_EQ(list->credentialCount, 0U);
    if ((g_api.listError && !g_api.allocateBeforeError) || g_api.emptyList) {
        return g_api.listError;
    }
    list->credentialCount = 1;
    if (g_api.nullList) {
        return 0;
    }
    list->credentialAbstract = static_cast<CredentialAbstract *>(
        CmMalloc(MOCK_CERT_COUNT * sizeof(CredentialAbstract)));
    if (!list->credentialAbstract) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    std::fill_n(list->credentialAbstract, MOCK_CERT_COUNT, CredentialAbstract{});
    std::copy_n(CLIENT_ALIAS, sizeof(CLIENT_ALIAS), list->credentialAbstract[0].alias);
    std::copy_n(URI, sizeof(URI), list->credentialAbstract[0].keyUri);
    list->credentialAbstract[1] = list->credentialAbstract[0];
    if (g_api.badAlias) {
        auto &alias = list->credentialAbstract[0].alias;
        std::fill_n(alias, sizeof(alias), 'A');
    }
    if (g_api.badUri) {
        auto &keyUri = list->credentialAbstract[0].keyUri;
        std::fill_n(keyUri, sizeof(keyUri), 'A');
    }
    if (g_api.emptyUri) {
        list->credentialAbstract[0].keyUri[0] = '\0';
    }
    if (g_api.matchSecond) {
        std::copy_n(UNRELATED_ALIAS, sizeof(UNRELATED_ALIAS), list->credentialAbstract[0].alias);
    }
    list->credentialCount = g_api.overflow ? MAX_COUNT_CERTIFICATE + 1 :
        (g_api.duplicate || g_api.matchSecond) ? MOCK_CERT_COUNT : 1;
    return g_api.listError;
}

extern "C" int32_t CmGetAppCert(const CmBlob *uri, uint32_t store, Credential *credential)
{
    CheckUri(uri);
    EXPECT_EQ(store, static_cast<uint32_t>(CM_PRI_CREDENTIAL_STORE));
    EXPECT_EQ(credential->credData.size, static_cast<uint32_t>(MAX_LEN_CERTIFICATE_CHAIN));
    EXPECT_NE(credential->credData.data, nullptr);
    if (g_api.getError) {
        return g_api.getError;
    }
    constexpr char publicChain[] = "public certificate chain";
    std::copy_n(publicChain, sizeof(publicChain), credential->credData.data);
    credential->credData.size = g_api.badBlob ? MAX_LEN_CERTIFICATE_CHAIN + 1 : sizeof(publicChain);
    if (g_api.emptyBlob) {
        credential->credData.size = 0;
    }
    credential->certNum = g_api.emptyChain ? 0 : MOCK_CERT_COUNT;
    credential->isExist = g_api.exists;
    return 0;
}

extern "C" int32_t CmInit(const CmBlob *uri, const CmSignatureSpec *spec, CmBlob *handle)
{
    CheckUri(uri);
    EXPECT_EQ(spec->purpose, static_cast<uint32_t>(CM_KEY_PURPOSE_SIGN));
    EXPECT_EQ(spec->digest, g_api.digest);
    EXPECT_EQ(spec->padding, g_api.padding);
    EXPECT_EQ(handle->size, sizeof(uint64_t));
    ++g_api.inits;
    if (g_api.initError) {
        return g_api.initError;
    }
    uint64_t value = SIGN_HANDLE;
    std::copy_n(reinterpret_cast<const uint8_t *>(&value), sizeof(value), handle->data);
    return 0;
}

extern "C" int32_t CmUpdate(const CmBlob *handle, const CmBlob *input)
{
    CheckHandle(handle);
    ++g_api.updates;
    EXPECT_EQ(input->size, CHUNK_SIZE);
    if (g_api.updateError && g_api.updates == g_api.failUpdateNumber) {
        return g_api.updateError;
    }
    g_api.message.insert(g_api.message.end(), input->data, input->data + input->size);
    return 0;
}

extern "C" int32_t CmFinish(const CmBlob *handle, const CmBlob *input, CmBlob *output)
{
    CheckHandle(handle);
    ++g_api.finishes;
    EXPECT_GT(input->size, 0U);
    EXPECT_LE(input->size, CHUNK_SIZE);
    if (g_api.finishError) {
        return g_api.finishError;
    }
    g_api.message.insert(g_api.message.end(), input->data, input->data + input->size);
    if (g_api.emptySignature || g_api.largeSignature) {
        output->size = g_api.emptySignature ? 0 : output->size + 1;
        return 0;
    }
    EXPECT_GE(output->size, sizeof(SIGNATURE_BYTES));
    std::copy_n(SIGNATURE_BYTES, sizeof(SIGNATURE_BYTES), output->data);
    output->size = sizeof(SIGNATURE_BYTES);
    return 0;
}

extern "C" int32_t CmAbort(const CmBlob *handle)
{
    CheckHandle(handle);
    ++g_api.aborts;
    return CMR_ERROR_KEY_ABORT_FAILED; // Cleanup failure cannot replace the primary failure.
}

namespace {
class TlsCertManagerAdapterTest : public testing::Test {
public:
    void SetUp() override { g_api = {}; }
    void TearDown() override { EXPECT_EQ(g_listAllocations, 0); }

    int Load(const std::string &alias = " Client ")
    {
        std::string uri = "stale uri";
        std::string pem = "stale certificate";
        uint32_t count = STALE_CERT_COUNT;
        int result = CreateCertManagerAdapter()->Load(alias, uri, pem, count);
        if (result == 0) {
            EXPECT_EQ(uri, URI);
            EXPECT_EQ(pem, std::string("public certificate chain", sizeof("public certificate chain")));
            EXPECT_EQ(count, MOCK_CERT_COUNT);
        }
        return result;
    }

    int Sign(size_t size = DEFAULT_MESSAGE_SIZE, AliasSignatureSpec spec = {"SHA256", RSA_PKCS1_PSS_PADDING})
    {
        std::vector<uint8_t> input(size, MESSAGE_FILL_BYTE);
        std::vector<uint8_t> signature(SIGNATURE_BUFFER_SIZE);
        int result = CreateCertManagerAdapter()->Sign(URI, spec, input.data(), input.size(), signature);
        if (result == 0) {
            EXPECT_EQ(signature, (std::vector<uint8_t>{'s', 'i', 'g'}));
            EXPECT_EQ(g_api.message, input);
        }
        return result;
    }
};

HWTEST_F(TlsCertManagerAdapterTest, ExactAliasPrivateStoreAndSecondEntry, TestSize.Level1)
{
    EXPECT_EQ(Load(), 0);
    EXPECT_EQ(Load("Client"), TLS_ALIAS_NOT_FOUND);
    EXPECT_EQ(Load(" client "), TLS_ALIAS_NOT_FOUND);
    g_api.matchSecond = true;
    EXPECT_EQ(Load(), 0);
}

HWTEST_F(TlsCertManagerAdapterTest, EmptyListAndMissingCredential, TestSize.Level1)
{
    g_api.emptyList = true;
    EXPECT_EQ(Load(), TLS_ALIAS_NOT_FOUND);
    g_api = {};
    g_api.exists = false;
    EXPECT_EQ(Load(), TLS_ALIAS_NOT_FOUND);
}

HWTEST_F(TlsCertManagerAdapterTest, InvalidListCountsPointersAndStrings, TestSize.Level1)
{
    for (auto flag : {&ApiState::overflow, &ApiState::nullList, &ApiState::badAlias,
        &ApiState::badUri, &ApiState::emptyUri, &ApiState::duplicate}) {
        g_api = {};
        g_api.*flag = true;
        EXPECT_EQ(Load(), TLS_ALIAS_SERVICE_ERROR);
    }
}

HWTEST_F(TlsCertManagerAdapterTest, ListErrorStillFreesSdkAllocationAndResetsOutputs, TestSize.Level1)
{
    g_api.listError = CMR_ERROR_IPC_WRITE_FAIL;
    g_api.allocateBeforeError = true;
    std::string uri = "old";
    std::string pem = "old";
    constexpr uint32_t initialCertCount = 7;
    uint32_t count = initialCertCount;
    EXPECT_EQ(CreateCertManagerAdapter()->Load(" Client ", uri, pem, count), TLS_ALIAS_SERVICE_ERROR);
    EXPECT_EQ(g_listAllocations, 0);
    EXPECT_TRUE(uri.empty());
    EXPECT_TRUE(pem.empty());
    EXPECT_EQ(count, 0U);
}

HWTEST_F(TlsCertManagerAdapterTest, EmptyAndOversizedCertificateBlob, TestSize.Level1)
{
    g_api.emptyBlob = true;
    EXPECT_EQ(Load(), TLS_ALIAS_NOT_FOUND);
    g_api = {};
    g_api.emptyChain = true;
    EXPECT_EQ(Load(), TLS_ALIAS_NOT_FOUND);
    g_api = {};
    g_api.badBlob = true;
    EXPECT_EQ(Load(), TLS_ALIAS_SERVICE_ERROR);
}

struct ErrorMapping {
    int32_t source;
    int32_t lookup;
    int32_t signing;
};
class TlsCertManagerErrorTest : public TlsCertManagerAdapterTest, public testing::WithParamInterface<ErrorMapping> {};

HWTEST_P(TlsCertManagerErrorTest, LookupAndInitMapping, TestSize.Level1)
{
    const auto mapping = GetParam();
    g_api.listError = mapping.source;
    EXPECT_EQ(Load(), mapping.lookup);
    g_api = {};
    g_api.getError = mapping.source;
    EXPECT_EQ(Load(), mapping.lookup);
    g_api = {};
    g_api.initError = mapping.source;
    EXPECT_EQ(Sign(), mapping.lookup);
    EXPECT_EQ(g_api.aborts, 0);
    EXPECT_EQ(g_api.finishes, 0);
}

HWTEST_P(TlsCertManagerErrorTest, SessionMappingAndAbortPreserveFirstError, TestSize.Level1)
{
    const auto mapping = GetParam();
    g_api.updateError = mapping.source;
    EXPECT_EQ(Sign(), mapping.signing);
    EXPECT_EQ(g_api.aborts, 1);
    EXPECT_EQ(g_api.finishes, 0);
    g_api = {};
    g_api.finishError = mapping.source;
    EXPECT_EQ(Sign(), mapping.signing);
    EXPECT_EQ(g_api.aborts, 1);
}

INSTANTIATE_TEST_SUITE_P(CmErrors, TlsCertManagerErrorTest, testing::Values(
    ErrorMapping{CMR_ERROR_PERMISSION_DENIED, TLS_ALIAS_PERMISSION, TLS_ALIAS_PERMISSION},
    ErrorMapping{CMR_ERROR_AUTH_FAILED_MAC_FAILED, TLS_ALIAS_UNAUTHORIZED, TLS_ALIAS_UNAUTHORIZED},
    ErrorMapping{CMR_ERROR_AUTH_FAILED_MAC_MISMATCH, TLS_ALIAS_UNAUTHORIZED, TLS_ALIAS_UNAUTHORIZED},
    ErrorMapping{CMR_ERROR_AUTH_CHECK_FAILED, TLS_ALIAS_UNAUTHORIZED, TLS_ALIAS_UNAUTHORIZED},
    ErrorMapping{CMR_ERROR_NOT_PERMITTED, TLS_ALIAS_UNAUTHORIZED, TLS_ALIAS_UNAUTHORIZED},
    ErrorMapping{CMR_ERROR_NOT_SUPPORTED, TLS_ALIAS_UNSUPPORTED, TLS_ALIAS_UNSUPPORTED},
    ErrorMapping{CMR_ERROR_INVALID_CERT_FORMAT, TLS_ALIAS_NOT_FOUND, TLS_ALIAS_NOT_FOUND},
    ErrorMapping{CMR_ERROR_NOT_FOUND, TLS_ALIAS_NOT_FOUND, TLS_ALIAS_SERVICE_ERROR},
    ErrorMapping{CMR_ERROR_NOT_EXIST, TLS_ALIAS_NOT_FOUND, TLS_ALIAS_SERVICE_ERROR},
    ErrorMapping{CMR_ERROR_IPC_WRITE_FAIL, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_SERVICE_ERROR},
    ErrorMapping{CMR_ERROR_STORAGE, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_SERVICE_ERROR},
    ErrorMapping{CMR_ERROR_KEY_INIT_FAILED, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_SERVICE_ERROR},
    ErrorMapping{CMR_ERROR_KEY_UPDATE_FAILED, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_SERVICE_ERROR},
    ErrorMapping{CMR_ERROR_KEY_FINISH_FAILED, TLS_ALIAS_SERVICE_ERROR, TLS_ALIAS_SERVICE_ERROR}));

HWTEST_F(TlsCertManagerAdapterTest, SignatureChunkBoundariesPreserveOriginalMessage, TestSize.Level1)
{
    for (size_t size : {size_t{1}, CHUNK_SIZE, CHUNK_SIZE + 1,
        DOUBLE_CHUNK_SIZE, DOUBLE_CHUNK_SIZE + 1, DEFAULT_MESSAGE_SIZE}) {
        SCOPED_TRACE(size);
        g_api = {};
        EXPECT_EQ(Sign(size), 0);
        EXPECT_EQ(g_api.inits, 1);
        EXPECT_EQ(g_api.updates, static_cast<int>((size - 1) / CHUNK_SIZE));
        EXPECT_EQ(g_api.finishes, 1);
        EXPECT_EQ(g_api.aborts, 0);
    }
}

HWTEST_F(TlsCertManagerAdapterTest, AllSupportedDigestAndPaddingMappings, TestSize.Level1)
{
    const std::pair<const char *, uint32_t> digests[] = {
        {"SHA256", CM_DIGEST_SHA256}, {"SHA384", CM_DIGEST_SHA384}, {"SHA512", CM_DIGEST_SHA512}};
    const std::pair<int, uint32_t> paddings[] = {
        {0, CM_PADDING_NONE}, {RSA_PKCS1_PADDING, CM_PADDING_PKCS1_V1_5}, {RSA_PKCS1_PSS_PADDING, CM_PADDING_PSS}};
    for (const auto &[digest, cmDigest] : digests) {
        for (const auto &[padding, cmPadding] : paddings) {
            g_api = {};
            g_api.digest = cmDigest;
            g_api.padding = cmPadding;
            EXPECT_EQ(Sign(SHORT_MESSAGE_SIZE, {digest, padding}), 0);
        }
    }
}

HWTEST_F(TlsCertManagerAdapterTest, InvalidSigningInputsNeverStartSession, TestSize.Level1)
{
    auto adapter = CreateCertManagerAdapter();
    const uint8_t data[] = {1};
    std::vector<uint8_t> signature(SIGNATURE_BUFFER_SIZE);
    std::vector<uint8_t> empty;
    EXPECT_EQ(adapter->Sign(URI, {"SHA1", 0}, data, 1, signature), TLS_ERR_SSL_NULL);
    EXPECT_EQ(adapter->Sign(URI, {"SHA256", 0}, nullptr, 1, signature), TLS_ERR_SSL_NULL);
    EXPECT_EQ(adapter->Sign(URI, {"SHA256", 0}, data, 0, signature), TLS_ERR_SSL_NULL);
    EXPECT_EQ(adapter->Sign(URI, {"SHA256", 0}, data, 1, empty), TLS_ERR_SSL_NULL);
    EXPECT_EQ(adapter->Sign(URI, {"SHA256", RSA_NO_PADDING}, data, 1, signature), TLS_ERR_SSL_NULL);
    EXPECT_EQ(g_api.inits, 0);
    EXPECT_EQ(g_api.aborts, 0);
}

HWTEST_F(TlsCertManagerAdapterTest, LaterUpdateFailureAbortsExactlyOnce, TestSize.Level1)
{
    constexpr int failingUpdateNumber = 2;
    g_api.updateError = CMR_ERROR_KEY_UPDATE_FAILED;
    g_api.failUpdateNumber = failingUpdateNumber;
    EXPECT_EQ(Sign(), TLS_ALIAS_SERVICE_ERROR);
    EXPECT_EQ(g_api.updates, failingUpdateNumber);
    EXPECT_EQ(g_api.finishes, 0);
    EXPECT_EQ(g_api.aborts, 1);
}

HWTEST_F(TlsCertManagerAdapterTest, InvalidSuccessfulFinishSizeDoesNotAbortConsumedSession, TestSize.Level1)
{
    g_api.emptySignature = true;
    EXPECT_EQ(Sign(), TLS_ALIAS_SERVICE_ERROR);
    EXPECT_EQ(g_api.finishes, 1);
    EXPECT_EQ(g_api.aborts, 0);
    g_api = {};
    g_api.largeSignature = true;
    EXPECT_EQ(Sign(), TLS_ALIAS_SERVICE_ERROR);
    EXPECT_EQ(g_api.finishes, 1);
    EXPECT_EQ(g_api.aborts, 0);
}
} // namespace
