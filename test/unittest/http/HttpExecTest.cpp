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


#include <cstring>
#include "gtest/gtest.h"

#ifdef GTEST_API_
#define private public
#endif

#include "http_exec.h"
#include "http_async_work.h"
#include "netstack_log.h"
#include "constant.h"
#include "secure_char.h"
#include "curl/curl.h"

#if ENABLE_HTTP_INTERCEPT
#include "epoll_multi_driver.h"
#include "request_info.h"
#endif

#if defined(HTTP_MULTIPATH_CERT_ENABLE) && defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE) && HAS_NETMANAGER_BASE
#include "VerifyMultiCandidateCertData.h"
#include "netstack_common_utils.h"
#endif
#ifdef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

struct SslCtxDeleter {
    void operator()(SSL_CTX* p) const { SSL_CTX_free(p); }
};
struct X509SroreCtxDeleter {
    void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_cleanup(p); }
};
struct BioDeleter {
    void operator()(BIO* p) const { BIO_free(p); }
};
struct X509Deleter {
    void operator()(X509* p) const { X509_free(p); }
};
struct X509StackDeleter {
    void operator()(STACK_OF(X509)* p) const { sk_X509_free(p); }
};
 
using unique_SSL_CTX = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using unique_X509_STORE_CTX = std::unique_ptr<X509_STORE_CTX, X509SroreCtxDeleter>;
using unique_BIO = std::unique_ptr<BIO, BioDeleter>;
using unique_X509 = std::unique_ptr<X509, X509Deleter>;
using unique_X509_STACK = std::unique_ptr<STACK_OF(X509), X509StackDeleter>;
#endif

#if defined(HTTP_MULTIPATH_CERT_ENABLE) && defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE) && HAS_NETMANAGER_BASE
static unique_X509 ParsePemCert(const char *pem)
{
    unique_BIO bio(BIO_new_mem_buf(pem, -1));
    return unique_X509(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
}

static std::string MakePinnedPubkey(X509 *cert)
{
    if (cert == nullptr) {
        return {};
    }
    unsigned char *pubkey = nullptr;
    int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &pubkey);
    if (length <= 0 || pubkey == nullptr) {
        OPENSSL_free(pubkey);
        return {};
    }
    std::string digest;
    bool ok = OHOS::NetStack::CommonUtils::Sha256sum(pubkey, static_cast<size_t>(length), digest);
    OPENSSL_free(pubkey);
    return ok ? "sha256//" + digest : std::string{};
}
#endif

using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Http;

struct CurlDeleter {
    void operator()(CURL* p) const { curl_easy_cleanup(p); }
};
using unique_CURL = std::unique_ptr<CURL, CurlDeleter>;

class HttpExecTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace std;
using namespace testing::ext;


HWTEST_F(HttpExecTest, SetOption001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    EXPECT_TRUE(HttpExec::SetOption(handle.get(), &context, context.GetCurlHeaderList()));
}

HWTEST_F(HttpExecTest, SetServerSSLCertOption001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    EXPECT_TRUE(HttpExec::SetServerSSLCertOption(handle.get(), &context));
}

HWTEST_F(HttpExecTest, GetSslVerifyHostValue001, TestSize.Level1)
{
    HttpRequestOptions options;
    EXPECT_EQ(HttpExec::GetSslVerifyHostValue(options), 2L);

    options.SetSslServerHostnameVerification(false);
    EXPECT_EQ(HttpExec::GetSslVerifyHostValue(options), 0L);
}

#if defined(HTTP_MULTIPATH_CERT_ENABLE) && defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE) && HAS_NETMANAGER_BASE
// A valid chain may be pinned by its root or leaf, but not an unrelated key.
HWTEST_F(HttpExecTest, VerifyPinnedPubkeyForChain_RootOrLeaf, TestSize.Level1)
{
    unique_X509 root = ParsePemCert(Ssl::TestData::OLD_ROOT_PEM);
    unique_X509 leaf = ParsePemCert(Ssl::TestData::LEAF_PEM);
    unique_X509 otherRoot = ParsePemCert(Ssl::TestData::SELF_NEW_ROOT_PEM);
    ASSERT_NE(root, nullptr);
    ASSERT_NE(leaf, nullptr);
    ASSERT_NE(otherRoot, nullptr);

    unique_X509_STACK chain(sk_X509_new_null());
    ASSERT_NE(chain, nullptr);
    ASSERT_EQ(sk_X509_push(chain.get(), leaf.get()), 1);
    ASSERT_EQ(sk_X509_push(chain.get(), root.get()), 2);

    std::string rootPin = MakePinnedPubkey(root.get());
    std::string leafPin = MakePinnedPubkey(leaf.get());
    std::string wrongPin = MakePinnedPubkey(otherRoot.get());
    ASSERT_FALSE(rootPin.empty());
    ASSERT_FALSE(leafPin.empty());
    ASSERT_FALSE(wrongPin.empty());
    EXPECT_TRUE(HttpExec::VerifyPinnedPubkeyForChain(chain.get(), rootPin));
    EXPECT_TRUE(HttpExec::VerifyPinnedPubkeyForChain(chain.get(), leafPin));
    EXPECT_FALSE(HttpExec::VerifyPinnedPubkeyForChain(chain.get(), wrongPin));
    EXPECT_TRUE(HttpExec::VerifyPinnedPubkeyForChain(chain.get(), ""));
    EXPECT_FALSE(HttpExec::VerifyPinnedPubkeyForChain(nullptr, leafPin));
}
#endif

#if defined(HTTP_MULTIPATH_CERT_ENABLE) && defined(HTTP_ONLY_VERIFY_ROOT_CA_ENABLE)
// Skipping certificate verification must not silently disable configured pinning.
HWTEST_F(HttpExecTest, SslCtxFunction_SkipWithPinKeepsOldCallback, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    unique_SSL_CTX sslCtx(SSL_CTX_new(TLS_client_method()));
    ASSERT_NE(handle, nullptr);
    ASSERT_NE(sslCtx, nullptr);

    auto manager = std::make_shared<EventManager>();
    RequestContext context(nullptr, manager);
    context.options.SetCanSkipCertVerifyFlag(true);
    std::string pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    context.SetPinnedPubkey(pin);
    ASSERT_EQ(HttpExec::SslCtxFunction(handle.get(), sslCtx.get(), &context), CURLE_OK);
    EXPECT_EQ(SSL_CTX_get_verify_mode(sslCtx.get()), SSL_VERIFY_PEER);

    unique_SSL_CTX noPinSslCtx(SSL_CTX_new(TLS_client_method()));
    ASSERT_NE(noPinSslCtx, nullptr);
    RequestContext noPinContext(nullptr, manager);
    noPinContext.options.SetCanSkipCertVerifyFlag(true);
    ASSERT_EQ(HttpExec::SslCtxFunction(handle.get(), noPinSslCtx.get(), &noPinContext), CURLE_OK);
    EXPECT_EQ(SSL_CTX_get_verify_mode(noPinSslCtx.get()), SSL_VERIFY_NONE);
}
#endif

#ifdef HTTP_MULTIPATH_CERT_ENABLE
HWTEST_F(HttpExecTest, MultiPathSslCtxFunction001, TestSize.Level1)
{
    std::string dummy_root_ca_pem = "-----BEGIN CERTIFICATE-----\n"
        "MIIC/jCCAeagAwIBAgIJPscmmRP6WujNMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n"
        "BAMTEE9wZW5IYXJtb255IFRlc3QwHhcNMjUwNzEzMTcyMTM4WhcNMzEwMTAzMTcy\n"
        "MTM4WjAbMRkwFwYDVQQDExBPcGVuSGFybW9ueSBUZXN0MIIBIjANBgkqhkiG9w0B\n"
        "AQEFAAOCAQ8AMIIBCgKCAQEA1WD9TT08Sx3jJprsLToBOxm0cXEL1p/Lbo+D9L5P\n"
        "xb5eDAsbzbShhjhMu0dUshwDZzFOPIIKldB7qy1oqXVIH6r/qht549nH+/ouriWW\n"
        "meWdGKOAkzB5szwRWTSA/okM+afCUN5fV1H5B498jGXBhtNOJbm1+hMJs0siHCPC\n"
        "A5Hc9mf8J33LJA7ZvsGR4/K6+mFE9fjzvxw0bN97Qwjtl/DNpKNmUY5YTy/qbkfx\n"
        "1ZXkE3ztgjQnQvyQvvT4TRu3oSJd4jVtmpsiJZuObcCzv/Z9gcM0FWXAUuvX8TCS\n"
        "io4eMIrSP0I/0J4C5a0zcWZJGzsJ+RkVRxEHcozNOMlyjQIDAQABo0UwQzAMBgNV\n"
        "HRMEBTADAQH/MAsGA1UdDwQEAwIC9DAmBgNVHREEHzAdhhtodHRwOi8vZXhhbXBs\n"
        "ZS5vcmcvd2ViaWQjbWUwDQYJKoZIhvcNAQELBQADggEBAGHRWidqgRFopjieMfuc\n"
        "4Re/vqk25+CDy8LmuH/Ha9zHGd2Wxif5PGpEgjcP4zfk8XRGVGvRR++Uu3FInNga\n"
        "a+k1ClbgiDf+E0uh64kTYzTjd0UMJ7Pbn1FKXjpvZaJZOIKTeR7O9UhdNeqE4g7Q\n"
        "tTkF39n9pOGDfyA4kOErfcWA21zRd0qTEe5qnrJ0+HiMY7V5LYjIJ9tJyRTpfCzr\n"
        "7yzDZzDwSwdpM/i+B2jbjqbQIJHdcajdzxdq9VzLla1yNtA/AOxtmTmY2q8Uj3mw\n"
        "zD2cfeLdHoEhKHnSP76QdUnUMMn8eaPPMqWa+7XhxfXCCJjiE8STLzOkBAcvR9E2\n"
        "QVo=\n"
        "-----END CERTIFICATE-----\n";
    unique_CURL handle(curl_easy_init());
    unique_SSL_CTX ctx(SSL_CTX_new(TLS_client_method()));
    napi_env env = nullptr;
    std::shared_ptr<EventManager> eventManager = std::make_shared<EventManager>();
    RequestContext context(env, eventManager);
    context.options.SetCaData(dummy_root_ca_pem);
    CURLcode ret = HttpExec::MultiPathSslCtxFunction(handle.get(), ctx.get(), &context);
    ASSERT_EQ(ret, CURLE_OK);
 
    unique_BIO bio(BIO_new_mem_buf(dummy_root_ca_pem.data(), dummy_root_ca_pem.size()));
    ASSERT_NE(bio, nullptr);
 
    unique_X509 cert(PEM_read_bio_X509(bio.get(), NULL, NULL, NULL));
    ASSERT_NE(cert, nullptr);
 
    // 配置 X509_STORE_CTX，执行验证
    X509_STORE *store = SSL_CTX_get_cert_store(ctx.get());
    unique_X509_STORE_CTX storeCtx(X509_STORE_CTX_new());
    X509_STORE_CTX_init(storeCtx.get(), store, cert.get(), nullptr);
 
    // 默认允许自签名证书验证
    int verify_result = X509_verify_cert(storeCtx.get());
 
    EXPECT_EQ(verify_result, 1);
}
#endif

HWTEST_F(HttpExecTest, SetSslTypeAndClientEncCert001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    
    context.options.SetSslType(SslType::TLS);
    EXPECT_TRUE(HttpExec::SetSslTypeAndClientEncCert(handle.get(), &context));
}

HWTEST_F(HttpExecTest, SetSslTypeAndClientEncCert002, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    
    context.options.SetSslType(SslType::TLCP);
    EXPECT_FALSE(HttpExec::SetSslTypeAndClientEncCert(handle.get(), &context));
}

HWTEST_F(HttpExecTest, SetOptionWithMaxRedirects001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is set to 0 (disable redirect)
    context.options.SetMaxRedirects(0);
    EXPECT_EQ(context.options.GetMaxRedirects(), 0);
}

HWTEST_F(HttpExecTest, SetOptionWithMaxRedirects002, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is set to a normal value
    context.options.SetMaxRedirects(5);
    EXPECT_EQ(context.options.GetMaxRedirects(), 5);
}

HWTEST_F(HttpExecTest, IsReachRedirectLimitTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is not set (undefined)
    // IsReachRedirectLimit should return false
    context.redirects_ = 10;
    EXPECT_FALSE(context.IsReachRedirectLimit());
}

HWTEST_F(HttpExecTest, IsReachRedirectLimitTest002, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is set to 0 and redirects_ is 0
    // IsReachRedirectLimit should return true (0 >= 0)
    context.options.SetMaxRedirects(0);
    context.redirects_ = 0;
    EXPECT_TRUE(context.IsReachRedirectLimit());
}

HWTEST_F(HttpExecTest, IsReachRedirectLimitTest003, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is set to 5 and redirects_ is 3
    // IsReachRedirectLimit should return false (3 < 5)
    context.options.SetMaxRedirects(5);
    context.redirects_ = 3;
    EXPECT_FALSE(context.IsReachRedirectLimit());
}

HWTEST_F(HttpExecTest, IsReachRedirectLimitTest004, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is set to 5 and redirects_ is 5
    // IsReachRedirectLimit should return true (5 >= 5)
    context.options.SetMaxRedirects(5);
    context.redirects_ = 5;
    EXPECT_TRUE(context.IsReachRedirectLimit());
}

HWTEST_F(HttpExecTest, IsReachRedirectLimitTest005, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    // Test when maxRedirects is set to 5 and redirects_ is 10
    // IsReachRedirectLimit should return true (10 >= 5)
    context.options.SetMaxRedirects(5);
    context.redirects_ = 10;
    EXPECT_TRUE(context.IsReachRedirectLimit());
}

HWTEST_F(HttpExecTest, SetSniHostNameOption001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetSniHostName("example.com");
    EXPECT_TRUE(HttpExec::SetOption(handle.get(), &context,
                                    context.GetCurlHeaderList()));
}

HWTEST_F(HttpExecTest, SetSniHostNameOption002, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    EXPECT_TRUE(HttpExec::SetOption(handle.get(), &context,
                                    context.GetCurlHeaderList()));
}

HWTEST_F(HttpExecTest, SetServerSSLCertOptionWithPartialChain001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    context.options.SetPartialChain(false);
    EXPECT_TRUE(HttpExec::SetServerSSLCertOption(handle.get(), &context));
}

HWTEST_F(HttpExecTest, SetServerSSLCertOptionWithPartialChain002, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    context.options.SetPartialChain(true);
    EXPECT_TRUE(HttpExec::SetServerSSLCertOption(handle.get(), &context));
}

HWTEST_F(HttpExecTest, SetFollowRedirectPostToGetOption001, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetFollowRedirectPostToGet(true);
    EXPECT_TRUE(HttpExec::SetOption(handle.get(), &context,
                                    context.GetCurlHeaderList()));
}

HWTEST_F(HttpExecTest, SetFollowRedirectPostToGetOption002, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetFollowRedirectPostToGet(false);
    EXPECT_TRUE(HttpExec::SetOption(handle.get(), &context,
                                    context.GetCurlHeaderList()));
}

#if ENABLE_HTTP_INTERCEPT
HWTEST_F(HttpExecTest, IsRedirectPostToGetNeededBoundaryTest, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetFollowRedirectPostToGet(true);
    context.options.SetMethod(OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);

    // Only 301/302/303 convert; 300/304/307/308 must NOT.
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 300));
    EXPECT_TRUE (OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 301));
    EXPECT_TRUE (OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 302));
    EXPECT_TRUE (OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 303));
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 304));
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 307));
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 308));
}

HWTEST_F(HttpExecTest, IsRedirectPostToGetNeededNonPostTest, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetFollowRedirectPostToGet(true);

    // Option is POST-specific: PUT/GET must not convert even with option on.
    context.options.SetMethod(Http::HttpConstant::HTTP_METHOD_PUT);
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 303));
    context.options.SetMethod(Http::HttpConstant::HTTP_METHOD_GET);
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 303));
}

HWTEST_F(HttpExecTest, IsRedirectPostToGetNeededOptionOffTest, TestSize.Level1)
{
    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetFollowRedirectPostToGet(false);
    context.options.SetMethod(OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    EXPECT_FALSE(OHOS::NetStack::HttpOverCurl::EpollMultiDriver::IsRedirectPostToGetNeeded(&context, 303));
}

static std::unique_ptr<OHOS::NetStack::Http::RequestContext> BuildRedirectTestContext(
    bool followRedirectPostToGet, const std::string &method)
{
    auto context = std::make_unique<OHOS::NetStack::Http::RequestContext>(nullptr, nullptr);
    context->options.SetUrl("http://127.0.0.1:1/original");
    context->options.SetMethod(method);
    context->options.SetFollowRedirectPostToGet(followRedirectPostToGet);
    context->options.ReplaceBody("key=value", strlen("key=value"));
    context->options.SetHeader("Content-Type", "application/x-www-form-urlencoded");
    context->options.SetHeader("Content-Length", "9");
    context->options.SetHeader("X-Keep-Me", "keep-me");
    return context;
}

static OHOS::NetStack::HttpOverCurl::RequestInfo *BuildRedirectTestRequestInfo(
    CURL *easyHandle, OHOS::NetStack::Http::RequestContext *context)
{
    // HandleRedirect() takes ownership and deletes it.
    return new OHOS::NetStack::HttpOverCurl::RequestInfo{easyHandle, {}, context};
}

HWTEST_F(HttpExecTest, HandleRedirectPostToGetTest, TestSize.Level1)
{
    auto context = BuildRedirectTestContext(true, OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    auto queue = std::make_shared<
        OHOS::NetStack::HttpOverCurl::ThreadSafeStorage<OHOS::NetStack::HttpOverCurl::RequestInfo *>>();
    OHOS::NetStack::HttpOverCurl::EpollMultiDriver driver(queue);

    CURL *easyHandle = curl_easy_init();
    ASSERT_NE(easyHandle, nullptr);
    auto requestInfo = BuildRedirectTestRequestInfo(easyHandle, context.get());
    auto location = std::make_shared<std::string>("http://127.0.0.1:1/redirected");

    OHOS::NetStack::HttpOverCurl::EpollMultiDriver::ApplyRedirectPostToGet(context.get());

    driver.HandleRedirect(easyHandle, location, requestInfo);

    EXPECT_EQ(context->options.GetUrl(), "http://127.0.0.1:1/redirected");
    EXPECT_EQ(context->options.GetMethod(), OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_GET);
    EXPECT_TRUE(context->options.GetBody().empty());
    EXPECT_EQ(context->options.GetHeader().count("Content-Type"), 0u);
    EXPECT_EQ(context->options.GetHeader().count("Content-Length"), 0u);
    EXPECT_EQ(context->options.GetHeader().count("X-Keep-Me"), 1u);
    EXPECT_EQ(context->redirects_, 1u);
}

HWTEST_F(HttpExecTest, HandleRedirectSeeOtherPostToGetTest, TestSize.Level1)
{
    auto context = BuildRedirectTestContext(true, OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    auto queue = std::make_shared<
        OHOS::NetStack::HttpOverCurl::ThreadSafeStorage<OHOS::NetStack::HttpOverCurl::RequestInfo *>>();
    OHOS::NetStack::HttpOverCurl::EpollMultiDriver driver(queue);

    auto requestInfo = BuildRedirectTestRequestInfo(nullptr, context.get());
    auto location = std::make_shared<std::string>("http://127.0.0.1:1/redirected");

    OHOS::NetStack::HttpOverCurl::EpollMultiDriver::ApplyRedirectPostToGet(context.get());

    driver.HandleRedirect(nullptr, location, requestInfo);

    EXPECT_EQ(context->options.GetUrl(), "http://127.0.0.1:1/redirected");
    EXPECT_EQ(context->options.GetMethod(), OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_GET);
    EXPECT_TRUE(context->options.GetBody().empty());
    EXPECT_EQ(context->options.GetHeader().count("Content-Type"), 0u);
    EXPECT_EQ(context->options.GetHeader().count("Content-Length"), 0u);
    EXPECT_EQ(context->redirects_, 1u);
}

HWTEST_F(HttpExecTest, HandleRedirectKeepPostWhenOptionOffTest, TestSize.Level1)
{
    auto context = BuildRedirectTestContext(false, OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    auto queue = std::make_shared<
        OHOS::NetStack::HttpOverCurl::ThreadSafeStorage<OHOS::NetStack::HttpOverCurl::RequestInfo *>>();
    OHOS::NetStack::HttpOverCurl::EpollMultiDriver driver(queue);

    auto requestInfo = BuildRedirectTestRequestInfo(nullptr, context.get());
    auto location = std::make_shared<std::string>("http://127.0.0.1:1/redirected");

    driver.HandleRedirect(nullptr, location, requestInfo);

    EXPECT_EQ(context->options.GetUrl(), "http://127.0.0.1:1/redirected");
    EXPECT_EQ(context->options.GetMethod(), OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    EXPECT_EQ(context->options.GetBody(), "key=value");
    EXPECT_EQ(context->options.GetHeader().count("Content-Type"), 1u);
    EXPECT_EQ(context->options.GetHeader().count("Content-Length"), 1u);
    EXPECT_EQ(context->options.GetHeader().count("X-Keep-Me"), 1u);
    EXPECT_EQ(context->redirects_, 1u);
}

HWTEST_F(HttpExecTest, HandleRedirectKeepPostOnTemporaryRedirectTest, TestSize.Level1)
{
    auto context = BuildRedirectTestContext(true, OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    auto queue = std::make_shared<
        OHOS::NetStack::HttpOverCurl::ThreadSafeStorage<OHOS::NetStack::HttpOverCurl::RequestInfo *>>();
    OHOS::NetStack::HttpOverCurl::EpollMultiDriver driver(queue);

    auto requestInfo = BuildRedirectTestRequestInfo(nullptr, context.get());
    auto location = std::make_shared<std::string>("http://127.0.0.1:1/redirected");

    // 307/308 must preserve the method even when the option is on, so no conversion
    // is applied by HandleCurlDoneMessage() before HandleRedirect() runs.
    driver.HandleRedirect(nullptr, location, requestInfo);

    EXPECT_EQ(context->options.GetUrl(), "http://127.0.0.1:1/redirected");
    EXPECT_EQ(context->options.GetMethod(), OHOS::NetStack::Http::HttpConstant::HTTP_METHOD_POST);
    EXPECT_EQ(context->options.GetBody(), "key=value");
    EXPECT_EQ(context->options.GetHeader().count("Content-Type"), 1u);
    EXPECT_EQ(context->options.GetHeader().count("Content-Length"), 1u);
    EXPECT_EQ(context->redirects_, 1u);
}
#endif

HWTEST_F(HttpExecTest, SetFollowRedirectPostToGetWithMaxRedirectsZero, TestSize.Level1)
{
    unique_CURL handle(curl_easy_init());
    ASSERT_NE(handle, nullptr);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    context.options.SetFollowRedirectPostToGet(true);
    context.options.SetMaxRedirects(0);
    EXPECT_TRUE(HttpExec::SetOption(handle.get(), &context, context.GetCurlHeaderList()));
}

#ifdef HTTP_HANDOVER_FEATURE
HWTEST_F(HttpExecTest, SetHandoverCallbacks, TestSize.Level1)
{
    HttpOverCurl::TransferCallbacks callbacks;
    HttpExec::SetHandoverCallbacks(callbacks);
    ASSERT_TRUE(callbacks.handoverInfoCallback);
    ASSERT_TRUE(callbacks.setHandoverInfoCallback);
    ASSERT_TRUE(callbacks.resetResponseCallback);
}

HWTEST_F(HttpExecTest, HandoverInfoCallbackNull, TestSize.Level1)
{
    HttpOverCurl::TransferCallbacks callbacks;
    HttpExec::SetHandoverCallbacks(callbacks);
    ASSERT_TRUE(callbacks.handoverInfoCallback);

    auto info = callbacks.handoverInfoCallback(nullptr);
    EXPECT_EQ(info.taskId, 0u);
    EXPECT_EQ(info.method, "init");
    EXPECT_EQ(info.requestUrl, "init");
}

HWTEST_F(HttpExecTest, SetHandoverInfoCallbackNull, TestSize.Level1)
{
    HttpOverCurl::TransferCallbacks callbacks;
    HttpExec::SetHandoverCallbacks(callbacks);
    ASSERT_TRUE(callbacks.setHandoverInfoCallback);

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);
    EXPECT_EQ(context.GetRequestHandoverInfo(), "no handover");

    HttpHandoverInfo handoverInfo;
    handoverInfo.handOverId = 200;
    handoverInfo.handOverNum = 5;
    callbacks.setHandoverInfoCallback(handoverInfo, nullptr);
    EXPECT_EQ(context.GetRequestHandoverInfo(), "no handover");

    callbacks.setHandoverInfoCallback(handoverInfo, &context);
    auto info = context.GetRequestHandoverInfo();
    EXPECT_NE(info, "no handover");
    EXPECT_NE(info.find("HandoverNum:5"), std::string::npos);
}
#endif // HTTP_HANDOVER_FEATURE
} // namespace
