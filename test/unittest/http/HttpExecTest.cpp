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
#ifdef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

struct SSL_CTX_deleter {
    void operator()(SSL_CTX* p) const { SSL_CTX_free(p); }
};
struct X509_STORE_CTX_deleter {
    void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_cleanup(p); }
};
struct BIO_deleter {
    void operator()(BIO* p) const { BIO_free(p); }
};
struct X509_deleter {
    void operator()(X509* p) const { X509_free(p); }
};
 
using unique_SSL_CTX = std::unique_ptr<SSL_CTX, SSL_CTX_deleter>;
using unique_X509_STORE_CTX = std::unique_ptr<X509_STORE_CTX, X509_STORE_CTX_deleter>;
using unique_BIO = std::unique_ptr<BIO, BIO_deleter>;
using unique_X509 = std::unique_ptr<X509, X509_deleter>;
#endif

using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Http;

struct CURL_deleter {
    void operator()(CURL* p) const { curl_easy_cleanup(p); }
};
using unique_CURL = std::unique_ptr<CURL, CURL_deleter>;

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
} // namespace