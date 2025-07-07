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
#endif

using namespace OHOS::NetStack;
using namespace OHOS::NetStack::Http;

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
    auto handle = curl_easy_init();

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    EXPECT_TRUE(HttpExec::SetOption(handle, &context, context.GetCurlHeaderList()));
}

HWTEST_F(HttpExecTest, SetServerSSLCertOption001, TestSize.Level1)
{
    auto handle = curl_easy_init();

    napi_env env = nullptr;
    auto manager = std::make_shared<EventManager>();
    OHOS::NetStack::Http::RequestContext context(env, manager);

    EXPECT_TRUE(HttpExec::SetServerSSLCertOption(handle, &context));
}

#ifdef HTTP_MULTIPATH_CERT_ENABLE
HWTEST_F(HttpExecTest, LoadCaCertFromString001, TestSize.Level1)
{
    X509_STORE *store = X509_STORE_new();
    std::string dummy_root_ca_pem = "-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIICN29tj0e7AIwDQYJKoZIhvcNAQELBQAwgYoxCzAJBgNV
BAYTAkNOMRMwEQYDVQQDDApleGFtcGxlLmNuMRAwDgYDVQQKDAdDb21wYW55MREw
DwYDVQQLDAhEaXZpc2lvbjEOMAwGA1UECAwFQW5IdWkxDjAMBgNVBAcMBUhlRmVp
MSEwHwYJKoZIhvcNAQkBFhJleGFtcGxlQGV4YW1wbGUuY24wHhcNMjUwNzA4MDAy
NzIxWhcNMjgwNzA4MDAyNzIxWjBeMQswCQYDVQQGEwJDTjESMBAGA1UEAwwJMTI3
LjAuMC4xMQkwBwYDVQQKDAAxCTAHBgNVBAsMADEJMAcGA1UECAwAMQkwBwYDVQQH
DAAxDzANBgkqhkiG9w0BCQEWADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMvlHdoeGVrU8iBJZZLtRSXmwiTay0HFC0T9OYbMO4yQ5nTtB1z8/2IRMvyD
apsdUJ+zs1v0kX9R/NionqmivRi2n/w8ZnGrr096iAhvbKtonbzAnY3pN6GWr8R5
EQXaCc+aAS1yuVwxsxD/2gpIul0V+HDzdqq88CF9Tf7Sqq010MH2QHpolitAicK5
aNgz223RY5ZVD7I1UNrn8IK2f+VjgWex2H7VXSVpNbwx5qqLbZ9TsGjXioeanLSQ
1Xeg+3t1Vm9mkYt9vENA29FdXsC42iUo2dlqQRYUgG0rX9zSFZ/GZTXfODGFtmEV
VZjmcj9Jwuwr50c0x5DNxu1NaZMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAQLym
uMWI5yhAscuVd1p0SeNFDCmomzvxwq6WRsXD0y/BuZitB2oApAZt4Z5MkkJ6UgAd
jJjKn34QoRZCmrt0imudbmz5G0EIOnVp9KHcfBj3oqDz6v7MLR4ts8+8hAqnS4R/
HaM04AiC9VXT/JA3FsJQs+5gekx9GYOroI6AfFt0LiP5tkOOSx6rbW+hkCnrwxEC
YkLkXv0BPZcabhfTO9yxcQn5bPOQH6+G7/byeCTI4+RXbKMjOsk3hB3zpp1hiOko
P12OrbAl9UvZuzVft8x4ZT952EtDstdpLFLOgldgZEpLBdgyZLLhbgp/JcnQGB83
zRxV2brJWJBfxFyaew==
-----END CERTIFICATE-----";
    HttpExec::LoadCaCertFromString(store, dummy_root_ca_pem);

    // 从 PEM 读取证书用于验证
    BIO *bio = BIO_new_mem_buf(dummy_root_ca_pem.data(), dummy_root_ca_pem.size());
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    // 没有读取到证书，测试失败
    ASSERT_NE(cert, nullptr);

    // 配置 X509_STORE_CTX，执行验证
    X509_STORE_CTX ctx;
    X509_STORE_CTX_init(&ctx, store, cert, nullptr);

    // 默认允许自签名证书验证
    int verify_result = X509_verify_cert(&ctx);

    // 清理
    X509_STORE_CTX_cleanup(&ctx);
    X509_free(cert);
    X509_STORE_free(store);
    BIO_free(bio);

    // 预期验成功：1
    EXPECT_EQ(verify_result, 1);
}
#endif
} // namespace