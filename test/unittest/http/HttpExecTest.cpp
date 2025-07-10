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
MIIDazCCAlOgAwIBAgIUUkPBvZGXiOfpNTu6MGDlDw8OaLEwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAyMDUwODQyMDNaFw0yNTAy
MDQwODQyMDNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCenbm9Vs2F+Mu951dRqoQy68pP2OmIWbl+mFLbgydi
lRgmsdBuWM/qGJtXGOR77Z89uXv18hIrVNBv1Tt0DlGJmnO9i8AlRYhKj1lYsdnN
RBHItkOZI7s4+NSGqOqYbM0Jmo4pp66c4mwzMVuLLoO1+i5ROxROGa+b78hoQoCp
UvtBX81pX1ds6To22bqig2zmdGjHHFkNk3mQyyG2JeIm4q7bt25S/D3HpX7Vpkmq
S1jewXu0tzAul+tydzqziQE4XeV0Oz+QUT/VpiPile0xKqmJX3l+YbkvHSIlfeFM
JsM0ZngUkmKmFponIy0uZTY8VRnuRf7bs+FtFCDjf1BbAgMBAAGjUzBRMB0GA1Ud
DgQWBBR2f3W2xNpqseiAN81AmkbhSzQDVjAfBgNVHSMEGDAWgBR2f3W2xNpqseiA
N81AmkbhSzQDVjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCG
gybJtcyHNSOkvfa7FOVDGqKK2J+j51EGTINwPqf2oUF0sFJPNx0Rm+s7JBPb/EC1
70abbejtFOSBZMjoEMa5VFXDOAJ9bMILqk4owmnUWvkfVwLA5tRXxcVx34d02OLj
qIc9h0s7d2rbU1LOw3/8f4oVgDzcr8FMEWYG0y6h8g6NOUFky17wTODSgZIrWRxY
0fHpDe+jlQnxCoiAv7m3hGiNE0yquA4B4y4aduqyxNW1yQPxeHtrPeONJV6/8MIR
JxWsJPT2P9ao/DHCItMK1gEibmkATbHvpQfU/V75QoqVXY8GdYlLt0P247aiPyYr
As8jWsq731gdVsRCnGzE
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