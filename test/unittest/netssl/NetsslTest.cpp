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
#include <iostream>

#include "cert_context.h"
#include "gtest/gtest.h"
#include "net_ssl.h"
#include "net_ssl_async_work.h"
#include "net_ssl_exec.h"
#include "net_ssl_module.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"

class NetsslTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

namespace {
using namespace testing::ext;
using namespace OHOS::NetStack::Ssl;

HWTEST_F(NetsslTest, CertVerifyTest001, TestSize.Level1)
{
    napi_env env = nullptr;
    CertContext context(env, nullptr);

    bool ret = SslExec::ExecVerify(&context);
    EXPECT_EQ(ret, false);
}

HWTEST_F(NetsslTest, NetStackVerifyCertificationTest001, TestSize.Level1)
{
    CertBlob *cert = nullptr;
    CertBlob *caCert = nullptr;

    uint32_t ret = NetStackVerifyCertification(cert);
    EXPECT_EQ(ret, SSL_X509_V_ERR_UNSPECIFIED);

    ret = NetStackVerifyCertification(cert, caCert);
    EXPECT_EQ(ret, SSL_X509_V_ERR_UNSPECIFIED);
}

HWTEST_F(NetsslTest, NetStackVerifyCertificationTest002, TestSize.Level1)
{
    CertBlob cert;
    CertBlob caCert;

    uint32_t verifyResult = 0;
    ProcessResult(verifyResult);
    EXPECT_EQ(verifyResult, SSL_NONE_ERR);

    verifyResult = 1;
    ProcessResult(verifyResult);
    EXPECT_EQ(verifyResult, SSL_X509_V_ERR_UNSPECIFIED);

    uint32_t ret = NetStackVerifyCertification(&cert);
    EXPECT_EQ(ret, SSL_X509_V_ERR_UNSPECIFIED);

    ret = NetStackVerifyCertification(&cert, &caCert);
    EXPECT_EQ(ret, SSL_X509_V_ERR_UNSPECIFIED);
}
} // namespace
