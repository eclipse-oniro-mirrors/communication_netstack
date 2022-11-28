/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>
#include <string>

#include "tls_key.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace {
using namespace testing::ext;
static char g_keyFile[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEowIBAAKCAQEAqVzrf6PkLu0uhp5yl2HPNm0vLyI1KLqgsdz5s+JvVdbPXNxD\r\n"
"g6fmdwa64tJXZPKx7i1KwNs/Jx3xv1N6rqB0au+Ku0Zdq7zbMCqej63SbFW1XWvQ\r\n"
"6RJ76GcitgrFMTlQN4AzfX0xLFaUJHRuDS4QC5UE9CmV3kD09BNgItu/hxPAHSwg\r\n"
"q6myc1uufYCwCUIV3bzxd65M343zubTlwOSmsCSqQIl8C1Gd6NWT69tL4fq2hHc/\r\n"
"09VAlcLvugztwM6NHwDCmRFEDz3RdRahAvCEde8OkY/Aor6UucYWzCJofLeyKVQg\r\n"
"6J3CTsT/zUE6pdKTvuhQbpRCtWKWSa7qDv1WywIDAQABAoIBAFGpbCPvcmbuFjDy\r\n"
"1W4Iy1EC9G1VoSwyUKlyUzRZSjWpjfLIggVJP+bEZ/hWU61pGEIvtIupK5pA5f/K\r\n"
"0KzC0V9+gPYrx563QTjIVAwTVBLIgNq60dCQCQ7WK/Z62voRGIyqVCl94+ftFyE8\r\n"
"wpO4UiRDhk/0fT7dMz882G32ZzNJmY9eHu+yOaRctJW2gRBROHpQfDGBCz7w8s2j\r\n"
"ulIcnvwGOrvVllsL+vgY95M0LOq0W8ObbUSlawTnNTSRxFL68Hz5EaVJ19EYvEcC\r\n"
"eWnpEqIfF8OhQ+mYbdrAutXCkqJLz3rdu5P2Lbk5Ht5ETfr7rtUzvb4+ExIcxVOs\r\n"
"eys8EgECgYEA29tTxJOy2Cb4DKB9KwTErD1sFt9Ed+Z/A3RGmnM+/h75DHccqS8n\r\n"
"g9DpvHVMcMWYFVYGlEHC1F+bupM9CgxqQcVhGk/ysJ5kXF6lSTnOQxORnku3HXnV\r\n"
"4QzgKtLfHbukW1Y2RZM3aCz+Hg+bJrpacWyWZ4tRWNYsO58JRaubZjsCgYEAxTSP\r\n"
"yUBleQejl5qO76PGUUs2W8+GPr492NJGb63mEiM1zTYLVN0uuDJ2JixzHb6o1NXZ\r\n"
"6i00pSksT3+s0eiBTRnF6BJ0y/8J07ZnfQQXRAP8ypiZtd3jdOnUxEHfBw2QaIdP\r\n"
"tVdUc2mpIhosAYT9sWpHYvlUqTCdeLwhkYfgeLECgYBoajjVcmQM3i0OKiZoCOKy\r\n"
"/pTYI/8rho+p/04MylEPdXxIXEWDYD6/DrgDZh4ArQc2kt2bCcRTAnk+WfEyVYUd\r\n"
"aXVdfry+/uqhJ94N8eMw3hlZeZIk8JkQQgIwtGd8goJjUoWB85Hr6vphIn5IHVcY\r\n"
"6T5hPLxMmaL2SeioawDpwwKBgQCFXjDH6Hc3zQTEKND2HIqou/b9THH7yOlG056z\r\n"
"NKZeKdXe/OfY8uT/yZDB7FnGCgVgO2huyTfLYvcGpNAZ/eZEYGPJuYGn3MmmlruS\r\n"
"fsvFQfUahu2dY3zKusEcIXhV6sR5DNnJSFBi5VhvKcgNFwYDkF7K/thUu/4jgwgo\r\n"
"xf33YQKBgDQffkP1jWqT/pzlVLFtF85/3eCC/uedBfxXknVMrWE+CM/Vsx9cvBZw\r\n"
"hi15LA5+hEdbgvj87hmMiCOc75e0oz2Rd12ZoRlBVfbncH9ngfqBNQElM7Bueqoc\r\n"
"JOpKV+gw0gQtiu4beIdFnYsdZoZwrTjC4rW7OI0WYoLJabMFFh3I\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
} // namespace

class TlsKeyTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsKeyTest, AlgorithmTest, TestSize.Level2)
{
    SecureData structureData(g_keyFile);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    TLSKey tlsKey = TLSKey(structureData, ALGORITHM_RSA, keyPass);
    KeyAlgorithm algorithm = tlsKey.Algorithm();
    EXPECT_EQ(algorithm, ALGORITHM_RSA);
}

HWTEST_F(TlsKeyTest, CopyConstruction, TestSize.Level2)
{
    SecureData structureData(g_keyFile);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    TLSKey tlsKey = TLSKey(structureData, ALGORITHM_RSA, keyPass);
    TLSKey tlsKeyCopy = TLSKey(tlsKey);
    KeyAlgorithm algorithm = tlsKeyCopy.Algorithm();
    EXPECT_EQ(algorithm, ALGORITHM_RSA);
}

HWTEST_F(TlsKeyTest, AssignmentConstruction, TestSize.Level2)
{
    SecureData structureData(g_keyFile);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    TLSKey tlsKey = TLSKey(structureData, ALGORITHM_RSA, keyPass);
    TLSKey key = tlsKey;
    KeyAlgorithm algorithm = key.Algorithm();
    EXPECT_EQ(algorithm, ALGORITHM_RSA);
}

HWTEST_F(TlsKeyTest, HandleTest, TestSize.Level2)
{
    SecureData structureData(g_keyFile);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    TLSKey tlsKey = TLSKey(structureData, ALGORITHM_RSA, keyPass);
    Handle handle = tlsKey.handle();
    EXPECT_NE(handle, nullptr);
}

HWTEST_F(TlsKeyTest, GetKeyPassTest, TestSize.Level2)
{
    SecureData structureData(g_keyFile);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    TLSKey tlsKey = TLSKey(structureData, ALGORITHM_RSA, keyPass);
    SecureData getKeyPass = tlsKey.GetKeyPass();
    EXPECT_EQ(getKeyPass.Length(), keyPass.Length());
}

HWTEST_F(TlsKeyTest, GetKeyDataTest, TestSize.Level2)
{
    SecureData structureData(g_keyFile);
    std::string keyPassStr = "";
    SecureData keyPass(keyPassStr);
    TLSKey tlsKey = TLSKey(structureData, ALGORITHM_RSA, keyPass);
    SecureData getKeyData= tlsKey.GetKeyPass();
    EXPECT_NE(static_cast<uint32_t>(0), structureData.Length());
}
} // namespace NetStack
} // namespace OHOS