/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include "gtest/gtest.h"

#define private public
#include "tls_key.h"

namespace OHOS::NetStack::TlsSocket {
class TLSKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TLSKeyTest::SetUpTestCase() {}
void TLSKeyTest::TearDownTestCase() {}
void TLSKeyTest::SetUp() {}
void TLSKeyTest::TearDown() {}

HWTEST_F(TLSKeyTest, TLSKeyTestt001, testing::ext::TestSize.Level1)
{
    TLSKey key;
    TLSKey other;
    key = other;
    EXPECT_EQ(key.opaque_, nullptr);
    EXPECT_EQ(key.rsa_, nullptr);
    EXPECT_EQ(key.dsa_, nullptr);
    EXPECT_EQ(key.dh_, nullptr);
    EXPECT_EQ(key.ec_, nullptr);
    EXPECT_EQ(key.genericKey_, nullptr);
    other.rsa_ = RSA_new();
    other.dsa_ = DSA_new();
    other.dh_ = DH_new();
    other.ec_ = EC_KEY_new();
    other.genericKey_ = EVP_PKEY_new();
    key = other;
    EXPECT_NE(key.rsa_, nullptr);
    EXPECT_NE(key.dsa_, nullptr);
    EXPECT_NE(key.dh_, nullptr);
    EXPECT_NE(key.ec_, nullptr);
    EXPECT_NE(key.genericKey_, nullptr);
}
} // namespace OHOS::NetStack::TlsSocket
