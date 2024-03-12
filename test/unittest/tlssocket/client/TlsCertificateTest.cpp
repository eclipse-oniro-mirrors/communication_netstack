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
#include <openssl/pem.h>
#include <string>

#define private public
#include "tls.h"
#include "TlsTest.h"
#include "tls_certificate.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
using namespace testing::ext;
} // namespace

class TlsCertificateTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsCertificateTest, CertificateTest001, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    bool isCertFromData = tlsCertificate.CertificateFromData(CLIENT_FILE, LOCAL_CERT);
    EXPECT_EQ(isCertFromData, true);
}

HWTEST_F(TlsCertificateTest, CertificateTest002, TestSize.Level2)
{
    std::string data = "";
    TLSCertificate tlsCertificate = TLSCertificate(data, EncodingFormat::DER, LOCAL_CERT);
    bool ret = tlsCertificate.CertificateFromDer(CLIENT_FILE, LOCAL_CERT);
    EXPECT_EQ(ret, false);
}

HWTEST_F(TlsCertificateTest, CertificateTest003, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, EncodingFormat::PEM, LOCAL_CERT);
    bool ret = tlsCertificate.CertificateFromPem(CA_CRT_FILE, LOCAL_CERT);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, CopyConstruction, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    TLSCertificate tlsCopy = TLSCertificate(tlsCertificate);
    bool isCertFromData = tlsCopy.CertificateFromData(CLIENT_FILE, LOCAL_CERT);
    EXPECT_EQ(isCertFromData, true);
}

HWTEST_F(TlsCertificateTest, AssignmentConstruction, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    TLSCertificate tlsCert = tlsCertificate;
    bool isCertFromData = tlsCert.CertificateFromData(CLIENT_FILE, LOCAL_CERT);
    EXPECT_EQ(isCertFromData, true);
}

HWTEST_F(TlsCertificateTest, GetLocalCertString, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    std::string localCert = tlsCertificate.GetLocalCertString();
    std::cout << "localCert:" << localCert << std::endl;
    EXPECT_NE(localCert.c_str(), nullptr);
}

HWTEST_F(TlsCertificateTest, CertificateFromPemTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    bool ret = tlsCertificate.CertificateFromPem(CERTIFICAT, LOCAL_CERT);
    EXPECT_FALSE(ret);
    ret = tlsCertificate.CertificateFromPem("", LOCAL_CERT);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, CertificateFromDerTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    bool ret = tlsCertificate.CertificateFromDer(CA_CRT_FILE, LOCAL_CERT);
    EXPECT_FALSE(ret);
    ret = tlsCertificate.CertificateFromDer("", LOCAL_CERT);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, GetSignatureAlgorithmTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    tlsCertificate.CertificateFromDer(CERTIFICAT, CA_CERT);
    std::string ret = tlsCertificate.GetSignatureAlgorithm();
    EXPECT_FALSE(ret.empty());
    TLSCertificate tlsCertificate2 = TLSCertificate("", LOCAL_CERT);
    ret = tlsCertificate2.GetSignatureAlgorithm();
    EXPECT_TRUE(ret.empty());
}

HWTEST_F(TlsCertificateTest, CaFromData, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CA_CRT_FILE, CA_CERT);
    bool isFilePath = tlsCertificate.CertificateFromData(CA_CRT_FILE, CA_CERT);

    BIO *bio = BIO_new_mem_buf(CA_CRT_FILE, -1);
    X509 *x509Ca = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    bool setLocalCertRawData = tlsCertificate.SetLocalCertRawData(x509Ca);
    EXPECT_TRUE(setLocalCertRawData);
    bool setX509Version = tlsCertificate.SetX509Version(x509Ca);
    EXPECT_TRUE(setX509Version);
    bool setSerialNumber = tlsCertificate.SetSerialNumber(x509Ca);
    EXPECT_TRUE(setSerialNumber);
    bool setNotValidTime = tlsCertificate.SetNotValidTime(x509Ca);
    EXPECT_TRUE(setNotValidTime);
    bool setSignatureAlgorithm = tlsCertificate.SetSignatureAlgorithm(x509Ca);
    EXPECT_TRUE(setSignatureAlgorithm);
    bool caCertToString = tlsCertificate.CaCertToString(x509Ca);
    EXPECT_TRUE(caCertToString);
    bool localCertToString = tlsCertificate.LocalCertToString(x509Ca);
    EXPECT_TRUE(localCertToString);

    BIO *bioCrt = BIO_new_mem_buf(CLIENT_FILE, -1);
    X509 *x509Crt = PEM_read_bio_X509(bioCrt, nullptr, nullptr, nullptr);
    BIO_free(bioCrt);
    bool analysisCert = tlsCertificate.AnalysisCertificate(CertType::LOCAL_CERT, x509Crt);
    EXPECT_TRUE(analysisCert);
    bool analysisCa = tlsCertificate.AnalysisCertificate(CertType::CA_CERT, x509Ca);
    EXPECT_TRUE(analysisCa);
    EXPECT_EQ(isFilePath, true);
}

HWTEST_F(TlsCertificateTest, AnalysisCertificateTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.AnalysisCertificate(CertType::LOCAL_CERT, x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, CaCertToStringTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.CaCertToString(x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, LocalCertToStringTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.LocalCertToString(x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, SetX509VersionTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.SetX509Version(x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, SetSerialNumberTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.SetSerialNumber(x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, SetNotValidTimeTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.SetNotValidTime(x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, SetSignatureAlgorithmTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.SetSignatureAlgorithm(x509);
    EXPECT_FALSE(ret);
}

HWTEST_F(TlsCertificateTest, SetLocalCertRawDataTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(CLIENT_FILE, LOCAL_CERT);
    X509 *x509 = nullptr;
    bool ret = tlsCertificate.SetLocalCertRawData(x509);
    EXPECT_FALSE(ret);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
