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

#include <fstream>
#include <cstring>

#include "gtest/gtest.h"
#include "openssl/ssl.h"

#include "tls_certificate.h"

namespace OHOS::NetStack::TlsSocket {
class TLSCertificateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void TLSCertificateTest::SetUpTestCase() {}
void TLSCertificateTest::TearDownTestCase() {}
void TLSCertificateTest::SetUp() {}
void TLSCertificateTest::TearDown() {}

static const char *PEM_CERT =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDiDCCAnCgAwIBAgIUfIbu2Fl2yRfHMjp3jPnZwQsG4nwwDQYJKoZIhvcNAQEL\n"
    "BQAwgYwxCzAJBgNVBAYTAlJVMRkwFwYDVQQIDBBTYWludC1QZXRlcnNidXJnMRkw\n"
    "FwYDVQQHDBBTYWludC1QZXRlcnNidXJnMSAwHgYDVQQKDBdIdWF3ZWkgVGVjaG5v\n"
    "bG9naWVzIEx0ZDEMMAoGA1UECwwDUiZEMRcwFQYDVQQDDA5IdWF3ZWkgUm9vdCBD\n"
    "QTAgFw0yMzEyMjkwNzQwMDNaGA8yMTIzMTIwNTA3NDAwM1owFzEVMBMGA1UEAwwM\n"
    "ZmFrZUZvclByb3h5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAscFh\n"
    "B11wXp5PyWqGE0a2a4lrYgcvNRuuK/mzw9y1TRy44e+77UqSpxglPbadk0GGQI6Q\n"
    "jmbk3CCUJ1Wi0uVGiRlLL2Z5moeHnLN+mbLjtt3xhSwZgfLanwM0wHdZBSRalXnI\n"
    "peOkR3MoiMqHs4ELW09kf1COOooIAS1arFH5q8EODgs8k5/fCoiawgx7rvM6V2G9\n"
    "4m6HHqsip0rS4RY3EE9a1w3q7uLXh773n/YwsfoRNd/3elch1MRbURzO8ser3vBV\n"
    "P8NB1YnoFSYyF6szIoasnswOZQRAE3c+kraMzEyYCNL4L1hEkDt2hQOXvJIWO6Nz\n"
    "mbmIBmlWpEovt8bFmQIDAQABo1QwUjAfBgNVHSMEGDAWgBRaTirB5B1uI7SOD5ei\n"
    "aMuEm4RyODAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DAXBgNVHREEEDAOggxmYWtl\n"
    "Rm9yUHJveHkwDQYJKoZIhvcNAQELBQADggEBAEwmj+al+eJIP83/Ug5rbYFVmlRu\n"
    "nnILNl0Sd18/faSKNuNLNUWEK8VgRs/8loTMeAnltSy63bai4fTJIEALWPvVFgbJ\n"
    "mjVsy+c7MYM1E1nAndfITAzJohRKZBaO9UQjF30ex7xr/TYOHX0rDpArme2Cj7TC\n"
    "ZkhlFrAVAyNf6DMfMdFNsevWjdOFz0nAzoDcvb27ilkwa8y4zXXYmyUjIQlBpIyX\n"
    "MCGLY1lzvE7qey26HPDi1Mnkcq0lZaYam7HbkY8OmgewcoiSXypqZnGcvUJ3DrBn\n"
    "yGToxaOr12CCNDkvs0fkLdXj9x6Ks9DEFPZvXNV0d8iZo+cbAR3B4tsuUHg=\n"
    "-----END CERTIFICATE-----\n";

HWTEST_F(TLSCertificateTest, TLSCertificateTest001, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("DATA", PEM, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest002, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("DATA", DER, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest003, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("DATA", PEM, LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest004, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("DATA", DER, LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest005, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("DATA", static_cast<EncodingFormat>(100), CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest006, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("DATA", static_cast<EncodingFormat>(100), LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest007, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("", PEM, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest008, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("", DER, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest009, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("", PEM, LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest010, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("", DER, LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest011, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("", static_cast<EncodingFormat>(100), CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest012, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate("", static_cast<EncodingFormat>(100), LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest013, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate(PEM_CERT, PEM, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest014, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate(PEM_CERT, DER, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest015, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate(PEM_CERT, PEM, LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest016, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate(PEM_CERT, DER, LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest017, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate(PEM_CERT, static_cast<EncodingFormat>(100), CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest018, testing::ext::TestSize.Level1)
{
    TLSCertificate certificate(PEM_CERT, static_cast<EncodingFormat>(100), LOCAL_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest019, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("./test.pem");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    TLSCertificate certificate("./test.pem", PEM, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest020, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("./test.pem");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    TLSCertificate certificate(PEM_CERT, DER, CA_CERT);
    EXPECT_EQ(certificate.GetLocalCertString(), "");
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest021, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("./test.pem");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    TLSCertificate certificate;
    EXPECT_TRUE(certificate.CertificateFromPem("./test.pem", CA_CERT));
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest022, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("./test.pem");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    TLSCertificate certificate;
    EXPECT_TRUE(certificate.CertificateFromPem("./test.pem", LOCAL_CERT));
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest023, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("/system/lib/test.der");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    TLSCertificate certificate;
    EXPECT_FALSE(certificate.CertificateFromDer("/system/lib/test.der", CA_CERT));
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest024, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("/system/lib/test.der");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    TLSCertificate certificate;
    EXPECT_FALSE(certificate.CertificateFromDer("/system/lib/test.der", LOCAL_CERT));
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest025, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("./test.pem");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    auto fp = fopen("./test.pem", "r");
    auto cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    unsigned char *der = nullptr;
    auto len = i2d_X509(cert, &der);
    fp = fopen("/system/lib/test.der", "wb");
    if (fp != nullptr) {
        fwrite(der, 1, len, fp);
        fclose(fp);
    }
    TLSCertificate certificate;
    EXPECT_FALSE(certificate.CertificateFromPem("/system/lib/test.der", LOCAL_CERT));
}

HWTEST_F(TLSCertificateTest, TLSCertificateTest026, testing::ext::TestSize.Level1)
{
    std::ofstream outfile;
    outfile.open("./test.pem");
    outfile.write(PEM_CERT, static_cast<std::streamsize>(strlen(PEM_CERT)));
    outfile.close();
    auto fp = fopen("./test.pem", "r");
    auto cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    unsigned char *der = nullptr;
    auto len = i2d_X509(cert, &der);
    fp = fopen("/system/lib/test.der", "wb");
    if (fp != nullptr) {
        fwrite(der, 1, len, fp);
        fclose(fp);
    }

    TLSCertificate certificate;
    EXPECT_FALSE(certificate.CertificateFromPem("/system/lib/test.der", CA_CERT));
}
} // namespace OHOS::NetStack::TlsSocket