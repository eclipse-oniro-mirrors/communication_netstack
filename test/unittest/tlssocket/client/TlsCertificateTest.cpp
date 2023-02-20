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
#include <openssl/pem.h>

#define private public
#include "tls.h"
#include "tls_certificate.h"

namespace OHOS {
namespace NetStack {
namespace {
using namespace testing::ext;
static char g_clientFile[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDezCCAmMCFD6h5R4QvySV9q9mC6s31qQFLX14MA0GCSqGSIb3DQEBCwUAMHgx\r\n"
"CzAJBgNVBAYTAkNOMQswCQYDVQQIDAJHRDELMAkGA1UEBwwCU1oxDDAKBgNVBAoM\r\n"
"A0NPTTEMMAoGA1UECwwDTlNQMQswCQYDVQQDDAJDQTEmMCQGCSqGSIb3DQEJARYX\r\n"
"emhhbmd6aGV3ZWkwMTAzQDE2My5jb20wHhcNMjIwNDI0MDIwMjU3WhcNMjMwNDI0\r\n"
"MDIwMjU3WjB8MQswCQYDVQQGEwJDTjELMAkGA1UECAwCR0QxCzAJBgNVBAcMAlNa\r\n"
"MQwwCgYDVQQKDANDT00xDDAKBgNVBAsMA05TUDEPMA0GA1UEAwwGQ0xJRU5UMSYw\r\n"
"JAYJKoZIhvcNAQkBFhd6aGFuZ3poZXdlaTAxMDNAMTYzLmNvbTCCASIwDQYJKoZI\r\n"
"hvcNAQEBBQADggEPADCCAQoCggEBAKlc63+j5C7tLoaecpdhzzZtLy8iNSi6oLHc\r\n"
"+bPib1XWz1zcQ4On5ncGuuLSV2Tyse4tSsDbPycd8b9Teq6gdGrvirtGXau82zAq\r\n"
"no+t0mxVtV1r0OkSe+hnIrYKxTE5UDeAM319MSxWlCR0bg0uEAuVBPQpld5A9PQT\r\n"
"YCLbv4cTwB0sIKupsnNbrn2AsAlCFd288XeuTN+N87m05cDkprAkqkCJfAtRnejV\r\n"
"k+vbS+H6toR3P9PVQJXC77oM7cDOjR8AwpkRRA890XUWoQLwhHXvDpGPwKK+lLnG\r\n"
"FswiaHy3silUIOidwk7E/81BOqXSk77oUG6UQrVilkmu6g79VssCAwEAATANBgkq\r\n"
"hkiG9w0BAQsFAAOCAQEAOeqp+hFVRs4YB3UjU/3bvAUFQLS97gapCp2lk6jS88jt\r\n"
"uNeyvwulOAtZEbcoIIvzzNxvBDOVibTJ6gZU9P9g0WyRu2RTgy+UggNwH8u8KZzM\r\n"
"DT8sxuoYvRcEWbOhlNQgACa7AlQSLQifo8nvEMS2i9o8WHoHu42MRDYOHYVIwWXH\r\n"
"h6mZzfo+zrPyv3NFlwlWqaNiTGgnGCXzlVK3p5YYqLbNVYpy0U5FBxQ7fITsqcbK\r\n"
"PusAAEZzPxm8Epo647M28gNkdEEM/7bqhSTJO+jfkojgyQt2ghlw+NGCmG4dJGZb\r\n"
"yA7Z3PBj8aqEwmRUF8SAR1bxWBGk2IYRwgStuwvusg==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_caCrtFile[] =
"Certificate:\r\n"
"   Data:\r\n"
"        Version: 3 (0x2)\r\n"
"        Serial Number: 1 (0x1)\r\n"
"        Signature Algorithm: sha256WithRSAEncryption\r\n"
"        Issuer: C=CN, ST=beijing, O=ahaha Inc, OU=Root CA, CN=ahaha CA\r\n"
"        Validity\r\n"
"            Not Before: Aug 23 07:33:55 2022 GMT\r\n"
"            Not After : Aug 23 07:33:55 2023 GMT\r\n"
"        Subject: C=CN, ST=beijing, O=ahaha Inc, OU=Root CA, CN=ahaha CA\r\n"
"        Subject Public Key Info:\r\n"
"            Public Key Algorithm: rsaEncryption\r\n"
"                RSA Public-Key: (2048 bit)\r\n"
"                Modulus:\r\n"
"                    00:9d:df:68:f7:7b:78:0b:21:f3:6f:24:60:ef:ce:\r\n"
"                    02:90:24:df:c4:d3:f3:e4:26:6c:c7:12:bf:28:cd:\r\n"
"                    38:2d:3f:ab:76:11:64:ce:6b:f6:07:fd:35:1e:b9:\r\n"
"                    ec:22:72:03:4d:eb:d2:94:49:2d:82:44:6c:72:59:\r\n"
"                    14:ab:e7:0c:72:32:3e:ad:fa:9d:52:da:24:8d:e9:\r\n"
"                    a4:10:d7:dd:34:66:df:7e:e0:0e:66:53:8b:ee:91:\r\n"
"                    07:9a:ce:2a:85:25:09:77:3d:5f:75:1c:a1:b3:ab:\r\n"
"                    86:3b:21:28:f8:43:aa:f0:0b:7d:4d:f9:df:85:33:\r\n"
"                    4a:3b:ff:e4:03:59:25:62:a1:e9:da:92:63:02:93:\r\n"
"                    bd:f9:df:6e:c6:57:a7:d2:e6:7b:37:14:a9:ba:69:\r\n"
"                    71:0c:c5:4f:66:fe:67:66:5c:8d:d7:04:4d:d8:f3:\r\n"
"                    0b:c0:0b:7d:49:eb:68:94:28:f6:31:0f:0d:2a:03:\r\n"
"                    70:a7:97:f9:38:90:36:d4:4b:39:4b:53:a5:2c:32:\r\n"
"                    72:f2:41:86:32:13:3c:40:2d:3f:e8:63:d3:8c:8a:\r\n"
"                    83:79:d3:20:f6:bc:cd:97:3e:94:91:4e:3c:74:8d:\r\n"
"                    9a:fa:29:de:c4:a5:f7:e1:e2:06:55:e6:6c:41:0f:\r\n"
"                    60:3b:90:de:3a:84:ef:3a:77:79:27:00:23:55:66:\r\n"
"                    ca:81\r\n"
"                Exponent: 65537 (0x10001)\r\n"
"        X509v3 extensions:\r\n"
"            X509v3 Basic Constraints:\r\n"
"                CA:TRUE\r\n"
"        Signature Algorithm: sha256WithRSAEncryption\r\n"
"            61:3e:39:71:7f:b1:50:dd:71:97:cd:dc:a9:4b:72:96:0a:12:\r\n"
"            c1:18:fd:35:b5:e0:97:1b:76:58:22:8d:cd:75:51:0f:ba:04:\r\n"
"            00:94:6a:46:d5:3a:c5:ac:ea:7d:9c:ec:6f:19:b6:f1:2b:06:\r\n"
"            e9:bb:cb:49:24:34:0b:55:bd:02:19:24:19:85:bb:e4:a4:80:\r\n"
"            f4:d6:90:82:7e:81:5c:9b:89:d4:15:ed:3a:b7:a2:37:59:40:\r\n"
"            db:b4:18:25:90:2e:ae:82:f9:a8:0c:9d:bd:c7:8c:54:85:ed:\r\n"
"            07:d1:70:1d:ee:a1:92:bd:12:97:83:4d:9e:9e:b7:01:b5:56:\r\n"
"            a5:1f:31:6e:a1:48:68:a4:4f:1c:fa:b0:38:27:47:12:eb:55:\r\n"
"            a3:45:f7:e3:18:ba:d7:85:3c:1f:2c:1e:5e:38:75:5e:80:8a:\r\n"
"            fd:1c:84:4f:9b:ef:85:b7:79:89:d7:43:eb:d4:fb:c5:51:5b:\r\n"
"            84:6f:0e:06:32:54:13:e4:a7:e2:20:2d:b8:fa:2d:09:f8:8f:\r\n"
"            dd:01:19:39:cc:23:c0:d1:39:19:9a:f7:7c:53:63:bf:ea:be:\r\n"
"            04:9b:af:3e:6e:1e:77:c8:b9:0b:78:e9:0e:62:a7:51:db:1e:\r\n"
"            c0:63:4d:4d:14:ff:ca:44:7f:15:e4:fa:98:1e:3d:58:c2:b6:\r\n"
"            5a:64:68:d0\r\n"
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDazCCAlOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJDTjEQ\r\n"
"MA4GA1UECAwHYmVpamluZzEdMBsGA1UECgwUR2xvYmFsIEdvb2dsZSBDQSBJbmMx\r\n"
"EDAOBgNVBAsMB1Jvb3QgQ0ExHjAcBgNVBAMMFUdsb2JhbCBHb29nbGUgUm9vdCBD\r\n"
"QTAeFw0yMjA4MjMwNzMzNTVaFw0yMzA4MjMwNzMzNTVaMHAxCzAJBgNVBAYTAkNO\r\n"
"MRAwDgYDVQQIDAdiZWlqaW5nMR0wGwYDVQQKDBRHbG9iYWwgR29vZ2xlIENBIElu\r\n"
"YzEQMA4GA1UECwwHUm9vdCBDQTEeMBwGA1UEAwwVR2xvYmFsIEdvb2dsZSBSb290\r\n"
"IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnd9o93t4CyHzbyRg\r\n"
"784CkCTfxNPz5CZsxxK/KM04LT+rdhFkzmv2B/01HrnsInIDTevSlEktgkRsclkU\r\n"
"q+cMcjI+rfqdUtokjemkENfdNGbffuAOZlOL7pEHms4qhSUJdz1fdRyhs6uGOyEo\r\n"
"+EOq8At9TfnfhTNKO//kA1klYqHp2pJjApO9+d9uxlen0uZ7NxSpumlxDMVPZv5n\r\n"
"ZlyN1wRN2PMLwAt9SetolCj2MQ8NKgNwp5f5OJA21Es5S1OlLDJy8kGGMhM8QC0/\r\n"
"6GPTjIqDedMg9rzNlz6UkU48dI2a+inexKX34eIGVeZsQQ9gO5DeOoTvOnd5JwAj\r\n"
"VWbKgQIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBh\r\n"
"Pjlxf7FQ3XGXzdypS3KWChLBGP01teCXG3ZYIo3NdVEPugQAlGpG1TrFrOp9nOxv\r\n"
"GbbxKwbpu8tJJDQLVb0CGSQZhbvkpID01pCCfoFcm4nUFe06t6I3WUDbtBglkC6u\r\n"
"gvmoDJ29x4xUhe0H0XAd7qGSvRKXg02enrcBtValHzFuoUhopE8c+rA4J0cS61Wj\r\n"
"RffjGLrXhTwfLB5eOHVegIr9HIRPm++Ft3mJ10Pr1PvFUVuEbw4GMlQT5KfiIC24\r\n"
"+i0J+I/dARk5zCPA0TkZmvd8U2O/6r4Em68+bh53yLkLeOkOYqdR2x7AY01NFP/K\r\n"
"RH8V5PqYHj1YwrZaZGjQ\r\n"
"-----END CERTIFICATE-----\r\n";
} // namespace

class TlsCertificateTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp() {}

    virtual void TearDown() {}
};

HWTEST_F(TlsCertificateTest, CertificateTest, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(g_clientFile, LOCAL_CERT);
    bool isCertFromData = tlsCertificate.CertificateFromData(g_clientFile, LOCAL_CERT);
    EXPECT_EQ(isCertFromData, true);
}

HWTEST_F(TlsCertificateTest, CopyConstruction, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(g_clientFile, LOCAL_CERT);
    TLSCertificate tlsCopy = TLSCertificate(tlsCertificate);
    bool isCertFromData = tlsCopy.CertificateFromData(g_clientFile, LOCAL_CERT);
    EXPECT_EQ(isCertFromData, true);
}

HWTEST_F(TlsCertificateTest, AssignmentConstruction, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(g_clientFile, LOCAL_CERT);
    TLSCertificate tlsCert = tlsCertificate;
    bool isCertFromData = tlsCert.CertificateFromData(g_clientFile, LOCAL_CERT);
    EXPECT_EQ(isCertFromData, true);
}

HWTEST_F(TlsCertificateTest, GetLocalCertString, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(g_clientFile, LOCAL_CERT);
    std::string localCert = tlsCertificate.GetLocalCertString();
    std::cout << "localCert:" << localCert << std::endl;
    EXPECT_NE(localCert.c_str(), nullptr);
}

HWTEST_F(TlsCertificateTest, CaFromData, TestSize.Level2)
{
    TLSCertificate tlsCertificate = TLSCertificate(g_caCrtFile, CA_CERT);
    bool isFilePath = tlsCertificate.CertificateFromData(g_caCrtFile, CA_CERT);

    BIO *bio = BIO_new_mem_buf(g_caCrtFile, -1);
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

    BIO *bioCrt = BIO_new_mem_buf(g_clientFile, -1);
    X509 *x509Crt = PEM_read_bio_X509(bioCrt, nullptr, nullptr, nullptr);
    BIO_free(bioCrt);
    bool analysisCert = tlsCertificate.AnalysisCertificate(CertType::LOCAL_CERT, x509Crt);
    EXPECT_TRUE(analysisCert);
    bool analysisCa = tlsCertificate.AnalysisCertificate(CertType::CA_CERT, x509Ca);
    EXPECT_TRUE(analysisCa);
    EXPECT_EQ(isFilePath, true);
}
} // namespace NetStack
} // namespace OHOS
