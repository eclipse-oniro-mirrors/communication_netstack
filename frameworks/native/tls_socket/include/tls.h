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

#ifndef COMMUNICATIONNETSTACK_TLS_H
#define COMMUNICATIONNETSTACK_TLS_H

#include <vector>
#include "net_address.h"

namespace OHOS {
namespace NetStack {

using Handle = void *;
constexpr int MAX_BUF_LEN = 1024;

class TlsSecureOptions {
public:

    TlsSecureOptions();

    ~TlsSecureOptions() = default;

    void SetCa(const std::vector<std::string> &ca);

    void SetCert(const std::string &cert);

    void SetKey(const std::string &key);

    void SetPasswd(const std::string &passwd);

    void SetProtocol(const std::vector<std::string> &Protocol);

    void SetUseRemoteCipherPrefer(bool useRemoteCipherPrefer);

    void SetSignatureAlgorithms(const std::string &signatureAlgorithms);

    void SetCipherSuite(const std::string &cipherSuite);

    void SetCrl(const std::vector<std::string> &crl);

    [[nodiscard]] std::vector<std::string> GetCa() const;

    [[nodiscard]] std::string GetCert() const;

    [[nodiscard]] std::string GetKey() const;

    [[nodiscard]] std::vector<std::string> GetProtocol() const;

    [[nodiscard]] std::vector<std::string> GetCrl() const;

    [[nodiscard]] std::string GetPasswd() const;

    [[nodiscard]] std::string GetSignatureAlgorithms() const;

    [[nodiscard]] std::string GetCipherSuite() const;

    [[nodiscard]] bool GetUseRemoteCipherPrefer() const;

private:
    std::vector<std::string> caChain_;
    std::string cert_;
    std::string key_;
    std::string passwd_;
    std::vector<std::string> protocolChain_;
    bool useRemoteCipherPrefer_ = false;
    std::string signatureAlgorithms_;
    std::string cipherSuite_;
    std::vector<std::string> crlChain_;
};

class TlsConnectOptions {
public:
    void SetAddress(const NetAddress &address);

    void SetSecureOptions(const TlsSecureOptions &secureOptions);

    void SetAlpnProtocols(const std::vector<std::string> &alpnProtocols);

    NetAddress GetAddress();

    TlsSecureOptions GetTlsSecureOptions();

    std::vector<std::string> GetAlpnProtocols();

private:
    NetAddress address_;
    TlsSecureOptions secureOptions_;
    std::vector<std::string> alpnProtocols_;
};

struct CipherSuite {
    unsigned long cipherId_;
    std::string cipherName_;
};

enum TlsMode {
    UNENCRYPTED_MODE,
    SSL_CLIENT_MODE,
    SSL_SERVER_MODE
};

enum PeerVerifyMode {
    VERIFY_NONE,
    QUERY_PEER,
    VERIFY_PEER,
    AUTO_VERIFY_PEER
};

enum KeyType {
    PRIVATE_KEY,
    PUBLIC_KEY
};

enum CertType {
    CA_CERT,
    LOCAL_CERT
};

enum EncodingFormat {
    PEM,
    DER
};

enum KeyAlgorithm {
    OPAQUE,
    ALGORITHM_RSA,
    ALGORITHM_DSA,
    ALGORITHM_EC,
    ALGORITHM_DH
};

enum AlternativeNameEntryType {
    EMAIL_ENTRY,
    DNS_ENTRY,
    IPADDRESS_ENTRY
};

enum OpenMode {
    NOT_OPEN,
    READ_ONLY,
    WRITE_ONLY,
    READ_WRITE = READ_ONLY | WRITE_ONLY,
    APPEND,
    TRUNCATE,
    TEXT,
    UNBUFFERED,
    NEW_ONLY,
    EXISTION_ONLY
};

enum NetworkLayerProtocol {
    IPV4_PROTOCOL,
    IPV6_PROTOCOL,
    ANY_IP_PROTOCOL,
    UNKNOW_NETWORK_LAYER_PROTOCOL = -1
};

enum class ImplementedClass {
    KEY,
    CERTIFICATE,
    SOCKET,
    DIFFIE_HELLMAN,
    ELLIPTIC_CURVE
};

enum class SupportedFeature {
    CERTIFICATE_VERIFICATION,
    CLIENT_SIDE_ALPN,
    SERVER_SIDE_ALPN,
    OCSP,
    PSK,
    SESSION_TICKET,
    ALERTS
};

enum TlsOptions {
    SSL_OPTION_DISABLE_EMPTY_FRAGMENTS = 0x01,
    SSL_OPTION_DISABLE_SESSION_TICKETS = 0x02,
    SSL_OPTION_DISABLE_COMPRESSION = 0x04,
    SSL_OPTION_DISABLE_SERVER_NAME_INDICATION = 0x08,
    SSL_OPTION_DISABLE_LEGACY_RENEGOTIATION = 0x10,
    SSL_OPTION_DISABLE_SESSION_SHARING = 0x20,
    SSL_OPTION_DISABLE_SESSION_PERSISTENCE = 0x40,
    SSL_OPTION_DISABLE_SERVER_CIPHER_PREFERENCE = 0x80
};

enum TLSProtocol {
    TLS_V1_2,
    TLS_V1_3,
    UNKNOW_PROTOCOL
};

enum class Cipher {
    DES_CBC,
    DES_EDE3_CBC,
    RC2_CBC,
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC
};
} } // namespace OHOS::NetStack
#endif // COMMUNICATIONNETSTACK_TLS_H
