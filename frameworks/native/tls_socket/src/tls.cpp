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

#include "tls.h"
#include "netstack_log.h"
namespace OHOS {
namespace NetStack {

TlsSecureOptions::TlsSecureOptions()
        :useRemoteCipherPrefer_(true)
{
}

void TlsSecureOptions::SetCa(const std::vector<std::string> &ca)
{
    caChain_ = ca;
}

void TlsSecureOptions::SetCert(const std::string &cert)
{
    cert_ = cert;
}

void TlsSecureOptions::SetKey(const std::string &key)
{
    key_ = key;
}

void TlsSecureOptions::SetPasswd(const std::string &passwd)
{
    passwd_ = passwd;
}

void TlsSecureOptions::SetProtocol(const std::vector<std::string> &Protocol)
{
    protocolChain_ = Protocol;
}

void TlsSecureOptions::SetUseRemoteCipherPrefer(bool useRemoteCipherPrefer)
{
    useRemoteCipherPrefer_ = useRemoteCipherPrefer;
}

void TlsSecureOptions::SetSignatureAlgorithms(const std::string &signatureAlgorithms)
{
    signatureAlgorithms_ = signatureAlgorithms;
}

void TlsSecureOptions::SetCipherSuite(const std::string &cipherSuite)
{
    cipherSuite_ = cipherSuite;
}

void TlsSecureOptions::SetCrl(const std::vector<std::string> &crl)
{
    crlChain_ = crl;
}

void TlsConnectOptions::SetAddress(const NetAddress &address)
{
    address_.SetAddress(address.GetAddress());
    address_.SetPort(address.GetPort());
    address_.SetFamilyBySaFamily(address.GetSaFamily());
}

void TlsConnectOptions::SetSecureOptions(const TlsSecureOptions &secureOptions)
{
    secureOptions_.SetKey(secureOptions.GetKey());
    secureOptions_.SetCa(secureOptions.GetCa());
    secureOptions_.SetCert(secureOptions.GetCert());
    secureOptions_.SetProtocol(secureOptions.GetProtocol());
    secureOptions_.SetCrl(secureOptions.GetCrl());
    secureOptions_.SetPasswd(secureOptions.GetPasswd());
    secureOptions_.SetSignatureAlgorithms(secureOptions.GetSignatureAlgorithms());
    secureOptions_.SetCipherSuite(secureOptions.GetCipherSuite());
    secureOptions_.SetUseRemoteCipherPrefer(secureOptions.GetUseRemoteCipherPrefer());
}

void TlsConnectOptions::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    alpnProtocols_ = alpnProtocols;
}

std::vector<std::string> TlsSecureOptions::GetCa() const
{
    return caChain_;
}

std::string TlsSecureOptions::GetCert() const
{
    return cert_;
}

std::string TlsSecureOptions::GetKey() const
{
    return key_;
}

std::vector<std::string> TlsSecureOptions::GetProtocol() const
{
    return protocolChain_;
}

std::vector<std::string> TlsSecureOptions::GetCrl() const
{
    return crlChain_;
}

std::string TlsSecureOptions::GetCipherSuite() const
{
    return cipherSuite_;
}

std::string TlsSecureOptions::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

bool TlsSecureOptions::GetUseRemoteCipherPrefer() const
{
    return useRemoteCipherPrefer_;
}

std::string TlsSecureOptions::GetPasswd() const
{
    return passwd_;
}

NetAddress TlsConnectOptions::GetAddress()
{
    return address_;
}

TlsSecureOptions TlsConnectOptions::GetTlsSecureOptions()
{
    return secureOptions_;
}

std::vector<std::string> TlsConnectOptions::GetAlpnProtocols()
{
    return alpnProtocols_;
}
} } // namespace OHOS::NetStack
