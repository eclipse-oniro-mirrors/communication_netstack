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

#include "tls_connect_context.h"

#include <cstdint>
#include <string>
#include <vector>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace {
static constexpr const char *CHECK_SERVER_IDENTITY = "checkServerIdentity";
static constexpr const char *ALPN_PROTOCOLS = "ALPNProtocols";
static constexpr const char *SECURE_OPTIONS = "secureOptions";
static constexpr const char *CA_NAME = "ca";
static constexpr const char *CERT_NAME = "cert";
static constexpr const char *KEY_NAME = "key";
static constexpr const char *PASSWD_NAME = "passwd";
static constexpr const char *PROTOCOLS_NAME = "protocols";
static constexpr const char *SIGNATURE_ALGORITHMS = "signatureAlgorithms";
static constexpr const char *USE_REMOTE_CIPHER_PREFER = "useRemoteCipherPrefer";
static constexpr const char *CIPHER_SUITES = "cipherSuites";
static constexpr const char *CRL_NAME = "crl";
static constexpr const char *ADDRESS_NAME = "address";
static constexpr const char *FAMILY_NAME = "family";
static constexpr const char *PORT_NAME = "port";

bool ReadNecessaryOptions(napi_env env, napi_value *params, napi_value secureOptions, TLSSecureOptions &secureOption)
{
    if (!NapiUtils::HasNamedProperty(env, secureOptions, CA_NAME)) {
        return false;
    }
    napi_value caVector = NapiUtils::GetNamedProperty(env, secureOptions, CA_NAME);
    uint32_t arrayLong = NapiUtils::GetArrayLength(env, caVector);
    napi_value element = nullptr;
    std::vector<std::string> caVec;
    for (uint32_t i = 0; i < arrayLong; i++) {
        element = NapiUtils::GetArrayElement(env, caVector, i);
        std::string ca = NapiUtils::GetStringFromValueUtf8(env, element);
        caVec.push_back(ca);
    }
    secureOption.SetCaChain(caVec);

    if (!NapiUtils::HasNamedProperty(env, secureOptions, KEY_NAME)) {
        return false;
    }
    std::string key = NapiUtils::GetStringPropertyUtf8(env, secureOptions, KEY_NAME);
    secureOption.SetKey(key);

    if (!NapiUtils::HasNamedProperty(env, secureOptions, CERT_NAME)) {
        return false;
    }
    std::string cert = NapiUtils::GetStringPropertyUtf8(env, secureOptions, CERT_NAME);
    secureOption.SetCert(cert);
    return true;
}
} // namespace
TLSConnectContext::TLSConnectContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void TLSConnectContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    connectOptions_ = ReadTLSConnectOptions(GetEnv(), params);

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[ARG_INDEX_1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool TLSConnectContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_object) {
            NETSTACK_LOGE("tlsConnectContext first param is not object");
            return false;
        }
        return true;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_object) {
            NETSTACK_LOGE("tls ConnectContext first param is not object");
            return false;
        }
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_1]) != napi_function) {
            NETSTACK_LOGE(" tls ConnectContext second param is not function");
            return false;
        }
        return true;
    }
    return false;
}

TLSConnectOptions TLSConnectContext::ReadTLSConnectOptions(napi_env env, napi_value *params)
{
    TLSConnectOptions options;
    NetAddress address = ReadNetAddress(GetEnv(), params);
    TLSSecureOptions secureOption = ReadTLSSecureOptions(GetEnv(), params);
    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], CHECK_SERVER_IDENTITY)) {
        napi_value checkServerIdentity = NapiUtils::GetNamedProperty(GetEnv(), params[0], CHECK_SERVER_IDENTITY);
        if (checkCallback_ != nullptr) {
            (void)napi_delete_reference(GetEnv(), checkCallback_);
        }
        napi_create_reference(GetEnv(), checkServerIdentity, 1, &checkCallback_);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], ALPN_PROTOCOLS)) {
        napi_value alpnProtocols = NapiUtils::GetNamedProperty(GetEnv(), params[0], ALPN_PROTOCOLS);
        uint32_t arrayLength = NapiUtils::GetArrayLength(GetEnv(), alpnProtocols);
        napi_value elementValue = nullptr;
        std::vector<std::string> alpnProtocolVec;
        for (uint32_t i = 0; i < arrayLength; i++) {
            elementValue = NapiUtils::GetArrayElement(GetEnv(), alpnProtocols, i);
            std::string alpnProtocol = NapiUtils::GetStringFromValueUtf8(GetEnv(), elementValue);
            alpnProtocolVec.push_back(alpnProtocol);
        }
        options.SetAlpnProtocols(alpnProtocolVec);
    }
    NETSTACK_LOGI("ConnectContext::ReadTLSConnectOptions(napi_env env, napi_value *params) end");
    return options;
}

TLSSecureOptions TLSConnectContext::ReadTLSSecureOptions(napi_env env, napi_value *params)
{
    TLSSecureOptions secureOption;

    if (!NapiUtils::HasNamedProperty(GetEnv(), params[ARG_INDEX_0], SECURE_OPTIONS)) {
        return secureOption;
    }
    napi_value secureOptions = NapiUtils::GetNamedProperty(GetEnv(), params[ARG_INDEX_0], SECURE_OPTIONS);
    if (!ReadNecessaryOptions(env, params, secureOptions, secureOption)) {
        return secureOption;
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, PASSWD_NAME)) {
        secureOption.SetKeyPass(NapiUtils::GetStringPropertyUtf8(env, secureOptions, PASSWD_NAME));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, PROTOCOLS_NAME)) {
        napi_value protocolVector = NapiUtils::GetNamedProperty(env, secureOptions, PROTOCOLS_NAME);
        uint32_t num = NapiUtils::GetArrayLength(GetEnv(), protocolVector);
        napi_value element = nullptr;
        std::vector<std::string> protocolVec;
        for (uint32_t i = 0; i < num; i++) {
            element = NapiUtils::GetArrayElement(GetEnv(), protocolVector, i);
            std::string protocol = NapiUtils::GetStringFromValueUtf8(GetEnv(), element);
            protocolVec.push_back(protocol);
        }
        secureOption.SetProtocolChain(protocolVec);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, SIGNATURE_ALGORITHMS)) {
        std::string signatureAlgorithms = NapiUtils::GetStringPropertyUtf8(env, secureOptions, SIGNATURE_ALGORITHMS);
        secureOption.SetSignatureAlgorithms(signatureAlgorithms);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, USE_REMOTE_CIPHER_PREFER)) {
        bool useRemoteCipherPrefer = NapiUtils::GetBooleanProperty(env, secureOptions, USE_REMOTE_CIPHER_PREFER);
        secureOption.SetUseRemoteCipherPrefer(useRemoteCipherPrefer);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, CIPHER_SUITES)) {
        std::string cipherSuites = NapiUtils::GetStringPropertyUtf8(env, secureOptions, CIPHER_SUITES);
        secureOption.SetCipherSuite(cipherSuites);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, CRL_NAME)) {
        napi_value crlVector = NapiUtils::GetNamedProperty(env, secureOptions, CRL_NAME);
        uint32_t num = NapiUtils::GetArrayLength(GetEnv(), crlVector);
        napi_value element = nullptr;
        std::vector<std::string> crlVec;
        for (uint32_t i = 0; i < num; i++) {
            element = NapiUtils::GetArrayElement(GetEnv(), crlVector, i);
            std::string crl = NapiUtils::GetStringFromValueUtf8(GetEnv(), element);
            crlVec.push_back(crl);
        }
        secureOption.SetCrlChain(crlVec);
    }
    return secureOption;
}

NetAddress TLSConnectContext::ReadNetAddress(napi_env env, napi_value *params)
{
    NetAddress address;
    napi_value netAddress = NapiUtils::GetNamedProperty(GetEnv(), params[0], ADDRESS_NAME);

    std::string addr = NapiUtils::GetStringPropertyUtf8(GetEnv(), netAddress, ADDRESS_NAME);
    address.SetAddress(addr);
    uint32_t family = NapiUtils::GetUint32Property(GetEnv(), netAddress, FAMILY_NAME);
    if (family == 1) {
        address.SetFamilyBySaFamily(AF_INET);
    } else {
        address.SetFamilyBySaFamily(AF_INET6);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, PORT_NAME)) {
        uint16_t port = static_cast<uint16_t>(NapiUtils::GetUint32Property(GetEnv(), netAddress, PORT_NAME));
        address.SetPort(port);
    }
    return address;
}
} // namespace NetStack
} // namespace OHOS
