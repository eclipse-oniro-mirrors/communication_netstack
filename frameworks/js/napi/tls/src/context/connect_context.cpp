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

#include "connect_context.h"

#include <cstdint>
#include <string>
#include <vector>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
ConnectContext::ConnectContext(napi_env env, EventManager *manager) : BaseContext(env, manager) {}

void ConnectContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        return;
    }
    connectOptions_ = ReadTlsConnectOptions(GetEnv(), params);

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[ARG_INDEX_1]) == napi_ok);
        return;
    }
    SetParseOK(true);
}

bool ConnectContext::CheckParamsType(napi_value *params, size_t paramsCount)
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

TLSConnectOptions ConnectContext::ReadTlsConnectOptions(napi_env env, napi_value *params)
{
    TLSConnectOptions options;
    NetAddress address = ReadNetAddress(GetEnv(), params);
    TLSSecureOptions secureOption = ReadTlsSecureOptions(GetEnv(), params);
    options.SetNetAddress(address);
    options.SetTlsSecureOptions(secureOption);

    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], "ALPNProtocols")) {
        napi_value alpnProtocols = NapiUtils::GetNamedProperty(GetEnv(), params[0], "ALPNProtocols");
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
    NETSTACK_LOGI("ConnectContext::ReadTlsConnectOptions(napi_env env, napi_value *params) end");
    return options;
}

TLSSecureOptions ConnectContext::ReadTlsSecureOptions(napi_env env, napi_value *params)
{
    TLSSecureOptions secureOption;

    if (!NapiUtils::HasNamedProperty(GetEnv(), params[ARG_INDEX_0], "secureOptions")) {
        return secureOption;
    }
    napi_value secureOptions = NapiUtils::GetNamedProperty(GetEnv(), params[ARG_INDEX_0], "secureOptions");

    if (!NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "ca")) {
        return secureOption;
    }
    napi_value caVector = NapiUtils::GetNamedProperty(GetEnv(), secureOptions, "ca");
    uint32_t arrayLong = NapiUtils::GetArrayLength(GetEnv(), caVector);
    napi_value element = nullptr;
    std::vector<std::string> caVec;
    for (uint32_t i = 0; i < arrayLong; i++) {
        element = NapiUtils::GetArrayElement(GetEnv(), caVector, i);
        std::string ca = NapiUtils::GetStringFromValueUtf8(GetEnv(), element);
        caVec.push_back(ca);
    }
    secureOption.SetCaChain(caVec);

    if (!NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "key")) {
        return secureOption;
    }
    std::string key = NapiUtils::GetStringPropertyUtf8(env, secureOptions, "key");
    secureOption.SetKey(key);

    if (!NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "cert")) {
        return secureOption;
    }
    std::string cert = NapiUtils::GetStringPropertyUtf8(env, secureOptions, "cert");
    secureOption.SetCert(cert);

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "passwd")) {
        secureOption.SetPassWd(NapiUtils::GetStringPropertyUtf8(env, secureOptions, "passwd"));
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "protocols")) {
        napi_value protocolVector = NapiUtils::GetNamedProperty(env, secureOptions, "protocols");
        uint32_t num = NapiUtils::GetArrayLength(GetEnv(), protocolVector);
        napi_value element = nullptr;
        std::vector<std::string> protocolVec;
        for (uint32_t i = 0; i < num; i++) {
            element = NapiUtils::GetArrayElement(GetEnv(), protocolVector, i);
            std::string protocol = NapiUtils::GetStringFromValueUtf8(GetEnv(), element);
            NETSTACK_LOGI("protocol is %{public}s", protocol.c_str());
            protocolVec.push_back(protocol);
        }
        secureOption.SetProtocolChain(protocolVec);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "signatureAlgorithms")) {
        std::string signatureAlgorithms = NapiUtils::GetStringPropertyUtf8(env, secureOptions, "signatureAlgorithms");
        secureOption.SetSignatureAlgorithms(signatureAlgorithms);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "useRemoteCipherPrefer")) {
        bool useRemoteCipherPrefer = NapiUtils::GetBooleanProperty(env, secureOptions, "useRemoteCipherPrefer");
        secureOption.SetUseRemoteCipherPrefer(useRemoteCipherPrefer);
    }

    if (NapiUtils::HasNamedProperty(GetEnv(), secureOptions, "cipherSuites")) {
        std::string cipherSuites = NapiUtils::GetStringPropertyUtf8(env, secureOptions, "cipherSuites");
        secureOption.SetCipherSuite(cipherSuites);
    }
    return secureOption;
}

NetAddress ConnectContext::ReadNetAddress(napi_env env, napi_value *params)
{
    NetAddress address;
    napi_value netAddress = NapiUtils::GetNamedProperty(GetEnv(), params[0], "address");

    std::string addr = NapiUtils::GetStringPropertyUtf8(GetEnv(), netAddress, "address");
    address.SetAddress(addr);
    uint32_t family = NapiUtils::GetUint32Property(GetEnv(), netAddress, "family");
    if (family == 1) {
        address.SetFamilyBySaFamily(AF_INET);
    } else {
        address.SetFamilyBySaFamily(AF_INET6);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), netAddress, "port")) {
        uint16_t port = static_cast<uint16_t>(NapiUtils::GetUint32Property(GetEnv(), netAddress, "port"));
        address.SetPort(port);
    }
    return address;
}
} // namespace NetStack
} // namespace OHOS
