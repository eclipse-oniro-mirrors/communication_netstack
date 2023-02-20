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

#include "tls_socket_fuzzer.h"

#include <securec.h>

#include "netstack_log.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;
constexpr size_t STR_LEN = 10;
}
template <class T>
T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    if (memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize)) {
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}

std::string GetStringFromData(int strlen)
{
    char cstr[strlen];
    cstr[strlen - 1] = '\0';
    for (int i = 0; i < strlen - 1; i++) {
        cstr[i] = GetData<char>();
    }
    std::string str(cstr);
    return str;
}

void BindFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("BindFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    TLSSocket tlsSocket;
    NetAddress netAddress;
    std::string str = GetStringFromData(STR_LEN);
    netAddress.SetAddress(str);
    netAddress.SetFamilyByJsValue(GetData<uint32_t>());
    netAddress.SetFamilyBySaFamily(GetData<sa_family_t>());
    netAddress.SetPort(GetData<uint16_t>());
    tlsSocket.Bind(netAddress, [](bool ok) {
        NETSTACK_LOGD("Calback received");
    });
    tlsSocket.Close([](int32_t errorNumber) {});
    tlsSocket.GetRemoteAddress([](int32_t errorNumber, const NetAddress &address) {});
    tlsSocket.GetCertificate([](int32_t errorNumber, const X509CertRawData &cert) {});
    tlsSocket.GetRemoteCertificate([](int32_t errorNumber, const X509CertRawData &cert) {});
    tlsSocket.GetProtocol([](int32_t errorNumber, const std::string &protocol) {});
    tlsSocket.GetCipherSuite([](int32_t errorNumber, const std::vector<std::string> &suite) {});
    tlsSocket.GetSignatureAlgorithms([](int32_t errorNumber, const std::vector<std::string> &algorithms) {});
    tlsSocket.OnMessage([](const std::string &data, const SocketRemoteInfo &remoteInfo) {});
    tlsSocket.OnConnect([]() {});
    tlsSocket.OnClose([]() {});
    tlsSocket.OnError([](int32_t errorNumber, const std::string &errorString) {});
    tlsSocket.OffMessage();
    tlsSocket.OffConnect();
    tlsSocket.OffClose();
    tlsSocket.OffError();
}

void ConnectFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("ConnectFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    TLSSocket tlsSocket;
    NetAddress netAddress;
    std::string str = GetStringFromData(STR_LEN);
    netAddress.SetAddress(str);
    netAddress.SetFamilyByJsValue(GetData<uint32_t>());
    netAddress.SetFamilyBySaFamily(GetData<sa_family_t>());
    netAddress.SetPort(GetData<uint16_t>());
    TLSConnectOptions options;
    options.SetNetAddress(netAddress);
    options.SetCheckServerIdentity([](const std::string &hostName, const std::vector<std::string> &x509Certificates) {
            NETSTACK_LOGD("Calback received");
        });
    std::vector<std::string> alpnProtocols(STR_LEN, str);
    options.SetAlpnProtocols(alpnProtocols);
    tlsSocket.Connect(options, [](bool ok) {
        NETSTACK_LOGD("Calback received");
    });
}

void SendFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    TLSSocket tlsSocket;
    TCPSendOptions options;
    std::string str = GetStringFromData(STR_LEN);
    options.SetData(str);
    options.SetEncoding(str);
    tlsSocket.Send(options, [](bool ok) {
        NETSTACK_LOGD("Calback received");
    });
}

void SetExtraOptionsFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    TLSSocket tlsSocket;
    TCPExtraOptions options;
    options.SetKeepAlive(*(reinterpret_cast<const bool *>(data)));
    options.SetOOBInline(*(reinterpret_cast<const bool *>(data)));
    options.SetTCPNoDelay(*(reinterpret_cast<const bool *>(data)));
    tlsSocket.SetExtraOptions(options, [](bool ok) {
        NETSTACK_LOGD("Calback received");
    });
}

void SetCaChainFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetCaChainFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    uint32_t count = GetData<uint32_t>() % 10;
    std::vector<std::string> caChain;
    caChain.reserve(count);
    for (size_t i = 0; i < count; i++) {
        caChain.emplace_back(str);
    }
    TLSSecureOptions option;
    option.SetCaChain(caChain);
    auto ret = option.GetCaChain();
}

void SetCertFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetCertFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string cert = GetStringFromData(STR_LEN);
    TLSSecureOptions option;
    option.SetCert(cert);
    auto ret = option.GetCert();
}

void SetKeyFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetKeyFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    SecureData secureData(str);
    TLSSecureOptions option;
    option.SetKey(secureData);
    auto ret = option.GetKey();
}

void SetKeyPassFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetKeyPassFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    SecureData secureData(str);
    TLSSecureOptions option;
    option.SetKeyPass(secureData);
    auto ret = option.GetKeyPass();
}

void SetProtocolChainFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetProtocolChainFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    uint32_t count = GetData<uint32_t>() % 10;
    std::vector<std::string> caChain;
    caChain.reserve(count);
    for (size_t i = 0; i < count; i++) {
        caChain.emplace_back(str);
    }
    TLSSecureOptions option;
    option.SetProtocolChain(caChain);
    auto ret = option.GetProtocolChain();
}

void SetUseRemoteCipherPreferFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetUseRemoteCipherPreferFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool useRemoteCipherPrefer = GetData<int32_t>() % 2 == 0;
    TLSSecureOptions option;
    option.SetUseRemoteCipherPrefer(useRemoteCipherPrefer);
    bool ret = option.UseRemoteCipherPrefer();
    NETSTACK_LOGD("ret:%{public}s", ret ? "true" : "false");
}

void SetSignatureAlgorithmsFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetSignatureAlgorithmsFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    TLSSecureOptions option;
    option.SetSignatureAlgorithms(str);
    auto ret = option.GetSignatureAlgorithms();
}

void SetCipherSuiteFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetCipherSuiteFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    TLSSecureOptions option;
    option.SetCipherSuite(str);
    auto ret = option.GetCipherSuite();
}

void SetCrlChainFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetCrlChainFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    uint32_t count = GetData<uint32_t>() % 10;
    std::vector<std::string> caChain;
    caChain.reserve(count);
    for (size_t i = 0; i < count; i++) {
        caChain.emplace_back(str);
    }
    TLSSecureOptions option;
    option.SetCrlChain(caChain);
    auto ret = option.GetCrlChain();
}

void SetNetAddressFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetNetAddressFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    NetAddress address;
    std::string str = GetStringFromData(STR_LEN);
    uint32_t num = GetData<uint32_t>();
    uint16_t port = GetData<uint16_t>();
    address.SetAddress(str);
    address.SetFamilyByJsValue(num);
    address.SetPort(port);
    TLSConnectOptions option;
    option.SetNetAddress(address);
    auto ret = option.GetNetAddress();
}

void SetTlsSecureOptionsFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetTlsSecureOptionsFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    TLSSecureOptions tls;
    std::string str = GetStringFromData(STR_LEN);
    tls.SetCipherSuite(str);
    tls.SetSignatureAlgorithms(str);
    tls.SetCert(str);
    TLSConnectOptions option;
    option.SetTlsSecureOptions(tls);
    auto ret = option.GetTlsSecureOptions();
    option.SetCheckServerIdentity([](const std::string, const std::vector<std::string>) {});
}

void SetAlpnProtocolsFuzzTest(const uint8_t *data, size_t size)
{
    NETSTACK_LOGD("SetAlpnProtocolsFuzzTest:enter");
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    std::string str = GetStringFromData(STR_LEN);
    uint32_t count = GetData<uint32_t>() % 10;
    std::vector<std::string> strs;
    strs.reserve(count);
    for (size_t i = 0; i < count; i++) {
        strs.emplace_back(str);
    }
    TLSConnectOptions option;
    option.SetAlpnProtocols(strs);
    auto ret = option.GetCheckServerIdentity();
}
} // NetStack
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::BindFuzzTest(data, size);
    OHOS::NetStack::ConnectFuzzTest(data, size);
    OHOS::NetStack::SendFuzzTest(data, size);
    OHOS::NetStack::SetExtraOptionsFuzzTest(data, size);
    OHOS::NetStack::SetCaChainFuzzTest(data, size);
    OHOS::NetStack::SetCertFuzzTest(data, size);
    OHOS::NetStack::SetKeyFuzzTest(data, size);
    OHOS::NetStack::SetKeyPassFuzzTest(data, size);
    OHOS::NetStack::SetProtocolChainFuzzTest(data, size);
    OHOS::NetStack::SetUseRemoteCipherPreferFuzzTest(data, size);
    OHOS::NetStack::SetSignatureAlgorithmsFuzzTest(data, size);
    OHOS::NetStack::SetCipherSuiteFuzzTest(data, size);
    OHOS::NetStack::SetCrlChainFuzzTest(data, size);
    OHOS::NetStack::SetNetAddressFuzzTest(data, size);
    OHOS::NetStack::SetTlsSecureOptionsFuzzTest(data, size);
    OHOS::NetStack::SetAlpnProtocolsFuzzTest(data, size);
    return 0;
}
