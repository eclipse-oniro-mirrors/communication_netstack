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

#include "tls_sockket_fuzzer.h"
#include "tls_socket.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {

void BindFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    TLSSocket tlsSocket;
    NetAddress netAddress;
    std::string str(reinterpret_cast<const char*>(data), size);
    netAddress.SetAddress(str);
    netAddress.SetFamilyByJsValue(*(reinterpret_cast<const uint32_t*>(data)));
    netAddress.SetFamilyBySaFamily(*(reinterpret_cast<const sa_family_t*>(data)));
    netAddress.SetPort(*(reinterpret_cast<const uint16_t*>(data)));
    tlsSocket.Bind(netAddress, [](bool ok) {
        NETSTACK_LOGE("Calback received");
    });
}

void ConnectFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    TLSSocket tlsSocket;
    NetAddress netAddress;
    std::string str(reinterpret_cast<const char*>(data), size);
    netAddress.SetAddress(str);
    netAddress.SetFamilyByJsValue(*(reinterpret_cast<const uint32_t*>(data)));
    netAddress.SetFamilyBySaFamily(*(reinterpret_cast<const sa_family_t*>(data)));
    netAddress.SetPort(*(reinterpret_cast<const uint16_t*>(data)));
    TLSConnectOptions options;
    options.SetNetAddress(netAddress);
    options.SetCheckServerIdentity([](const std::string &hostName, const std::vector<std::string> &x509Certificates) {
            NETSTACK_LOGE("Calback received");
        });
    std::vector<std::string> alpnProtocols(3, str);
    options.SetAlpnProtocols(alpnProtocols);
    tlsSocket.Connect(options, [](bool ok) {
        NETSTACK_LOGE("Calback received");
    });
}

void SendTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    TLSSocket tlsSocket;
    TCPSendOptions options;
    std::string str(reinterpret_cast<const char*>(data), size);
    options.SetData(str);
    options.SetEncoding(str);
    tlsSocket.Send(options, [](bool ok) {
        NETSTACK_LOGE("Calback received");
    });
}

void SetExtraOptionsTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return;
    }
    TLSSocket tlsSocket;
    TCPExtraOptions options;
    options.SetKeepAlive(*(reinterpret_cast<const bool*>(data)));
    options.SetOOBInline(*(reinterpret_cast<const bool*>(data)));
    options.SetTCPNoDelay(*(reinterpret_cast<const bool*>(data)));
    tlsSocket.SetExtraOptions(options, [](bool ok) {
        NETSTACK_LOGE("Calback received");
    });
}
} // NetStack
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::BindFuzzTest(data, size);
    OHOS::NetStack::ConnectFuzzTest(data, size);
    OHOS::NetStack::SendTest(data, size);
    OHOS::NetStack::SetExtraOptionsTest(data, size);
    return 0;
}