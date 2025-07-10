/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "websocket_ani.h"

#include "secure_char.h"
#include "wrapper.rs.h"
#include <memory>

namespace OHOS {
namespace NetStackAni {

std::unique_ptr<NetStack::WebSocketClient::WebSocketClient> CreateWebSocket()
{
    return std::make_unique<NetStack::WebSocketClient::WebSocketClient>();
}

int32_t Connect(NetStack::WebSocketClient::WebSocketClient &client, const rust::str url, ConnectOptions options)
{
    NetStack::WebSocketClient::OpenOptions openOptions;
    bool isValue = false;
    std::string key;
    std::string value;
    for (const auto &item : options.headers) {
        if (isValue) {
            value = std::string(item);
            openOptions.headers.insert(std::make_pair(key, value));
            isValue = false;
        } else {
            key = std::string(item);
            isValue = true;
        }
    }
    return client.Connect(std::string(url), openOptions);
}

void SetCaPath(NetStack::WebSocketClient::WebSocketClient &client, const rust::str caPath)
{
    auto context = client.GetClientContext();
    context->SetUserCertPath(std::string(caPath));
}

void SetClientCert(NetStack::WebSocketClient::WebSocketClient &client, const rust::str clientCert,
                   const rust::str clientKey)
{
    auto context = client.GetClientContext();
    context->clientCert = std::string(clientCert);
    context->clientKey = NetStack::Secure::SecureChar(std::string(clientKey));
}

void SetCertPassword(NetStack::WebSocketClient::WebSocketClient &client, const rust::str password)
{
    auto context = client.GetClientContext();
    context->keyPassword = NetStack::Secure::SecureChar(std::string(password));
}

int32_t Send(NetStack::WebSocketClient::WebSocketClient &client, const rust::str data)
{
    return client.Send(const_cast<char *>(data.data()), data.size());
}

int32_t Close(NetStack::WebSocketClient::WebSocketClient &client, CloseOption options)
{
    NetStack::WebSocketClient::CloseOption closeOption{
        .code = options.code,
        .reason = options.reason.data(),
    };
    return client.Close(closeOption);
}

} // namespace NetStackAni
} // namespace OHOS