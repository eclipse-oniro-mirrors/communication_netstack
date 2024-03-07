/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstring>
#include <map>
#include <securec.h>
#include <string>
#include <vector>

#include "netstack_log.h"
#include "secure_char.h"
#include "websocket_client_innerapi.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketClient {
namespace {
OpenOptions openOptions;
std::map<std::string, std::string> headers = {
    {"Content-Type", "application/json"},
    {"Authorization", "Bearer your_token_here"},
};
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
[[maybe_unused]] constexpr size_t STR_LEN = 255;
} // namespace
template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || g_baseFuzzSize <= g_baseFuzzPos || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        return object;
    }
    g_baseFuzzPos += objectSize;
    return object;
}

void SetGlobalFuzzData(const uint8_t *data, size_t size)
{
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
}

std::string GetStringFromData(int strlen)
{
    if (strlen < 1) {
        return "";
    }

    char cstr[strlen];
    cstr[strlen - 1] = '\0';
    for (int i = 0; i < strlen - 1; i++) {
        cstr[i] = GetData<char>();
    }
    std::string str(cstr);
    return str;
}

static void OnMessage(WebSocketClient *client, const std::string &data, size_t length) {}

static void OnOpen(WebSocketClient *client, OpenResult openResult) {}

static void OnError(WebSocketClient *client, ErrorResult error) {}

static void OnClose(WebSocketClient *client, CloseResult closeResult) {}

void SetRequestOptionsTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    openOptions.headers["Content-Type"] = str;
    openOptions.headers["Authorization"] = str;
    WebSocketClient *client = new WebSocketClient();
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    client->Connect("www.baidu.com", openOptions);
}

void SetConnectUrlTest(const uint8_t *data, size_t size)
{
    if (size < 1 || data == nullptr) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    openOptions.headers["Content-Type"] = "application/json";
    WebSocketClient *client = new WebSocketClient();
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    client->Connect(str, openOptions);
}

void SetSendDataTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    openOptions.headers["Content-Type"] = "application/json";
    WebSocketClient *client = new WebSocketClient();
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    client->Connect("www.baidu.com", openOptions);
    const char *data1 = str.c_str();
    int32_t sendLength = std::strlen(data1);
    client->Send(const_cast<char *>(data1), sendLength);
}

void SetSendDataLengthTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    openOptions.headers["Content-Type"] = "application/json";
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    WebSocketClient *client = new WebSocketClient();
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    client->Connect("www.baidu.com", openOptions);
    const char *data1 = "Hello,world!";
    client->Send(const_cast<char *>(data1), size);
}

void SetCloseOptionTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    openOptions.headers["Content-Type"] = "application/json";
    openOptions.headers["Authorization"] = "Bearer your_token_here";
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);

    WebSocketClient *client = new WebSocketClient();
    client->Registcallback(OnOpen, OnMessage, OnError, OnClose);
    client->Connect("www.baidu.com", openOptions);
    CloseOption CloseOptions;
    CloseOptions.code = size;
    CloseOptions.reason = str.c_str();
    client->Close(CloseOptions);
}

} // namespace WebSocketClient
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::WebSocketClient::SetRequestOptionsTest(data, size);
    OHOS::NetStack::WebSocketClient::SetConnectUrlTest(data, size);
    OHOS::NetStack::WebSocketClient::SetSendDataTest(data, size);
    OHOS::NetStack::WebSocketClient::SetSendDataLengthTest(data, size);
    OHOS::NetStack::WebSocketClient::SetCloseOptionTest(data, size);
    return 0;
}