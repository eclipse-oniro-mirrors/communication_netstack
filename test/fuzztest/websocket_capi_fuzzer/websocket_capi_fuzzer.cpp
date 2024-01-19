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

#include <csignal>
#include <cstring>
#include <functional>
#include <iostream>

#include "net_websocket.h"
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketClient {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;
constexpr size_t STR_LEN = 255;
const int32_t LWS_CLOSE_STATUS_NORMAL = 1000;
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

void SetAddHeaderTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct WebSocket *client = nullptr;
    struct WebSocket_Header header1;
    header1.fieldName = str.c_str();
    header1.fieldValue = str.c_str();
    header1.next = nullptr;
    OH_WebSocketClient_AddHeader(client, header1);
}

void SetRequestOptionsTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    struct WebSocket *client = new WebSocket();
    const char *url1 = "www.baidu.com";

    OH_WebSocketClient_Connect(client, url1, client->requestOptions);
}

void SetConnectUrlTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct WebSocket *client = new WebSocket();
    const char *url1 = str.c_str();
    OH_WebSocketClient_Connect(client, url1, client->requestOptions);
}

void SetSendDataTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    struct WebSocket *client = new WebSocket();
    const char *senddata = "Hello, world,websocket!";
    int32_t sendLength = std::strlen(senddata);
    OH_WebSocketClient_Send(client, const_cast<char *>(senddata), sendLength);
}

void SetSendDataLengthTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    struct WebSocket *client = new WebSocket();
    const char *senddata = "Hello, world,websocket!";
    int32_t sendLength = size;
    OH_WebSocketClient_Send(client, const_cast<char *>(senddata), sendLength);
}

void SetCloseOptionTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    struct WebSocket *client = new WebSocket();

    struct WebSocket_CloseOption CloseOption;
    CloseOption.code = LWS_CLOSE_STATUS_NORMAL;
    CloseOption.reason = " ";
    OH_WebSocketClient_Close(client, CloseOption);
}

} // namespace WebSocketClient
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::WebSocketClient::SetAddHeaderTest(data, size);
    OHOS::NetStack::WebSocketClient::SetRequestOptionsTest(data, size);
    OHOS::NetStack::WebSocketClient::SetConnectUrlTest(data, size);
    OHOS::NetStack::WebSocketClient::SetSendDataTest(data, size);
    OHOS::NetStack::WebSocketClient::SetSendDataLengthTest(data, size);
    OHOS::NetStack::WebSocketClient::SetCloseOptionTest(data, size);
    return 0;
}