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

#include <cstring>
#include <functional>
#include <iostream>
#include <signal.h>
#include <string.h>

#include "net_websocket.h"
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace WebsocketClient {
namespace {
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
    if (memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize)) {
        return {};
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

// static void OnOpen(struct OH_NetStack_WebsocketClient *client, OH_NetStack_WebsocketClient_OpenResult openResult) {}

// static void OnMessage(struct OH_NetStack_WebsocketClient *client, char *data, uint32_t length) {}

// static void OnError(struct OH_NetStack_WebsocketClient *client, OH_NetStack_WebsocketClient_ErrorResult error) {}

// static void OnClose(struct OH_NetStack_WebsocketClient *client, OH_NetStack_WebsocketClient_CloseResult closeResult)
// {}

void SetAddHeaderTest(const uint8_t *data, size_t size)
{
    int ret;
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct OH_NetStack_WebsocketClient *client = nullptr;
    struct OH_NetStack_WebsocketClient_Slist header1;
    header1.fieldName = str.c_str();
    header1.fieldValue = str.c_str();
    header1.next = nullptr;
    ret = OH_NetStack_WebSocketClient_AddHeader(client, header1);
}

void SetRequestOptionsTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    const char *url1 = "www.baidu.com";

    struct OH_NetStack_WebsocketClient_Slist header1;
    header1.fieldName = str.c_str();
    header1.fieldValue = str.c_str();
    header1.next = nullptr;
    OH_NetStack_WebSocketClient_Connect(client, url1, client->requestOptions);
}

void SetConnectUrlTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    const char *url1 = str.c_str();
    OH_NetStack_WebSocketClient_Connect(client, url1, client->requestOptions);
}

void SetSendDataTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    const char *Senddata = "Hello, world,NDK!";
    int SendLength = std::strlen(Senddata);
    OH_NetStack_WebSocketClient_Send(client, const_cast<char *>(Senddata), SendLength);
}

void SetSendDataLengthTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();
    const char *Senddata = "Hello, world,NDK!";
    int SendLength = size;
    OH_NetStack_WebSocketClient_Send(client, const_cast<char *>(Senddata), SendLength);
}

void SetCloseOptionTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return;
    }
    SetGlobalFuzzData(data, size);
    std::string str = GetStringFromData(STR_LEN);
    struct OH_NetStack_WebsocketClient *client = new OH_NetStack_WebsocketClient();

    struct OH_NetStack_WebsocketClient_CloseOption CloseOption;
    CloseOption.code = 1000;
    CloseOption.reason = " ";
    OH_NetStack_WebSocketClient_Close(client, CloseOption);
}

} // namespace WebsocketClient
} // namespace NetStack
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::NetStack::WebsocketClient::SetAddHeaderTest(data, size);
    OHOS::NetStack::WebsocketClient::SetRequestOptionsTest(data, size);
    OHOS::NetStack::WebsocketClient::SetConnectUrlTest(data, size);
    OHOS::NetStack::WebsocketClient::SetSendDataTest(data, size);
    OHOS::NetStack::WebsocketClient::SetSendDataLengthTest(data, size);
    OHOS::NetStack::WebsocketClient::SetCloseOptionTest(data, size);
    return 0;
}