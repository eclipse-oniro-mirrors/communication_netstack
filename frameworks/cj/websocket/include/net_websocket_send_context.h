/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NET_WEBSOCKET_SEND_CONTEXT_H
#define NET_WEBSOCKET_SEND_CONTEXT_H

#include "libwebsockets.h"
#include "constant.h"
#include "net_websocket_base_context.h"

namespace OHOS::NetStack::NetWebSocket {
class CJWebsocketProxy;
class WebSocketSendContext final : public WebSocketBaseContext {
public:
    WebSocketSendContext() = delete;

    WebSocketSendContext(CJWebsocketProxy* websocketProxy);

    void ParseParams(CArrUI8 data, bool stringType);

    [[nodiscard]] int32_t GetErrorCode() const override;

    [[nodiscard]] std::string GetErrorMessage() const override;

    void *data;

    size_t length;

    lws_write_protocol protocol;
};
}
#endif