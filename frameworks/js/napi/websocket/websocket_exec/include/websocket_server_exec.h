/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_EXEC_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_SERVER_EXEC_H

#include <map>
#include "server_start_context.h"
#include "list_all_connections_context.h"
#include "server_send_context.h"
#include "server_close_context.h"
#include "server_stop_context.h"
#include "websocket_utils.h"
#include "netstack_log.h"

namespace OHOS::NetStack::Websocket {

struct ClientInfo {
    int32_t cnt;
    uint64_t lastConnectionTime;
};

struct WebSocketMessage {
    std::string data;
    WebSocketConnection connection;
};

class UserData {
public:
    struct SendData {
        SendData(void *paraData, size_t paraLength, lws_write_protocol paraProtocol)
            : data(paraData), length(paraLength), protocol(paraProtocol)
        {
        }

        SendData() = delete;

        ~SendData() = default;

        void *data;
        size_t length;
        lws_write_protocol protocol;
    };

    explicit UserData(lws_context *context)
        : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), closed_(false), threadStop_(false), context_(context)
    {
    }

    bool IsClosed()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    bool IsThreadStop()
    {
        return threadStop_.load();
    }

    void SetThreadStop(bool threadStop)
    {
        threadStop_.store(threadStop);
    }

    void Close(lws_close_status status, const std::string &reason)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closeStatus = status;
        closeReason = reason;
        closed_ = true;
    }

    void Push(void *data, size_t length, lws_write_protocol protocol)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dataQueue_.emplace(data, length, protocol);
    }

    SendData Pop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return {nullptr, 0, LWS_WRITE_TEXT};
        }
        SendData data = dataQueue_.front();
        dataQueue_.pop();
        return data;
    }

    void SetContext(lws_context *context)
    {
        context_ = context;
    }

    lws_context *GetContext()
    {
        return context_;
    }

    bool IsEmpty()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (dataQueue_.empty()) {
            return true;
        }
        return false;
    }

    void SetLws(lws *wsi)
    {
        std::lock_guard<std::mutex> lock(mutexForLws_);
        if (wsi == nullptr) {
            NETSTACK_LOGD("set wsi nullptr");
        }
        wsi_ = wsi;
    }

    void TriggerWritable()
    {
        std::lock_guard<std::mutex> lock(mutexForLws_);
        if (wsi_ == nullptr) {
            NETSTACK_LOGE("wsi is nullptr, can not trigger");
            return;
        }
        lws_callback_on_writable(wsi_);
    }

    std::map<std::string, std::string> header;

    lws_close_status closeStatus;

    std::string closeReason;

    uint32_t openStatus;

    std::string openMessage;

private:
    volatile bool closed_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    std::mutex mutexForLws_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;

    lws *wsi_ = nullptr;
};

class WebSocketServerExec final {
public:
    /* async work execute */
    static bool ExecServerStart(ServerStartContext *context);

    static bool ExecListAllConnections(ListAllConnectionsContext *context);

    static bool ExecServerClose(ServerCloseContext *context);

    static bool ExecServerSend(ServerSendContext *context);

    static bool ExecServerStop(ServerStopContext *context);

    static int lwsServerCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    /* async work callback */
    static napi_value ServerStartCallback(ServerStartContext *context);

    static napi_value ListAllConnectionsCallback(ListAllConnectionsContext *context);

    static napi_value ServerCloseCallback(ServerCloseContext *context);

    static napi_value ServerSendCallback(ServerSendContext *context);

    static napi_value ServerStopCallback(ServerStopContext *context);

private:
    static int HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int RaiseServerError(EventManager *manager);

    static int LwsCallbackEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackFilterProtocolConnection(lws *wsi, lws_callback_reasons reason,
        void *user, void *in, size_t len);

    static int LwsCallbackReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackServerWriteable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackWsPeerInitiatedCloseServer(lws *wsi, lws_callback_reasons reason,
        void *user, void *in, size_t len);

    static int LwsCallbackClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackWsiDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackProtocolDestroyServer(lws *wsi, lws_callback_reasons reason,
        void *user, void *in, size_t len);

    static void OnConnect(lws *wsi, EventManager *manager);

    static void OnServerClose(lws *wsi, EventManager *manager, lws_close_status closeStatus,
        const std::string &closeReason);

    static void OnServerMessage(lws *wsi, EventManager *manager, void *data, size_t length,
        bool isBinary, bool isFinal);

    static void OnServerError(EventManager *manager, int32_t code);

    static void HandleServerRcvMessage(lws *wsi, EventManager *manager, void *data,
        size_t length, bool isBinary, bool isFinal);

    static void SetWebsocketMessage(lws *wsi, EventManager *manager, const std::string &msg, void *dataMsg);

    static bool IsOverMaxClientConns(EventManager *manager, const std::string ip);

    static bool IsOverMaxConcurrentClientsCnt(EventManager *manager, const std::vector<WebSocketConnection> connections,
        const std::string ip);

    static bool IsOverMaxCntForOneClient(EventManager *manager, const std::vector<WebSocketConnection> connections,
        const std::string ip);

    static bool IsAllowConnection(const std::string &clientId);

    static bool IsIpInBanList(const std::string &id);

    static bool IsHighFreqConnection(const std::string &id);

    static void AddBanList(const std::string &id);

    static void UpdataClientList(const std::string &id);

    static lws *GetClientWsi(const std::string clientId);

    static uint64_t GetCurrentSecond();

    static void CloseAllConnection(const std::shared_ptr<UserData> &userData);

    static void FillServerContextInfo(ServerStartContext *context, std::shared_ptr<EventManager> &manager,
        lws_context_creation_info &info);

    static bool FillServerCertPath(ServerStartContext *context, lws_context_creation_info &info);

    static void StartService(lws_context_creation_info &info, std::shared_ptr<EventManager> &manager);

    static void AddConnections(const std::string &Id, lws *wsi, std::shared_ptr<UserData> &userData,
        WebSocketConnection &conn);

    static void RemoveConnections(const std::string &Id, UserData &userData);

    static bool GetPeerConnMsg(lws *wsi, EventManager *manager, std::string &clientId, WebSocketConnection &conn);

    static std::vector<WebSocketConnection> GetConnections();
};
} // namespace OHOS::NetStack::Websocket
#endif /* COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H */