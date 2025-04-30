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

#ifndef COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H
#define COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H

#include "close_context.h"
#include "connect_context.h"
#include "send_context.h"
#ifdef NETSTACK_WEBSOCKETSERVER
#include "server_start_context.h"
#include "list_all_connections_context.h"
#include "server_send_context.h"
#include "server_close_context.h"
#include "server_stop_context.h"
#include "websocket_utils.h"
#endif // NETSTACK_WEBSOCKETSERVER

namespace OHOS::NetStack::Websocket {

#ifdef NETSTACK_WEBSOCKETSERVER
struct ClientInfo {
    int32_t cnt;
    uint64_t lastConnectionTime;
};

struct WebSocketMessage {
    std::string data;
    WebSocketConnection connection;
};
#endif

class WebSocketExec final {
public:
    static bool CreatConnectInfo(ConnectContext *context, lws_context *lwsContext,
                                 const std::shared_ptr<EventManager> &manager);
    /* async work execute */
    static bool ExecConnect(ConnectContext *context);

    static bool ExecSend(SendContext *context);

    static bool ExecClose(CloseContext *context);

#ifdef NETSTACK_WEBSOCKETSERVER
    static bool ExecServerStart(ServerStartContext *context);
 
    static bool ExecListAllConnections(ListAllConnectionsContext *context);
 
    static bool ExecServerClose(ServerCloseContext *context);
 
    static bool ExecServerSend(ServerSendContext *context);
 
    static bool ExecServerStop(ServerStopContext *context);
#endif

    /* async work callback */
    static napi_value ConnectCallback(ConnectContext *context);

    static napi_value SendCallback(SendContext *context);

    static napi_value CloseCallback(CloseContext *context);

    static int LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int lwsServerCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

#ifdef NETSTACK_WEBSOCKETSERVER
    static napi_value ServerStartCallback(ServerStartContext *context);
 
    static napi_value ListAllConnectionsCallback(ListAllConnectionsContext *context);
 
    static napi_value ServerCloseCallback(ServerCloseContext *context);
 
    static napi_value ServerSendCallback(ServerSendContext *context);
 
    static napi_value ServerStopCallback(ServerStopContext *context);
#endif

private:
    static bool ParseUrl(ConnectContext *context, char *prefix, size_t prefixLen, char *address, size_t addressLen,
                         char *path, size_t pathLen, int *port);

    static int RaiseError(EventManager *manager, uint32_t httpResponse);

    static int HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                      size_t len);

    static int LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                size_t len);

    static int LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                   size_t len);

    static int LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static int LwsCallbackVhostCertAging(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);

    static void OnOpen(EventManager *manager, uint32_t status, const std::string &message);

    static void OnError(EventManager *manager, int32_t code, uint32_t httpResponse);

    static uint32_t GetHttpResponseFromWsi(lws *wsi);

    static void OnMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal);

    static void OnClose(EventManager *manager, lws_close_status closeStatus, const std::string &closeReason);

    static void OnHeaderReceive(EventManager *manager, const std::map<std::string, std::string> &headers);

    static void FillContextInfo(ConnectContext *context, lws_context_creation_info &info, char *proxyAds);

    static bool FillCaPath(ConnectContext *context, lws_context_creation_info &info);

    static void GetWebsocketProxyInfo(ConnectContext *context, std::string &host, uint32_t &port,
                                      std::string &exclusions);
    static void HandleRcvMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal);

#ifdef NETSTACK_WEBSOCKETSERVER
    static int RaiseServerError(EventManager *manager, uint32_t httpResponse);

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

    static bool IsOverMaxClientConns(EventManager *manager);

    static bool IsAllowedProtocol(lws *wsi);

    static bool IsAllowConnection(const std::string &clientId);

    static bool IsIpInBanList(const std::string &id);

    static bool IsHighFreqConnection(const std::string &id);

    static void AddBanList(const std::string &id);

    static void UpdataClientList(const std::string &id);

    static lws* GetClientWsi(const std::string clientId);

    static uint64_t GetCurrentSecond();

    static void CloseAllConnection();

    static void FillServerContextInfo(ServerStartContext *context, std::shared_ptr<EventManager> &manager,
        lws_context_creation_info &info);

    static bool FillServerCertPath(ServerStartContext *context, lws_context_creation_info &info);

    static void StartService(lws_context_creation_info &info, std::shared_ptr<EventManager> &manager);

    static void AddConnections(const std::string &Id, lws *wsi, std::shared_ptr<UserData> &userData,
        WebSocketConnection &conn);

    static void RemoveConnections(const std::string &Id, UserData &userData);

    static bool GetPeerConnMsg(lws *wsi, EventManager *manager, std::string &clientId, WebSocketConnection &conn);

    static std::vector<WebSocketConnection> GetConnections();
#endif
};
} // namespace OHOS::NetStack::Websocket
#endif /* COMMUNICATIONNETSTACK_WEBSOCKET_EXEC_H */
