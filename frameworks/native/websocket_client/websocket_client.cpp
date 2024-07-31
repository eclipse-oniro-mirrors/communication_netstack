/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <iostream>
#include <securec.h>
#include <string>

#include "netstack_log.h"
#include "websocket_client_innerapi.h"

static constexpr const char *PATH_START = "/";
static constexpr const char *NAME_END = ":";
static constexpr const char *STATUS_LINE_SEP = " ";
static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;
static constexpr const char *PREFIX_HTTPS = "https";
static constexpr const char *PREFIX_WSS = "wss";
static constexpr const int MAX_URI_LENGTH = 1024;
static constexpr const int MAX_HDR_LENGTH = 1024;
static constexpr const int MAX_HEADER_LENGTH = 8192;
static constexpr const size_t MAX_DATA_LENGTH = 4 * 1024 * 1024;
static constexpr const int FD_LIMIT_PER_THREAD = 1 + 1 + 1;
static constexpr const int CLOSE_RESULT_FROM_SERVER_CODE = 1001;
static constexpr const int CLOSE_RESULT_FROM_CLIENT_CODE = 1000;
static constexpr const char *LINK_DOWN = "The link is down";
static constexpr const char *CLOSE_REASON_FORM_SERVER = "websocket close from server";
static constexpr const int FUNCTION_PARAM_TWO = 2;
static constexpr const char *WEBSOCKET_CLIENT_THREAD_RUN = "OS_NET_WSCli";
static std::atomic<int> g_clientID(0);
namespace OHOS::NetStack::WebSocketClient {
static const lws_retry_bo_t RETRY = {
    .secs_since_valid_ping = 0,    /* force PINGs after secs idle */
    .secs_since_valid_hangup = 10, /* hangup after secs idle */
    .jitter_percent = 20,
};

WebSocketClient::WebSocketClient()
{
    clientContext = new ClientContext();
    clientContext->SetClientId(++g_clientID);
}

WebSocketClient::~WebSocketClient()
{
    delete clientContext;
    clientContext = nullptr;
}

ClientContext *WebSocketClient::GetClientContext() const
{
    return clientContext;
}

void RunService(WebSocketClient *Client)
{
    if (Client->GetClientContext()->GetContext() == nullptr) {
        return;
    }
    while (!Client->GetClientContext()->IsThreadStop()) {
        lws_service(Client->GetClientContext()->GetContext(), 0);
    }
}

int HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    return ret;
}

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};

int LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGD("ClientId:%{public}d, Lws Callback AppendHandshakeHeader,",
                  client->GetClientContext()->GetClientId());
    auto payload = reinterpret_cast<unsigned char **>(in);
    if (payload == nullptr || (*payload) == nullptr || len == 0) {
        return -1;
    }
    auto payloadEnd = (*payload) + len;
    for (const auto &pair : client->GetClientContext()->header) {
        std::string name = pair.first + NAME_END;
        if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char *>(name.c_str()),
                                        reinterpret_cast<const unsigned char *>(pair.second.c_str()),
                                        static_cast<int>(strlen(pair.second.c_str())), payload, payloadEnd)) {
            return -1;
        }
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Lws Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGD("ClientId:%{public}d,Callback WsPeerInitiatedClose", client->GetClientContext()->GetClientId());
    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGE("Lws Callback WsPeerInitiatedClose");
        client->GetClientContext()->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }
    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    client->GetClientContext()->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Lws Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGD("ClientId:%{public}d,Callback CallbackClientWritable,",
                  client->GetClientContext()->GetClientId());
    if (client->GetClientContext()->IsClosed()) {
        NETSTACK_LOGD("ClientId:%{public}d,Callback ClientWritable need to close",
                      client->GetClientContext()->GetClientId());
        lws_close_reason(
            wsi, client->GetClientContext()->closeStatus,
            reinterpret_cast<unsigned char *>(const_cast<char *>(client->GetClientContext()->closeReason.c_str())),
            strlen(client->GetClientContext()->closeReason.c_str()));
        // here do not emit error, because we close it
        return -1;
    }
    SendData sendData = client->GetClientContext()->Pop();
    if (sendData.data == nullptr || sendData.length == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    const char *message = sendData.data;
    size_t messageLen = strlen(message);
    auto buffer = std::make_unique<unsigned char[]>(LWS_PRE + messageLen);
    if (buffer == nullptr) {
        return -1;
    }
    int result = memcpy_s(buffer.get() + LWS_PRE, LWS_PRE + messageLen, message, messageLen);
    if (result != 0) {
        return -1;
    }
    int bytesSent = lws_write(wsi, buffer.get() + LWS_PRE, messageLen, LWS_WRITE_TEXT);
    NETSTACK_LOGD("ClientId:%{public}d,Client Writable send data length = %{public}d",
                  client->GetClientContext()->GetClientId(), bytesSent);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    NETSTACK_LOGE("ClientId:%{public}d,Callback ClientConnectionError", client->GetClientContext()->GetClientId());
    std::string buf;
    char *data = static_cast<char *>(in);
    buf.assign(data, len);
    ErrorResult errorResult;
    errorResult.errorCode = WebSocketErrorCode::WEBSOCKET_CONNECTION_ERROR;
    errorResult.errorMessage = data;
    client->onErrorCallback_(client, errorResult);
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    NETSTACK_LOGD("ClientId:%{public}d,Callback ClientReceive", client->GetClientContext()->GetClientId());
    std::string buf;
    char *data = static_cast<char *>(in);
    buf.assign(data, len);
    client->onMessageCallback_(client, data, len);
    return HttpDummy(wsi, reason, user, in, len);
}

std::vector<std::string> Split(const std::string &str, const std::string &sep, size_t size)
{
    std::string s = str;
    std::vector<std::string> res;
    while (!s.empty()) {
        if (res.size() + 1 == size) {
            res.emplace_back(s);
            break;
        }
        auto pos = s.find(sep);
        if (pos == std::string::npos) {
            res.emplace_back(s);
            break;
        }
        res.emplace_back(s.substr(0, pos));
        s = s.substr(pos + sep.size());
    }
    return res;
}

int LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    client->GetClientContext()->openStatus = lws_http_client_http_response(wsi);
    NETSTACK_LOGD("ClientId:%{public}d, libwebsockets Callback ClientFilterPreEstablish openStatus = %{public}d",
                  client->GetClientContext()->GetClientId(), client->GetClientContext()->openStatus);
    char statusLine[MAX_HDR_LENGTH] = {0};
    if (lws_hdr_copy(wsi, statusLine, MAX_HDR_LENGTH, WSI_TOKEN_HTTP) < 0 || strlen(statusLine) == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    auto vec = Split(statusLine, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);
    if (vec.size() >= FUNCTION_PARAM_TWO) {
        client->GetClientContext()->openMessage = vec[1];
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("libwebsockets Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGI("ClientId:%{public}d,Callback ClientEstablished", client->GetClientContext()->GetClientId());
    OpenResult openResult;
    openResult.status = client->GetClientContext()->openStatus;
    openResult.message = client->GetClientContext()->openMessage.c_str();
    client->onOpenCallback_(client, openResult);

    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGI("ClientId:%{public}d,Callback ClientClosed", client->GetClientContext()->GetClientId());
    std::string buf;
    char *data = static_cast<char *>(in);
    buf.assign(data, len);
    CloseResult closeResult;
    closeResult.code = CLOSE_RESULT_FROM_SERVER_CODE;
    closeResult.reason = CLOSE_REASON_FORM_SERVER;
    client->onCloseCallback_(client, closeResult);
    client->GetClientContext()->SetThreadStop(true);
    if ((client->GetClientContext()->closeReason).empty()) {
        client->GetClientContext()->Close(client->GetClientContext()->closeStatus, LINK_DOWN);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    WebSocketClient *client = static_cast<WebSocketClient *>(user);
    if (client->GetClientContext() == nullptr) {
        NETSTACK_LOGE("Callback ClientContext is nullptr");
        return -1;
    }
    NETSTACK_LOGI("Lws Callback LwsCallbackWsiDestroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("Lws Callback ProtocolDestroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    constexpr CallbackDispatcher dispatchers[] = {
        {LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER, LwsCallbackClientAppendHandshakeHeader},
        {LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, LwsCallbackWsPeerInitiatedClose},
        {LWS_CALLBACK_CLIENT_WRITEABLE, LwsCallbackClientWritable},
        {LWS_CALLBACK_CLIENT_CONNECTION_ERROR, LwsCallbackClientConnectionError},
        {LWS_CALLBACK_CLIENT_RECEIVE, LwsCallbackClientReceive},
        {LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH, LwsCallbackClientFilterPreEstablish},
        {LWS_CALLBACK_CLIENT_ESTABLISHED, LwsCallbackClientEstablished},
        {LWS_CALLBACK_CLIENT_CLOSED, LwsCallbackClientClosed},
        {LWS_CALLBACK_WSI_DESTROY, LwsCallbackWsiDestroy},
        {LWS_CALLBACK_PROTOCOL_DESTROY, LwsCallbackProtocolDestroy},
    };
    auto it = std::find_if(std::begin(dispatchers), std::end(dispatchers),
        [&reason](const CallbackDispatcher &dispatcher) { return dispatcher.reason == reason; });
    if (it != std::end(dispatchers)) {
        return it->callback(wsi, reason, user, in, len);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {{"lws-minimal-client1", LwsCallback, 0, 0, 0, NULL, 0},
                                           LWS_PROTOCOL_LIST_TERM};

static void FillContextInfo(lws_context_creation_info &info)
{
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.fd_limit_per_thread = FD_LIMIT_PER_THREAD;
}

bool ParseUrl(const std::string url, char *prefix, char *address, char *path, int *port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, MAX_URI_LENGTH, url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempPrefix = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempPrefix, &tempAddress, port, &tempPath);
    if (strcpy_s(prefix, MAX_URI_LENGTH, tempPrefix) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(address, MAX_URI_LENGTH, tempAddress) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(path, MAX_URI_LENGTH, tempPath) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    return true;
}

int CreatConnectInfo(const std::string url, lws_context *lwsContext, WebSocketClient *client)
{
    lws_client_connect_info connectInfo = {};
    char prefix[MAX_URI_LENGTH] = {0};
    char address[MAX_URI_LENGTH] = {0};
    char pathWithoutStart[MAX_URI_LENGTH] = {0};
    int port = 0;
    if (!ParseUrl(url, prefix, address, pathWithoutStart, &port)) {
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_PARSEURL_ERROR;
    }
    std::string path = PATH_START + std::string(pathWithoutStart);

    connectInfo.context = lwsContext;
    connectInfo.address = address;
    connectInfo.port = port;
    connectInfo.path = path.c_str();
    connectInfo.host = address;
    connectInfo.origin = address;

    connectInfo.local_protocol_name = "lws-minimal-client1";
    connectInfo.retry_and_idle_policy = &RETRY;
    if (strcmp(prefix, PREFIX_HTTPS) == 0 || strcmp(prefix, PREFIX_WSS) == 0) {
        connectInfo.ssl_connection =
            LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_INSECURE | LCCSCF_ALLOW_SELFSIGNED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.userdata = client;
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGE("Connect lws_context_destroy");
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_TO_SERVER_FAIL;
    }
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Connect(std::string url, struct OpenOptions options)
{
    NETSTACK_LOGI("ClientId:%{public}d, Connect start", this->GetClientContext()->GetClientId());
    if (!options.headers.empty()) {
        if (options.headers.size() > MAX_HEADER_LENGTH) {
            return WebSocketErrorCode::WEBSOCKET_ERROR_NO_HEADR_EXCEEDS;
        }
        for (const auto &item : options.headers) {
            const std::string &key = item.first;
            const std::string &value = item.second;
            this->GetClientContext()->header[key] = value;
        }
    }
    lws_context_creation_info info = {};
    FillContextInfo(info);
    lws_context *lwsContext = lws_create_context(&info);
    if (lwsContext == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_CONNECTION_NO_MEMOERY;
    }
    this->GetClientContext()->SetContext(lwsContext);
    int ret = CreatConnectInfo(url, lwsContext, this);
    if (ret != WEBSOCKET_NONE_ERR) {
        NETSTACK_LOGE("websocket CreatConnectInfo error");
        GetClientContext()->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        return ret;
    }
    std::thread serviceThread(RunService, this);
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_CLIENT_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_CLIENT_THREAD_RUN);
#endif
    serviceThread.detach();
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Send(char *data, size_t length)
{
    if (data == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_SEND_DATA_NULL;
    }
    if (length > MAX_DATA_LENGTH) {
        return WebSocketErrorCode::WEBSOCKET_DATA_LENGTH_EXCEEDS;
    }
    if (this->GetClientContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX;
    }
    this->GetClientContext()->Push(data, length, LWS_WRITE_TEXT);
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Close(CloseOption options)
{
    NETSTACK_LOGI("Close start");
    if (this->GetClientContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_NO_CLIENTCONTEX;
    }
    if (this->GetClientContext()->openStatus == 0)
        return WebSocketErrorCode::WEBSOCKET_ERROR_HAVE_NO_CONNECT;

    if (options.reason == nullptr || options.code == 0) {
        options.reason = "";
        options.code = CLOSE_RESULT_FROM_CLIENT_CODE;
    }
    this->GetClientContext()->Close(static_cast<lws_close_status>(options.code), options.reason);
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Registcallback(OnOpenCallback onOpen, OnMessageCallback onMessage, OnErrorCallback onError,
                                    OnCloseCallback onClose)
{
    onMessageCallback_ = onMessage;
    onCloseCallback_ = onClose;
    onErrorCallback_ = onError;
    onOpenCallback_ = onOpen;
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

int WebSocketClient::Destroy()
{
    NETSTACK_LOGI("Destroy start");
    if (this->GetClientContext()->GetContext() == nullptr) {
        return WebSocketErrorCode::WEBSOCKET_ERROR_HAVE_NO_CONNECT_CONTEXT;
    }
    this->GetClientContext()->SetContext(nullptr);
    lws_context_destroy(this->GetClientContext()->GetContext());
    return WebSocketErrorCode::WEBSOCKET_NONE_ERR;
}

} // namespace OHOS::NetStack::WebSocketClient