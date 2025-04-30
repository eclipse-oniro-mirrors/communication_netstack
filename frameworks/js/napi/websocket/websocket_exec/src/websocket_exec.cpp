/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "websocket_exec.h"

#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <shared_mutex>

#include "constant.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"

#ifdef HAS_NETMANAGER_BASE
#include "http_proxy.h"
#include "net_conn_client.h"
#endif
#define LWS_PLUGIN_STATIC

static constexpr const char *PROTOCOL_DELIMITER = "//";

static constexpr const char *NAME_END = ":";

static constexpr const char *STATUS_LINE_SEP = " ";

static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;

static constexpr const char *PREFIX_HTTPS = "https";

static constexpr const char *PREFIX_WSS = "wss";

static constexpr const char *PREFIX_WS = "ws";

static constexpr const int MAX_URI_LENGTH = 2048;

static constexpr const int MAX_HDR_LENGTH = 1024;

static constexpr const int MAX_PROTOCOL_LENGTH = 1024;

static constexpr const int MAX_ADDRESS_LENGTH = 1024;

static constexpr const int FD_LIMIT_PER_THREAD = 1 + 1 + 1;

static constexpr const int COMMON_ERROR_CODE = 200;

static constexpr const char *EVENT_KEY_CODE = "code";

static constexpr const char *EVENT_KEY_STATUS = "status";

static constexpr const char *EVENT_KEY_REASON = "reason";

static constexpr const char *EVENT_KEY_MESSAGE = "message";

static constexpr const char *LINK_DOWN = "The link is down";

static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;

static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";

static constexpr const char *WEBSOCKET_SYSTEM_PREPARE_CA_PATH = "/etc/security/certificates";

static constexpr const char *WEBSOCKET_CLIENT_THREAD_RUN = "OS_NET_WSJsCli";

#ifdef NETSTACK_WEBSOCKETSERVER
static constexpr const char *EVENT_KEY_CLIENT_PORT = "clientPort";

static constexpr const char *EVENT_KEY_CLIENT_IP = "clientIP";

static constexpr const char *EVENT_KEY_CONNECTION = "clientConnection";

static constexpr const char *EVENT_KEY_RESULT = "result";

static constexpr const char *EVENT_KEY_DATA = "data";

static constexpr const char *WEBSOCKET_SERVER_THREAD_RUN = "OS_NET_WSJsSer";

static constexpr const uint32_t MAX_CONCURRENT_CLIENTS_NUMBER = 10;

static constexpr const uint32_t MAX_CONNECTIONS_FOR_ONE_CLIENT = 10;

static constexpr const uint64_t ONE_MINUTE_IN_SEC = 60;

static constexpr const int32_t MAX_CONNECTIONS_PER_MINUTE = 50;
#endif

namespace OHOS::NetStack::Websocket {

#ifdef NETSTACK_WEBSOCKETSERVER
static std::shared_mutex wsMutex_;

static std::shared_mutex connListMutex_;

static std::shared_mutex banListMutex_;

static std::unordered_map<std::string, uint64_t> banList;

static std::unordered_map<std::string, ClientInfo> clientList;

static std::unordered_map<std::string,
    std::pair<lws*, OHOS::NetStack::Websocket::WebSocketConnection>> webSocketConnection_;

static const lws_protocols LWS_SERVER_PROTOCOLS[] = {
    {"lws_server", WebSocketExec::lwsServerCallback, 0, 0 },
    { NULL, NULL, 0, 0 },  // this line is needed
};
#endif

static const lws_protocols LWS_PROTOCOLS[] = {
    {"lws-minimal-client", WebSocketExec::LwsCallback, 0, 0},
    {nullptr, nullptr, 0, 0}, // this line is needed
};

static const lws_retry_bo_t RETRY = {
    .secs_since_valid_ping = 30,
    .secs_since_valid_hangup = 60,
    .jitter_percent = 20,
};

struct CallbackDispatcher {
    lws_callback_reasons reason;
    int (*callback)(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len);
};

struct OnOpenClosePara {
    OnOpenClosePara() : status(0) {}
    uint32_t status;
    std::string message;
};

#ifdef NETSTACK_WEBSOCKETSERVER
struct CloseResult {
    uint32_t code;
    std::string reason;
};

struct ClientConnectionCloseCallback {
    WebSocketConnection connection;
    CloseResult closeResult;
};

static const lws_http_mount mount = {
    NULL,
    "/",
    "./mount-origin",
    "index.html",
    NULL,
    NULL,
    NULL,
    NULL,
    0,
    0,
    0,
    0,
    0,
    0,
    LWSMPRO_FILE,
    1,
    NULL,
};
#endif

static const std::vector<std::string> WS_PREFIX = {PREFIX_WSS, PREFIX_WS};

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

template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplate(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);
    auto undefined = NapiUtils::GetUndefined(workWrapper->env);
    std::pair<napi_value, napi_value> arg = {undefined, obj};
    if (workWrapper->manager) {
        workWrapper->manager->Emit(workWrapper->type, arg);
        if (workWrapper->type == EventName::EVENT_MESSAGE &&
            workWrapper->manager->HasEventListener(EventName::EVENT_DATA_END)) {
            workWrapper->manager->Emit(EventName::EVENT_DATA_END, {undefined, undefined});
        }
    }
    delete workWrapper;
    delete work;
}

bool WebSocketExec::ParseUrl(ConnectContext *context, char *protocol, size_t protocolLen, char *address,
                             size_t addressLen, char *path, size_t pathLen, int *port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, MAX_URI_LENGTH, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempProt = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempProt, &tempAddress, port, &tempPath);
    if (strcpy_s(protocol, protocolLen, tempProt) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (std::find(WS_PREFIX.begin(), WS_PREFIX.end(), protocol) == WS_PREFIX.end()) {
        NETSTACK_LOGE("protocol failed");
        return false;
    }
    if (strcpy_s(address, addressLen, tempAddress) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (strcpy_s(path, pathLen, tempPath) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    return true;
}

void RunService(std::shared_ptr<UserData> userData, std::shared_ptr<EventManager> manager)
{
    NETSTACK_LOGI("websocket run service start");
    int res = 0;
    lws_context *context = userData->GetContext();
    if (context == nullptr) {
        NETSTACK_LOGE("context is null");
        return;
    }
    while (res >= 0 && !userData->IsThreadStop()) {
        res = lws_service(context, 0);
    }
    NETSTACK_LOGE("lws_service stop");
    lws_context_destroy(context);
    userData->SetContext(nullptr);
    manager->SetWebSocketUserData(nullptr);
    NETSTACK_LOGI("websocket run service end");
}

int WebSocketExec::RaiseError(EventManager *manager, uint32_t httpResponse)
{
    OnError(manager, COMMON_ERROR_CODE, httpResponse);
    return -1;
}

#ifdef NETSTACK_WEBSOCKETSERVER
int WebSocketExec::RaiseServerError(EventManager *manager, uint32_t httpResponse)
{
    OnServerError(manager, COMMON_ERROR_CODE);
    return -1;
}
#endif

uint32_t WebSocketExec::GetHttpResponseFromWsi(lws *wsi)
{
    if (wsi == nullptr) {
        return 0;
    }
    return lws_http_client_http_response(wsi);
}

int WebSocketExec::HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    if (ret < 0) {
        OnError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    }
    return 0;
}

int WebSocketExec::LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                          size_t len)
{
    NETSTACK_LOGD("lws callback client append handshake header");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    auto payload = reinterpret_cast<unsigned char **>(in);
    if (payload == nullptr || (*payload) == nullptr || len == 0) {
        NETSTACK_LOGE("header payload is null, do not append header");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto payloadEnd = (*payload) + len;
    for (const auto &pair : userData->header) {
        std::string name = pair.first + NAME_END;
        if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char *>(name.c_str()),
                                        reinterpret_cast<const unsigned char *>(pair.second.c_str()),
                                        static_cast<int>(strlen(pair.second.c_str())), payload, payloadEnd)) {
            NETSTACK_LOGE("add header failed");
            return RaiseError(manager, GetHttpResponseFromWsi(wsi));
        }
    }
    NETSTACK_LOGI("add header OK");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                   size_t len)
{
    NETSTACK_LOGD("lws callback ws peer initiated close");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGI("No close reason");
        userData->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }

    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    userData->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientWritable(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client writable");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (userData->IsClosed()) {
        NETSTACK_LOGI("need to close");
        lws_close_reason(wsi, userData->closeStatus,
                         reinterpret_cast<unsigned char *>(const_cast<char *>(userData->closeReason.c_str())),
                         strlen(userData->closeReason.c_str()));
        // here do not emit error, because we close it
        return -1;
    }
    auto sendData = userData->Pop();
    if (sendData.data == nullptr || sendData.length == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }
    int sendLength = lws_write(wsi, reinterpret_cast<unsigned char *>(sendData.data) + LWS_SEND_BUFFER_PRE_PADDING,
                               sendData.length, sendData.protocol);
    free(sendData.data);
    NETSTACK_LOGD("lws send data length is %{public}d", sendLength);
    if (!userData->IsEmpty()) {
        userData->TriggerWritable();
    }
    return HttpDummy(wsi, reason, user, in, len);
}

static napi_value CreateConnectError(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<int, uint32_t> *>(callbackPara);
    auto deleter = [](std::pair<int, uint32_t> *p) { delete p; };
    std::unique_ptr<std::pair<int, uint32_t>, decltype(deleter)> handler(pair, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, pair->first);
    NapiUtils::SetStringPropertyUtf8(env, err, "data", std::to_string(pair->second));
    return err;
}

void OnConnectError(EventManager *manager, int32_t code, uint32_t httpResponse)
{
    NETSTACK_LOGI("OnError %{public}d", code);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (auto userData = manager->GetWebSocketUserData(); userData != nullptr) {
        NETSTACK_LOGI("OnConnectError SetThreadStop");
        userData->SetThreadStop(true);
    }
    if (!manager->HasEventListener(EventName::EVENT_ERROR)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_ERROR);
        return;
    }
    auto pair = new std::pair<int, uint32_t>;
    pair->first = code;
    pair->second = httpResponse;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_ERROR, pair, CallbackTemplate<CreateConnectError>);
}

int WebSocketExec::LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                    size_t len)
{
    NETSTACK_LOGD("lws callback client connection error");
    NETSTACK_LOGI("Lws client connection error %{public}s", (in == nullptr) ? "null" : reinterpret_cast<char *>(in));
    // 200 means connect failed
    OnConnectError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client receive");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto isFinal = lws_is_final_fragment(wsi);
    OnMessage(manager, in, len, lws_frame_is_binary(wsi), isFinal);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                       size_t len)
{
    NETSTACK_LOGD("lws callback client filter preEstablish");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    userData->openStatus = GetHttpResponseFromWsi(wsi);
    char statusLine[MAX_HDR_LENGTH] = {0};
    if (lws_hdr_copy(wsi, statusLine, MAX_HDR_LENGTH, WSI_TOKEN_HTTP) < 0 || strlen(statusLine) == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }

    auto vec = CommonUtils::Split(statusLine, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);
    if (vec.size() >= FUNCTION_PARAM_TWO) {
        userData->openMessage = vec[1];
    }

    char buffer[MAX_HDR_LENGTH] = {};
    std::map<std::string, std::string> responseHeader;
    for (int i = 0; i < WSI_TOKEN_COUNT; i++) {
        if (lws_hdr_total_length(wsi, static_cast<lws_token_indexes>(i)) > 0) {
            lws_hdr_copy(wsi, buffer, sizeof(buffer), static_cast<lws_token_indexes>(i));
            std::string str;
            if (lws_token_to_string(static_cast<lws_token_indexes>(i))) {
                str =
                    std::string(reinterpret_cast<const char *>(lws_token_to_string(static_cast<lws_token_indexes>(i))));
            }
            if (!str.empty() && str.back() == ':') {
                responseHeader.emplace(str.substr(0, str.size() - 1), std::string(buffer));
            }
        }
    }
    lws_hdr_custom_name_foreach(
        wsi,
        [](const char *name, int nlen, void *opaque) -> void {
            auto header = static_cast<std::map<std::string, std::string> *>(opaque);
            if (header == nullptr) {
                return;
            }
            header->emplace(std::string(name).substr(0, nlen - 1), std::string(name).substr(nlen));
        },
        &responseHeader);
    OnHeaderReceive(manager, responseHeader);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client established");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->TriggerWritable();
    userData->SetLws(wsi);
    OnOpen(reinterpret_cast<EventManager *>(user), userData->openStatus, userData->openMessage);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback client closed");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->SetThreadStop(true);
    if ((userData->closeReason).empty()) {
        userData->Close(userData->closeStatus, LINK_DOWN);
    }
    if (userData->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnError(manager, COMMON_ERROR_CODE, GetHttpResponseFromWsi(wsi));
    }
    OnClose(reinterpret_cast<EventManager *>(user), userData->closeStatus, userData->closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback wsi destroy");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->SetLws(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback protocol destroy");
    return HttpDummy(wsi, reason, user, in, len);
}

// len: he number of days left before it expires
int WebSocketExec::LwsCallbackVhostCertAging(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws callback vhost cert aging. len: %{public}zu", len);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws callback reason is %{public}d", reason);
    CallbackDispatcher dispatchers[] = {
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
        {LWS_CALLBACK_VHOST_CERT_AGING, LwsCallbackVhostCertAging},
    };
    for (const auto dispatcher : dispatchers) {
        if (dispatcher.reason == reason) {
            return dispatcher.callback(wsi, reason, user, in, len);
        }
    }
    return HttpDummy(wsi, reason, user, in, len);
}

#ifdef NETSTACK_WEBSOCKETSERVER
int WebSocketExec::lwsServerCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("lws server callback reason is %{public}d", reason);
    CallbackDispatcher dispatchers[] = {
        {LWS_CALLBACK_ESTABLISHED, LwsCallbackEstablished},
        {LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION, LwsCallbackFilterProtocolConnection},
        {LWS_CALLBACK_RECEIVE, LwsCallbackReceive},
        {LWS_CALLBACK_SERVER_WRITEABLE, LwsCallbackServerWriteable},
        {LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, LwsCallbackWsPeerInitiatedCloseServer},
        {LWS_CALLBACK_CLOSED, LwsCallbackClosed},
        {LWS_CALLBACK_WSI_DESTROY, LwsCallbackWsiDestroyServer},
        {LWS_CALLBACK_PROTOCOL_DESTROY, LwsCallbackProtocolDestroyServer},
    };
    for (const auto dispatcher : dispatchers) {
        if (dispatcher.reason == reason) {
            return dispatcher.callback(wsi, reason, user, in, len);
        }
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws callback server established");
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
// bind clientuserdata with wsi
    lws_context* lwsContext = lws_get_context(wsi);
    std::shared_ptr<UserData> clientUserData;
    clientUserData = std::make_shared<UserData>(lwsContext);
    lws_set_wsi_user(wsi, clientUserData.get());

    std::string clientId;
    WebSocketConnection connection;
    bool ret = GetPeerConnMsg(wsi, manager, clientId, connection);
    if (!ret) {
        NETSTACK_LOGE("GetPeerConnMsg failed");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    NETSTACK_LOGI("connection clientip=%{public}s, clientport=%{public}d",
        connection.clientIP.c_str(), connection.clientPort);
    AddConnections(clientId, wsi, userData, connection);
    clientUserData->SetLws(wsi);
    clientUserData->TriggerWritable();
    OnConnect(wsi, manager);
    return HttpDummy(wsi, reason, user, in, len);
}

bool WebSocketExec::GetPeerConnMsg(lws *wsi, EventManager *manager, std::string &clientId, WebSocketConnection &conn)
{
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    int ret = getpeername(lws_get_socket_fd(wsi), reinterpret_cast<sockaddr *>(&addr), &addrLen);
    if (ret != 0) {
        NETSTACK_LOGE("getpeername failed");
        return false;
    }
    char ipStr[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        NETSTACK_LOGI("family is ipv4");
        auto *addrIn = reinterpret_cast<struct sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addrIn->sin_addr, ipStr, sizeof(ipStr));
        uint16_t port = ntohs(addrIn->sin_port);
        conn.clientPort = static_cast<uint32_t>(port);
        conn.clientIP = ipStr;
        clientId = std::string(ipStr) + ":" + std::to_string(port);
    } else if (addr.ss_family == AF_INET6) {
        NETSTACK_LOGI("family is ipv6");
        auto *addrIn6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addrIn6->sin6_addr, ipStr, sizeof(ipStr));
        uint16_t port = ntohs(addrIn6->sin6_port);
        conn.clientPort = static_cast<uint32_t>(port);
        conn.clientIP = ipStr;
        clientId = std::string(ipStr) + ":" + std::to_string(port);
    } else {
        NETSTACK_LOGE("getpeer Ipv4 or Ipv6 failed");
        return false;
    }
    return true;
}

bool WebSocketExec::IsOverMaxClientConns(EventManager *manager)
{
    std::vector<WebSocketConnection> connection = GetConnections();
    if (connection.size() >= manager->GetMaxConnClientCnt() * manager->GetMaxConnForOneClient()) {
        NETSTACK_LOGE("current connections is over limit");
        return true;
    }
    return false;
}

void WebSocketExec::AddConnections(const std::string &Id, lws *wsi,
    std::shared_ptr<UserData> &userData, WebSocketConnection &conn)
{
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("AddConnections failed: session %s", userData->IsClosed() ? "closed" : "thread stopped");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> lock(wsMutex_);
        webSocketConnection_[Id].first = wsi;
        webSocketConnection_[Id].second = conn;
        NETSTACK_LOGI("AddConnections success");
    }
}

int WebSocketExec::LwsCallbackClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("lws callback server closed");
    if (wsi ==nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto clientUserData = reinterpret_cast<UserData*>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUserData is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    clientUserData->SetThreadStop(true);
    if ((clientUserData->closeReason).empty()) {
        clientUserData->Close(clientUserData->closeStatus, LINK_DOWN);
    }
    if (clientUserData->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnServerError(manager, COMMON_ERROR_CODE);
    }
    std::string clientId;
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        for (auto it = webSocketConnection_.begin(); it != webSocketConnection_.end(); ++it) {
            if (it->second.first == wsi) {
                clientId = it->first;
            }
        }
    }
    OnServerClose(wsi, manager, clientUserData->closeStatus, clientUserData->closeReason);
    RemoveConnections(clientId, *clientUserData);
    if (userData->IsClosed() && webSocketConnection_.empty()) {
        NETSTACK_LOGI("server service is stopped");
        userData->SetThreadStop(true);
    }
    return HttpDummy(wsi, reason, user, in, len);
}

void WebSocketExec::RemoveConnections(const std::string &id, UserData &userData)
{
    if (webSocketConnection_.empty()) {
        NETSTACK_LOGE("connection list is empty");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.find(id) == webSocketConnection_.end()) {
            NETSTACK_LOGE("connection list find clientId failed");
            return;
        }
        webSocketConnection_.erase(id);
        NETSTACK_LOGI("connection erase success");
    }
}

int WebSocketExec::LwsCallbackWsiDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws server callback wsi destroy");
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    userData->SetLws(nullptr);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackProtocolDestroyServer(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws server callback protocol destroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackServerWriteable(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws callback Server writable");
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    // server
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (userData->IsThreadStop()) {
        NETSTACK_LOGI("session is stopped");
        return -1;
    }
    // client
    auto* clientUserData = reinterpret_cast<UserData*>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUserData is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (clientUserData->IsClosed()) {
        NETSTACK_LOGI("client is closed, need to close");
        lws_close_reason(wsi, clientUserData->closeStatus,
                         reinterpret_cast<unsigned char *>(const_cast<char *>(clientUserData->closeReason.c_str())),
                         strlen(clientUserData->closeReason.c_str()));
        return -1;
    }
    auto sendData = clientUserData->Pop();
    if (sendData.data == nullptr || sendData.length == 0) {
        NETSTACK_LOGE("send data is empty");
        return HttpDummy(wsi, reason, user, in, len);
    }
    int sendLength = lws_write(wsi, reinterpret_cast<unsigned char *>(sendData.data) + LWS_SEND_BUFFER_PRE_PADDING,
                               sendData.length, sendData.protocol);
    free(sendData.data);
    NETSTACK_LOGD("lws send data length is %{public}d", sendLength);
    if (!userData->IsEmpty()) {
        NETSTACK_LOGE("userData is not empty");
        userData->TriggerWritable();
    }
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsPeerInitiatedCloseServer(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws server callback ws peer initiated close");
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is null");
        return -1;
    }
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }

    if (in == nullptr || len < sizeof(uint16_t)) {
        NETSTACK_LOGI("No close reason");
        userData->Close(LWS_CLOSE_STATUS_NORMAL, "");
        return HttpDummy(wsi, reason, user, in, len);
    }

    uint16_t closeStatus = ntohs(*reinterpret_cast<uint16_t *>(in));
    std::string closeReason;
    closeReason.append(reinterpret_cast<char *>(in) + sizeof(uint16_t), len - sizeof(uint16_t));
    auto* clientUserData = reinterpret_cast<UserData*>(lws_wsi_user(wsi));
    clientUserData->Close(static_cast<lws_close_status>(closeStatus), closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackFilterProtocolConnection(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws server callback filter ProtocolConnection");
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or thread is stopped");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (!IsAllowedProtocol(wsi)) {
        NETSTACK_LOGE("protocol is not allowed");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    /* 是否超过最大连接数 */
    if (IsOverMaxClientConns(manager)) {
        NETSTACK_LOGE("current connections count is more than limit, need to close");
        return RaiseServerError(manager, GetHttpResponseFromWsi(wsi));
    }
    /* 添加防止恶意连接的业务逻辑 */
    std::string clientId;
    WebSocketConnection connection;
    bool ret = GetPeerConnMsg(wsi, manager, clientId, connection);
    if (!ret) {
        NETSTACK_LOGE("GetPeerConnMsg failed");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    if (!IsAllowConnection(clientId)) {
        NETSTACK_LOGE("Rejected malicious connection");
        return RaiseError(manager, GetHttpResponseFromWsi(wsi));
    }
    return HttpDummy(wsi, reason, user, in, len);
}

bool WebSocketExec::IsAllowConnection(const std::string &clientId)
{
    if (IsIpInBanList(clientId)) {
        NETSTACK_LOGE("clientid is in banList");
        return false;
    }
    if (IsHighFreqConnection(clientId)) {
        NETSTACK_LOGE("clientid reach high frequency connection");
        AddBanList(clientId);
        return false;
    }
    UpdataClientList(clientId);
    return true;
}

void WebSocketExec::UpdataClientList(const std::string &id)
{
    std::shared_lock<std::shared_mutex> lock(connListMutex_);
    auto it = clientList.find(id);
    if (it == clientList.end()) {
        NETSTACK_LOGI("add clientid to banList");
        clientList[id] = {1, GetCurrentSecond()};
    } else {
        auto now = GetCurrentSecond() - it->second.lastConnectionTime;
        if (now > ONE_MINUTE_IN_SEC) {
            NETSTACK_LOGI("reset clientid connections cnt");
            it->second = {1, GetCurrentSecond()};
        } else {
            it->second.cnt++;
        }
    }
}

void WebSocketExec::AddBanList(const std::string &id)
{
    std::shared_lock<std::shared_mutex> lock(banListMutex_);
    banList[id] = GetCurrentSecond() + ONE_MINUTE_IN_SEC;
}

bool WebSocketExec::IsIpInBanlist(const std::string &id)
{
    std::shared_lock<std::shared_mutex> lock(banListMutex_);
    auto it = banList.find(id);
    if (it != banList.end()) {
        auto now = GetCurrentSecond();
        if (now < it->second) {
            return true;
        } else {
            banList.erase(it);
        }
    }
    return false;
}

uint64_t WebSocketExec::GetCurrentSecond()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool WebSocketExec::IsHighFreqConnection(const std::string &id)
{
    std::shared_lock<std::shared_mutex> lock(connListMutex_);
    auto it = clientList.find(id);
    if (it != clientList.end()) {
        auto duration = GetCurrentSecond() - it->second.lastConnectionTime;
        if (duration <= ONE_MINUTE_IN_SEC) {
            return it->second.cnt > MAX_CONNECTIONS_PER_MINUTE;
        }
    }
    return false;
}

bool WebSocketExec::IsAllowedProtocol(lws *wsi)
{
    char requested_protocol[128] = {0};
    int32_t res = lws_hdr_copy(wsi, requested_protocol, sizeof(requested_protocol), WSI_TOKEN_PROTOCOL);
    if (res < 0) {
        NETSTACK_LOGE("fail to read protocol");
        return true;
    }
    if (strcmp(requested_protocol, "lws_server") != 0) {
        NETSTACK_LOGE("Protocol mismatch: client requested: %{public}s, server expects lws_server", requested_protocol);
        return true;
    }
    return true;
}

int WebSocketExec::LwsCallbackReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in,
    size_t len)
{
    NETSTACK_LOGD("lws callback server receive");
    lws_context* context = lws_get_context(wsi);
    EventManager* manager = static_cast<EventManager*>(lws_context_user(context));
    auto isFinal = lws_is_final_fragment(wsi);
    OnServerMessage(wsi, manager, in, len, lws_frame_is_binary(wsi), isFinal);
    return HttpDummy(wsi, reason, user, in, len);
}
#endif

void WebSocketExec::FillContextInfo(ConnectContext *context, lws_context_creation_info &info, char *proxyAds)
{
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = LWS_PROTOCOLS;
    info.fd_limit_per_thread = FD_LIMIT_PER_THREAD;

    char tempUri[MAX_URI_LENGTH] = {0};
    const char *tempProtocol = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    int32_t tempPort = 0;

    std::string host;
    uint32_t port = 0;
    std::string exclusions;

    if (strcpy_s(tempUri, MAX_URI_LENGTH, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return;
    }
    if (lws_parse_uri(tempUri, &tempProtocol, &tempAddress, &tempPort, &tempPath) != 0) {
        NETSTACK_LOGE("get websocket hostname failed");
        return;
    }
    GetWebsocketProxyInfo(context, host, port, exclusions);
    if (!host.empty() && !CommonUtils::IsHostNameExcluded(tempAddress, exclusions, ",")) {
        if (strcpy_s(proxyAds, host.length() + 1, host.c_str()) != EOK) {
            NETSTACK_LOGE("memory copy failed");
        }
        info.http_proxy_address = proxyAds;
        info.http_proxy_port = port;
    }
}

bool WebSocketExec::CreatConnectInfo(ConnectContext *context, lws_context *lwsContext,
                                     const std::shared_ptr<EventManager> &manager)
{
    lws_client_connect_info connectInfo = {};
    char protocol[MAX_URI_LENGTH] = {0};
    char address[MAX_URI_LENGTH] = {0};
    char path[MAX_URI_LENGTH] = {0};
    char customizedProtocol[MAX_PROTOCOL_LENGTH] = {0};
    int port = 0;

    if (!ParseUrl(context, protocol, MAX_URI_LENGTH, address, MAX_URI_LENGTH, path, MAX_URI_LENGTH, &port)) {
        NETSTACK_LOGE("ParseUrl failed");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_URL_ERROR);
        return false;
    }
    if (lwsContext == nullptr) {
        NETSTACK_LOGE("no memory");
        return false;
    }
    std::string tempHost = std::string(address) + NAME_END + std::to_string(port);
    std::string tempOrigin = std::string(protocol) + NAME_END + PROTOCOL_DELIMITER + tempHost;
    NETSTACK_LOGD("tempOrigin = %{private}s", tempOrigin.c_str());
    if (strcpy_s(customizedProtocol, context->GetProtocol().length() + 1, context->GetProtocol().c_str()) != EOK) {
        NETSTACK_LOGE("memory copy failed");
    }

    connectInfo.context = lwsContext;
    connectInfo.port = port;
    connectInfo.address = address;
    connectInfo.path = path;
    connectInfo.host = address;
    connectInfo.origin = address;
    connectInfo.protocol = customizedProtocol;

    if (strcmp(protocol, PREFIX_HTTPS) == 0 || strcmp(protocol, PREFIX_WSS) == 0) {
        connectInfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_SELFSIGNED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.retry_and_idle_policy = &RETRY;
    connectInfo.userdata = manager.get();
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGI("ExecConnect websocket connect failed");
        context->SetErrorCode(-1);
        OnConnectError(manager.get(), COMMON_ERROR_CODE, 0);
        return false;
    }
    return true;
}

static bool CheckFilePath(std::string &path)
{
    char tmpPath[PATH_MAX] = {0};
    if (!realpath(static_cast<const char *>(path.c_str()), tmpPath)) {
        NETSTACK_LOGE("path is error");
        return false;
    }
    path = tmpPath;
    return true;
}

bool WebSocketExec::FillCaPath(ConnectContext *context, lws_context_creation_info &info)
{
    if (!context->caPath_.empty()) {
        if (!CheckFilePath(context->caPath_)) {
            NETSTACK_LOGE("ca not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        info.client_ssl_ca_filepath = context->caPath_.c_str();
        NETSTACK_LOGD("load customize CA: %{public}s", info.client_ssl_ca_filepath);
    } else {
        info.client_ssl_ca_dirs[0] = WEBSOCKET_SYSTEM_PREPARE_CA_PATH;
#ifdef HAS_NETMANAGER_BASE
        if (NetManagerStandard::NetConnClient::GetInstance().TrustUserCa()) {
            context->userCertPath_ = BASE_PATH + std::to_string(getuid() / UID_TRANSFORM_DIVISOR);
            info.client_ssl_ca_dirs[1] = context->userCertPath_.c_str();
        }
#endif
        NETSTACK_LOGD("load system CA");
    }
    if (!context->clientCert_.empty()) {
        char realKeyPath[PATH_MAX] = {0};
        if (!CheckFilePath(context->clientCert_) || !realpath(context->clientKey_.Data(), realKeyPath)) {
            NETSTACK_LOGE("client cert not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        context->clientKey_ = Secure::SecureChar(realKeyPath);
        info.client_ssl_cert_filepath = context->clientCert_.c_str();
        info.client_ssl_private_key_filepath = context->clientKey_.Data();
        info.client_ssl_private_key_password = context->keyPassword_.Data();
    }
    return true;
}

bool WebSocketExec::ExecConnect(ConnectContext *context)
{
    NETSTACK_LOGD("websocket Connect exec");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->IsAtomicService() &&
        !CommonUtils::IsAllowedHostname(context->GetBundleName(), CommonUtils::DOMAIN_TYPE_WEBSOCKET_REQUEST,
                                        context->url)) {
        context->SetNoAllowedHost(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        return false;
    }
    lws_context_creation_info info = {};
    char proxyAds[MAX_ADDRESS_LENGTH] = {0};
    FillContextInfo(context, info, proxyAds);
    if (!FillCaPath(context, info)) {
        return false;
    }
    lws_context *lwsContext = nullptr;
    std::shared_ptr<UserData> userData;
    if (manager->GetWebSocketUserData() == nullptr) {
        lwsContext = lws_create_context(&info);
        userData = std::make_shared<UserData>(lwsContext);
        userData->header = context->header;
        manager->SetWebSocketUserData(userData);
    } else {
        NETSTACK_LOGE("Websocket connect already exist");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST);
        return false;
    }
    if (!CreatConnectInfo(context, lwsContext, manager)) {
        userData->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        manager->SetWebSocketUserData(nullptr);
        return false;
    }
    std::thread serviceThread(RunService, userData, manager);

#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_CLIENT_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_CLIENT_THREAD_RUN);
#endif
    serviceThread.detach();
    return true;
}

napi_value WebSocketExec::ConnectCallback(ConnectContext *context)
{
    if (context->GetErrorCode() < 0) {
        NETSTACK_LOGI("ConnectCallback connect failed");
        return NapiUtils::GetBoolean(context->GetEnv(), false);
    }
    NETSTACK_LOGI("ConnectCallback connect success");
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

bool WebSocketExec::ExecSend(SendContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    userData->Push(context->data, context->length, context->protocol);
    userData->TriggerWritable();
    NETSTACK_LOGD("lws ts send success");
    return true;
}

napi_value WebSocketExec::SendCallback(SendContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

bool WebSocketExec::ExecClose(CloseContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->GetSharedManager() == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }

    auto manager = context->GetSharedManager();
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }

    if (userData->IsClosed()) {
        NETSTACK_LOGE("connection has been closed");
        return false;
    }
    userData->Close(static_cast<lws_close_status>(context->code), context->reason);
    userData->TriggerWritable();
    NETSTACK_LOGI("ExecClose OK");
    return true;
}

napi_value WebSocketExec::CloseCallback(CloseContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager != nullptr) {
        NETSTACK_LOGD("websocket close, delete js ref");
        manager->DeleteEventReference(context->GetEnv());
    }
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

static napi_value CreateError(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<int, uint32_t> *>(callbackPara);
    auto deleter = [](std::pair<int, uint32_t> *p) { delete p; };
    std::unique_ptr<std::pair<int, uint32_t>, decltype(deleter)> handler(pair, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, pair->first);
    NapiUtils::SetStringPropertyUtf8(env, err, "data", std::to_string(pair->second));
    return err;
}

static napi_value CreateOpenPara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<OnOpenClosePara *>(callbackPara);
    auto deleter = [](const OnOpenClosePara *p) { delete p; };
    std::unique_ptr<OnOpenClosePara, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, obj, EVENT_KEY_STATUS, para->status);
    NapiUtils::SetStringPropertyUtf8(env, obj, EVENT_KEY_MESSAGE, para->message);
    return obj;
}

static napi_value CreateClosePara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<OnOpenClosePara *>(callbackPara);
    auto deleter = [](const OnOpenClosePara *p) { delete p; };
    std::unique_ptr<OnOpenClosePara, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, obj, EVENT_KEY_CODE, para->status);
    NapiUtils::SetStringPropertyUtf8(env, obj, EVENT_KEY_REASON, para->message);
    return obj;
}

static napi_value CreateTextMessagePara(napi_env env, void *callbackPara)
{
    auto manager = reinterpret_cast<EventManager *>(callbackPara);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        return NapiUtils::CreateStringUtf8(env, "");
    }
    auto msg = reinterpret_cast<std::string *>(manager->GetQueueData());
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto text = NapiUtils::CreateStringUtf8(env, *msg);
    delete msg;
    return text;
}

static napi_value CreateBinaryMessagePara(napi_env env, void *callbackPara)
{
    auto manager = reinterpret_cast<EventManager *>(callbackPara);
    auto msg = reinterpret_cast<std::string *>(manager->GetQueueData());
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(env, msg->size(), &data);
    if (data != nullptr && NapiUtils::ValueIsArrayBuffer(env, arrayBuffer) &&
        memcpy_s(data, msg->size(), msg->data(), msg->size()) >= 0) {
        delete msg;
        return arrayBuffer;
    }
    delete msg;
    return NapiUtils::GetUndefined(env);
}

#ifdef NETSTACK_WEBSOCKETSERVER
static napi_value CreateServerClosePara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<ClientConnectionCloseCallback *>(callbackPara);
    auto deleter = [](const ClientConnectionCloseCallback *p) { delete p; };
    std::unique_ptr<ClientConnectionCloseCallback, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    napi_value jsConn = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsConn) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsConn, EVENT_KEY_CLIENT_IP, para->connection.clientIP);
    NapiUtils::SetUint32Property(env, jsConn, EVENT_KEY_CLIENT_PORT, para->connection.clientPort);
    NapiUtils::SetNamedProperty(env, obj, EVENT_KEY_CONNECTION, jsConn);
    napi_value jsRes = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsRes) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, jsRes, EVENT_KEY_CODE, para->closeResult.code);
    NapiUtils::SetStringPropertyUtf8(env, jsRes, EVENT_KEY_REASON, para->closeResult.reason);
    NapiUtils::SetNamedProperty(env, obj, EVENT_KEY_RESULT, jsConn);
    return obj;
}

static napi_value ConvertWsBinaryMessageToJs(napi_env env, const WebSocketMessage* msg)
{
    napi_value jsMsg = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(env, msg->data.size(), &data);
    if (data != nullptr && NapiUtils::ValueIsArrayBuffer(env, arrayBuffer) &&
        memcpy_s(data, msg->data.size(), msg->data.c_str(), msg->data.size()) >= 0) {
        NapiUtils::SetNamedProperty(env, jsMsg, "data", arrayBuffer);
        napi_value jsConn = NapiUtils::CreateObject(env);
        if (NapiUtils::GetValueType(env, jsConn) != napi_object) {
            return NapiUtils::GetUndefined(env);
        }
        NapiUtils::SetStringPropertyUtf8(env, jsConn, EVENT_KEY_CLIENT_IP, msg->connection.clientIP);
        NapiUtils::SetUint32Property(env, jsConn, EVENT_KEY_CLIENT_PORT, msg->connection.clientPort);
        NapiUtils::SetNamedProperty(env, jsMsg, EVENT_KEY_CONNECTION, jsConn);
        return jsMsg;
    }
    return NapiUtils::GetUndefined(env);
}

static napi_value CreateServerBinaryMessagePara(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<lws*, std::shared_ptr<EventManager>> *>(callbackPara);
    if (pair == nullptr) {
        NETSTACK_LOGE("pair is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    lws *wsi = pair->first;
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto &manager = pair->second;
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::CreateStringUtf8(env, "");
    }
    auto msg = reinterpret_cast<WebSocketMessage *>(manager->GetServerQueueData(wsi));
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    napi_value jsMsg = ConvertWsBinaryMessageToJs(env, msg);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        delete msg;
        return NapiUtils::GetUndefined(env);
    }
    delete msg;
    return jsMsg;
}

static napi_value ConvertWsTextMessageToJs(napi_env env, const WebSocketMessage* msg)
{
    napi_value jsMsg = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsMsg, EVENT_KEY_DATA, msg->data);
    napi_value jsConn = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, jsConn) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetStringPropertyUtf8(env, jsConn, EVENT_KEY_CLIENT_IP, msg->connection.clientIP);
    NapiUtils::SetUint32Property(env, jsConn, EVENT_KEY_CLIENT_PORT, msg->connection.clientPort);
    NapiUtils::SetNamedProperty(env, jsMsg, EVENT_KEY_CONNECTION, jsConn);
    return jsMsg;
}

static napi_value CreateServerTextMessagePara(napi_env env, void *callbackPara)
{
    auto pair = reinterpret_cast<std::pair<lws*, std::shared_ptr<EventManager>> *>(callbackPara);
    if (pair == nullptr) {
        NETSTACK_LOGE("pair is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    lws *wsi = pair->first;
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto &manager = pair->second;
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::CreateStringUtf8(env, "");
    }
    auto msg = reinterpret_cast<WebSocketMessage *>(manager->GetServerQueueData(wsi));
    if (!msg) {
        NETSTACK_LOGE("msg is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    napi_value jsMsg = ConvertWsTextMessageToJs(env, msg);
    if (NapiUtils::GetValueType(env, jsMsg) != napi_object) {
        NETSTACK_LOGE("jsMsg is not object");
        delete msg;
        return NapiUtils::GetUndefined(env);
    }
    delete msg;
    return jsMsg;
}

static napi_value CreateConnectPara(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<WebSocketConnection *>(callbackPara);
    auto deleter = [](const WebSocketConnection *p) { delete p;};
    std::unique_ptr<WebSocketConnection, decltype(deleter)> handler(para, deleter);
    napi_value obj = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, obj) != napi_object) {
        NETSTACK_LOGE("napi_object not found");
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetUint32Property(env, obj, EVENT_KEY_CLIENT_PORT, para->clientPort);
    NapiUtils::SetStringPropertyUtf8(env, obj, EVENT_KEY_CLIENT_IP, para->clientIP);
    return obj;
}

static napi_value CreateServerError(napi_env env, void *callbackPara)
{
    auto code = reinterpret_cast<int32_t *>(callbackPara);
    if (code == nullptr) {
        NETSTACK_LOGE("code is nullptr");
    }
    auto deleter = [](int32_t *p) { delete p; };
    std::unique_ptr<int32_t, decltype(deleter)> handler(code, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, *code);
    return err;
}

void WebSocketExec::OnServerError(EventManager *manager, int32_t code)
{
    NETSTACK_LOGI("OnServerError %{public}d", code);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerEventListener = manager->HasEventListener(EventName::EVENT_SERVER_ERROR);
    if (!hasServerEventListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_ERROR);
        return;
    }
    auto para = new int32_t(code);
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_ERROR, para, CallbackTemplate<CreateServerError>);
}

void WebSocketExec::OnConnect(lws *wsi, EventManager *manager)
{
    NETSTACK_LOGI("OnConnect enter");
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerConnectListener = manager->HasEventListener(EventName::EVENT_SERVER_CONNECT);
    if (!hasServerConnectListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_CONNECT);
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        auto para = new WebSocketConnection;
        for (auto [id, connPair] : webSocketConnection_) {
            if (connPair.first == wsi) {
                para->clientIP = connPair.second.clientIP;
                para->clientPort = connPair.second.clientPort;
                NETSTACK_LOGI("connection find ok, clientId:%{public}s", id.c_str());
                manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_CONNECT,
                    para, CallbackTemplate<CreateConnectPara>);
                return;
            }
        }
    }
    NETSTACK_LOGE("not found client msg");
}

void WebSocketExec::OnServerClose(lws *wsi, EventManager *manager, lws_close_status closeStatus,
    const std::string &closeReason)
{
    NETSTACK_LOGI("OnServerClose %{public}u %{public}s", closeStatus, closeReason.c_str());
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerCloseListener = manager->HasEventListener(EventName::EVENT_SERVER_CLOSE);
    if (!hasServerCloseListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_CLOSE);
        return;
    }
    auto conn = new ClientConnectionCloseCallback;
    if (conn == nullptr) {
        return;
    }
    conn->closeResult.code = closeStatus;
    conn->closeResult.reason = closeReason;
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        for (auto [id, connPair] : webSocketConnection_) {
            if (connPair.first == wsi) {
                conn->connection = connPair.second;
                NETSTACK_LOGI("clientId: %{public}s", id.c_str());
                manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_CLOSE,
                    conn, CallbackTemplate<CreateServerClosePara>);
                return;
            }
        }
    }
    NETSTACK_LOGE("not found client msg");
}
#endif

void WebSocketExec::OnError(EventManager *manager, int32_t code, uint32_t httpResponse)
{
    NETSTACK_LOGI("OnError %{public}d", code);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_ERROR)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_ERROR);
        return;
    }
    auto pair = new std::pair<int, uint32_t>;
    pair->first = code;
    pair->second = httpResponse;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_ERROR, pair, CallbackTemplate<CreateError>);
}

napi_value CreateResponseHeader(napi_env env, void *callbackPara)
{
    auto para = reinterpret_cast<std::map<std::string, std::string> *>(callbackPara);
    if (para == nullptr) {
        return NapiUtils::GetUndefined(env);
    }
    auto deleter = [](const std::map<std::string, std::string> *p) {
        delete p;
        p = nullptr;
    };
    std::unique_ptr<std::map<std::string, std::string>, decltype(deleter)> handler(para, deleter);
    napi_value header = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, header) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    for (const auto &singleHeader : *para) {
        NapiUtils::SetStringPropertyUtf8(env, header, singleHeader.first, singleHeader.second);
    }
    return header;
}

void WebSocketExec::OnOpen(EventManager *manager, uint32_t status, const std::string &message)
{
    NETSTACK_LOGI("OnOpen %{public}u %{public}s", status, message.c_str());
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_OPEN)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_OPEN);
        return;
    }
    auto para = new OnOpenClosePara;
    para->status = status;
    para->message = message;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_OPEN, para, CallbackTemplate<CreateOpenPara>);
}

void WebSocketExec::OnClose(EventManager *manager, lws_close_status closeStatus, const std::string &closeReason)
{
    NETSTACK_LOGI("OnClose %{public}u %{public}s", closeStatus, closeReason.c_str());
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_CLOSE)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_CLOSE);
        return;
    }
    auto para = new OnOpenClosePara;
    para->status = closeStatus;
    para->message = closeReason;
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_CLOSE, para, CallbackTemplate<CreateClosePara>);
}

void WebSocketExec::OnMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal)
{
    NETSTACK_LOGD("OnMessage %{public}d", isBinary);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_MESSAGE)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_MESSAGE);
        return;
    }
    if (length > INT32_MAX) {
        NETSTACK_LOGE("data length too long");
        return;
    }
    HandleRcvMessage(manager, data, length, isBinary, isFinal);
}

void WebSocketExec::HandleRcvMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal)
{
    if (isBinary) {
        manager->AppendWebSocketBinaryData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWebSocketBinaryData();
            auto msg = new std::string;
            msg->append(msgFromManager.data(), msgFromManager.size());
            manager->SetQueueData(msg);
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_MESSAGE, manager,
                                                CallbackTemplate<CreateBinaryMessagePara>);
            manager->ClearWebSocketBinaryData();
        }
    } else {
        manager->AppendWebSocketTextData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWebSocketTextData();
            auto msg = new (std::nothrow) std::string;
            if (msg == nullptr) {
                return;
            }
            msg->append(msgFromManager.data(), msgFromManager.size());
            manager->SetQueueData(msg);
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_MESSAGE, manager,
                                                CallbackTemplate<CreateTextMessagePara>);
            manager->ClearWebSocketTextData();
        }
    }
}

#ifdef NETSTACK_WEBSOCKETSERVER
void WebSocketExec::OnServerMessage(lws *wsi, EventManager *manager, void *data,
    size_t length, bool isBinary, bool isFinal)
{
    NETSTACK_LOGD("server OnMessage %{public}d", isBinary);
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    bool hasServerEventListener = manager->HasEventListener(EventName::EVENT_SERVER_MESSAGE_RECEIVE);
    if (!hasServerEventListener) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_SERVER_MESSAGE_RECEIVE);
        return;
    }
    if (length > INT32_MAX) {
        NETSTACK_LOGE("data length too long");
        return;
    }
    HandleServerRcvMessage(wsi, manager, data, length, isBinary, isFinal);
}


void WebSocketExec::HandleServerRcvMessage(lws *wsi, EventManager *manager, void *data,
    size_t length, bool isBinary, bool isFinal)
{
    if (isBinary) {
        manager->AppendWsServerBinaryData(wsi, data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWsServerBinaryData(wsi);
            auto msg = new WebSocketMessage;
            if (msg == nullptr) {
                return;
            }
            SetWebsocketMessage(wsi, manager, msgFromManager, msg);
            manager->SetServerQueueData(wsi, msg);
            auto callbackPara = std::make_shared<std::pair<lws*, std::shared_ptr<EventManager>>>(wsi,
                manager->shared_from_this());
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_MESSAGE_RECEIVE, callbackPara.get(),
                                                CallbackTemplate<CreateServerBinaryMessagePara>);
            manager->ClearWsServerBinaryData(wsi);
        }
    } else {
        manager->AppendWsServerTextData(wsi, data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWsServerTextData(wsi);
            if (msgFromManager.empty()) {
                NETSTACK_LOGE("msgFromManager is empty");
                return;
            }
            auto msg = new WebSocketMessage;
            if (msg == nullptr) {
                return;
            }
            SetWebsocketMessage(wsi, manager, msgFromManager, msg);
            manager->SetServerQueueData(wsi, msg);
            auto callbackPara = std::make_shared<std::pair<lws*, std::shared_ptr<EventManager>>>(wsi,
                manager->shared_from_this());
            manager->EmitByUvWithoutCheckShared(EventName::EVENT_SERVER_MESSAGE_RECEIVE, callbackPara.get(),
                                                CallbackTemplate<CreateServerTextMessagePara>);
            manager->ClearWsServerTextData(wsi);
        }
    }
}

void WebSocketExec::SetWebsocketMessage(lws *wsi, EventManager *manager,
    const std::string &msgFromManager, void *dataMsg)
{
    NETSTACK_LOGD("SetWebsocketMessage enter");
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return;
    }
    auto webSocketMessage = static_cast<WebSocketMessage*>(dataMsg);
    webSocketMessage->data = msgFromManager;
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.empty()) {
            NETSTACK_LOGE("webSocketConnection_ is empty");
            return;
        }
        for (auto [_, connPair] : webSocketConnection_) {
            if (connPair.first == wsi) {
                webSocketMessage->connection = connPair.second;
                return;
            }
        }
    }
    NETSTACK_LOGE("not found client msgFromManager");
}
#endif

void WebSocketExec::OnHeaderReceive(EventManager *manager, const std::map<std::string, std::string> &headers)
{
    if (manager == nullptr || manager->innerMagic_.magicNumber != EVENT_MANAGER_MAGIC_NUMBER) {
        NETSTACK_LOGE("manager is null");
        return;
    }

    if (!manager->HasEventListener(EventName::EVENT_HEADER_RECEIVE)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_HEADER_RECEIVE);
        return;
    }
    auto para = new std::map<std::string, std::string>(headers);
    manager->EmitByUvWithoutCheckShared(EventName::EVENT_HEADER_RECEIVE, para, CallbackTemplate<CreateResponseHeader>);
}

void WebSocketExec::GetWebsocketProxyInfo(ConnectContext *context, std::string &host, uint32_t &port,
                                          std::string &exclusions)
{
    if (context->GetUsingWebsocketProxyType() == WebsocketProxyType::USE_SYSTEM) {
#ifdef HAS_NETMANAGER_BASE
        using namespace NetManagerStandard;
        HttpProxy websocketProxy;
        NetConnClient::GetInstance().GetDefaultHttpProxy(websocketProxy);
        host = websocketProxy.GetHost();
        port = websocketProxy.GetPort();
        exclusions = CommonUtils::ToString(websocketProxy.GetExclusionList());
#endif
    } else if (context->GetUsingWebsocketProxyType() == WebsocketProxyType::USE_SPECIFIED) {
        context->GetSpecifiedWebsocketProxy(host, port, exclusions);
    }
}

#ifdef NETSTACK_WEBSOCKETSERVER
bool WebSocketExec::ExecServerStart(ServerStartContext *context)
{
    NETSTACK_LOGD("websocket server start exec");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (!CommonUtils::IsValidIPV4(context->GetServerIP()) &&
        !CommonUtils::IsValidIPV6(context->GetServerIP())) {
        NETSTACK_LOGE("IPV4 and IPV6 are not valid");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_INVALID_NIC);
        return false;
    }
    if (!CommonUtils::IsValidPort(context->GetServerPort())) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_INVALID_PORT);
        NETSTACK_LOGE("Port is not valid");
        return false;
    }
    if (context->GetMaxConcurrentClientsNumber() > MAX_CONCURRENT_CLIENTS_NUMBER) {
        NETSTACK_LOGE("concurrent clients number is over limit");
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        return false;
    }
    manager->SetMaxConnClientCnt(context->GetMaxConcurrentClientsNumber());
    if (context->GetMaxConnectionsForOneClient() > MAX_CONNECTIONS_FOR_ONE_CLIENT) {
        NETSTACK_LOGE("connection number for one client is over limit");
        return false;
    }
    manager->SetMaxConnForOneClient(context->GetMaxConnectionsForOneClient());

    lws_context_creation_info info = {};
    FillServerContextInfo(context, manager, info);
    if (!FillServerCertPath(context, info)) {
        NETSTACK_LOGE("FillServerCertPath error");
        return false;
    }
    StartService(info, manager);
    return true;
}

void WebSocketExec::StartService(lws_context_creation_info &info, std::shared_ptr<EventManager> &manager)
{
    lws_context *lwsContext = nullptr;
    std::shared_ptr<UserData> userData;
    lwsContext = lws_create_context(&info);
    userData = std::make_shared<UserData>(lwsContext);
    manager->SetWebSocketUserData(userData);
    std::thread serviceThread(RunService, userData, manager);

#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
    pthread_setname_np(WEBSOCKET_SERVER_THREAD_RUN);
#else
    pthread_setname_np(serviceThread.native_handle(), WEBSOCKET_SERVER_THREAD_RUN);
#endif
    serviceThread.detach();
}

void WebSocketExec::FillServerContextInfo(ServerStartContext *context, std::shared_ptr<EventManager> &manager,
    lws_context_creation_info &info)
{
    info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
    info.port = context->GetServerPort();
    info.mounts = &mount;
    info.protocols = LWS_SERVER_PROTOCOLS;
    info.vhost_name = "localhost";
    info.user = manager.get();
// maybe
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
}

bool WebSocketExec::FillServerCertPath(ServerStartContext *context, lws_context_creation_info &info)
{
    if (!context->certPath_.empty()) {
        if (!CheckFilePath(context->certPath_) || !CheckFilePath(context->keyPath_)) {
            NETSTACK_LOGE("client cert not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        info.ssl_cert_filepath = context->certPath_.c_str();
        info.ssl_private_key_filepath = context->keyPath_.c_str();
    }
    return true;
}

bool WebSocketExec::ExecListAllConnections(ListAllConnectionsContext *context)
{
    NETSTACK_LOGD("ListAllConnections start exec");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }

    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    std::vector<WebSocketConnection> connection = GetConnections();
    context->SetAllConnections(connection);
    NETSTACK_LOGI("ExecListAllConnections OK");
    return true;
}

std::vector<WebSocketConnection> WebSocketExec::GetConnections()
{
    std::shared_lock<std::shared_mutex> lock(wsMutex_);
    std::vector<WebSocketConnection> conn;
    if (!webSocketConnection_.empty()) {
        for (auto [_, connPair] : webSocketConnection_) {
            conn.emplace_back(connPair.second);
        }
    }
    return conn;
}

bool WebSocketExec::ExecServerClose(ServerCloseContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    if (context->GetSharedManager() == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    WebSocketConnection conn = context->GetConnection();
    if (conn.clientIP.empty()) {
        NETSTACK_LOGE("connection is empty");
        return false;
    }
    std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
    NETSTACK_LOGI("ExecServerClose, clientID:%{public}s", clientId.c_str());
    auto wsi = GetClientWsi(clientId);
    if (wsi == nullptr) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);
        NETSTACK_LOGE("clientId not found:%{public}s", clientId.c_str());
        return false;
    }
    auto* clientUserData = reinterpret_cast<UserData*>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUser data is nullptr");
        return false;
    }
    if (clientUserData->IsClosed() || clientUserData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    clientUserData->Close(static_cast<lws_close_status>(context->code), context->reason);
    clientUserData->TriggerWritable();
    NETSTACK_LOGI("ExecServerClose OK");
    return true;
}

bool WebSocketExec::ExecServerSend(ServerSendContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    WebSocketConnection conn = context->GetConnection();
    if (conn.clientIP.empty()) {
        NETSTACK_LOGE("connection is empty");
        return false;
    }
    std::string clientId = conn.clientIP + ":" + std::to_string(conn.clientPort);
    NETSTACK_LOGI("connection clientid:%{public}s", clientId.c_str());
    auto wsi = GetClientWsi(clientId);
    if (wsi == nullptr) {
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECTION_NOT_EXIST);
        NETSTACK_LOGE("clientId not found:%{public}s", clientId.c_str());
        return false;
    }
    auto* clientUserData = reinterpret_cast<UserData*>(lws_wsi_user(wsi));
    if (clientUserData == nullptr) {
        NETSTACK_LOGE("clientUser data is nullptr");
        return false;
    }
    if (clientUserData->IsClosed() || clientUserData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    clientUserData->Push(context->data, context->length, context->protocol);
    clientUserData->TriggerWritable();
    NETSTACK_LOGD("lws ts send success");
    return true;
}

lws* WebSocketExec::GetClientWsi(const std::string clientId)
{
    std::shared_lock<std::shared_mutex> lock(wsMutex_);
    if (webSocketConnection_.empty()) {
        NETSTACK_LOGE("webSocketConnection is empty");
        return nullptr;
    }
    auto it = webSocketConnection_.find(clientId);
    if (it == webSocketConnection_.end()) {
        NETSTACK_LOGE("can't find clientId");
        return nullptr;
    }
    return it->second.first;
}
 
bool WebSocketExec::ExecServerStop(ServerStopContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    auto manager = context->GetSharedManager();
    if (manager == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }
    auto userData = manager->GetWebSocketUserData();
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is nullptr");
        return false;
    }
    if (userData->IsClosed() || userData->IsThreadStop()) {
        NETSTACK_LOGE("session is closed or stopped");
        return false;
    }
    CloseAllConnection();
    userData->Close(LWS_CLOSE_STATUS_GOINGAWAY, "");
    NETSTACK_LOGI("ExecServerStop OK");
    return true;
}

void WebSocketExec::CloseAllConnection()
{
    decltype(webSocketConnection_) connListTmp;
    {
        std::shared_lock<std::shared_mutex> lock(wsMutex_);
        if (webSocketConnection_.empty()) {
            NETSTACK_LOGE("webSocketConnection is empty");
            return;
        }
        connListTmp = webSocketConnection_;
    }
    const char* closeReason = "server is going away";
    for (auto [id, connPair] : connListTmp) {
        if (connPair.first == nullptr) {
            NETSTACK_LOGE("clientId not found:%{public}s", id.c_str());
            continue;
        }
        auto* clientUserData = reinterpret_cast<UserData*>(lws_wsi_user(connPair.first));
        clientUserData->Close(LWS_CLOSE_STATUS_GOINGAWAY, closeReason);
        clientUserData->TriggerWritable();
    }
    NETSTACK_LOGI("CloseAllConnection OK");
}
 
napi_value WebSocketExec::ServerStartCallback(ServerStartContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value WebSocketExec::ListAllConnectionsCallback(ListAllConnectionsContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("Context is null");
        return nullptr;
    }
    napi_value connectionsArray = NapiUtils::CreateArray(context->GetEnv(), 0);
    const std::vector<WebSocketConnection> connections = context->GetAllConnections();
    if (connections.empty()) {
        NETSTACK_LOGE("connections list is null");
        return connectionsArray;
    }
    uint32_t index = 0;
    for (const auto &conn : connections) {
        napi_value jsConn = NapiUtils::CreateObject(context->GetEnv());
        NapiUtils::SetUint32Property(context->GetEnv(), jsConn, EVENT_KEY_CLIENT_PORT, conn.clientPort);
        NapiUtils::SetStringPropertyUtf8(context->GetEnv(), jsConn, EVENT_KEY_CLIENT_IP, conn.clientIP);
        NapiUtils::SetArrayElement(context->GetEnv(), connectionsArray, index, jsConn);
        ++index;
    }
    return connectionsArray;
}

napi_value WebSocketExec::ServerSendCallback(ServerSendContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value WebSocketExec::ServerCloseCallback(ServerCloseContext *context)
{
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

napi_value WebSocketExec::ServerStopCallback(ServerStopContext *context)
{
    auto manager = context->GetSharedManager();
    if (manager != nullptr) {
        NETSTACK_LOGD("websocket close, delete js ref");
        manager->DeleteEventReference(context->GetEnv());
    }
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}
#endif
} // namespace OHOS::NetStack::Websocket
