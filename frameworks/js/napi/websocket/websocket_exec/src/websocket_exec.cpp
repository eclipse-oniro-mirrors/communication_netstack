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

#include "constant.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"

static constexpr const char *PATH_START = "/";

static constexpr const char *NAME_END = ":";

static constexpr const char *STATUS_LINE_SEP = " ";

static constexpr const size_t STATUS_LINE_ELEM_NUM = 2;

static constexpr const char *PREFIX_HTTPS = "https";

static constexpr const char *PREFIX_WSS = "wss";

static constexpr const char *PREFIX_WS = "ws";

static constexpr const int MAX_URI_LENGTH = 1024;

static constexpr const int MAX_HDR_LENGTH = 1024;

static constexpr const int FD_LIMIT_PER_THREAD = 1 + 1 + 1;

static constexpr const int COMMON_ERROR_CODE = 200;

static constexpr const char *EVENT_KEY_CODE = "code";

static constexpr const char *EVENT_KEY_STATUS = "status";

static constexpr const char *EVENT_KEY_REASON = "reason";

static constexpr const char *EVENT_KEY_MESSAGE = "message";

static constexpr const char *LINK_DOWN = "The link is down";

static constexpr const char *WEBSCOKET_PREPARE_CA_PATH = "/etc/ssl/certs/cacert.pem";

static constexpr const int32_t UID_TRANSFORM_DIVISOR = 200000;

static constexpr const int32_t MAX_DIR_LENGTH = 8192;

static constexpr const char *BASE_PATH = "/data/certificates/user_cacerts/";

static constexpr const char *WEBSOCKET_SYSTEM_PREPARE_CA_PATH = "/etc/security/certificates";

namespace OHOS::NetStack::Websocket {
static const lws_protocols LWS_PROTOCOLS[] = {
    {"lws-minimal-client", WebSocketExec::LwsCallback, 0, 0},
    {nullptr, nullptr, 0, 0}, // this line is needed
};

static const lws_retry_bo_t RETRY = {
    .secs_since_valid_ping = 0,
    .secs_since_valid_hangup = 10,
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
        dataQueue_.push(SendData(data, length, protocol));
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

    std::map<std::string, std::string> header;

    lws_close_status closeStatus;

    std::string closeReason;

    uint32_t openStatus;

    std::string openMessage;

private:
    volatile bool closed_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;
};

template <napi_value (*MakeJsValue)(napi_env, void *)> static void CallbackTemplate(uv_work_t *work, int status)
{
    (void)status;

    auto workWrapper = static_cast<UvWorkWrapper *>(work->data);
    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = MakeJsValue(env, workWrapper->data);

    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);

    delete workWrapper;
    delete work;
}

bool WebSocketExec::ParseUrl(ConnectContext *context, char *prefix, size_t prefixLen, char *address, size_t addressLen,
                             char *path, size_t pathLen, int *port)
{
    char uri[MAX_URI_LENGTH] = {0};
    if (strcpy_s(uri, MAX_URI_LENGTH, context->url.c_str()) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    const char *tempPrefix = nullptr;
    const char *tempAddress = nullptr;
    const char *tempPath = nullptr;
    (void)lws_parse_uri(uri, &tempPrefix, &tempAddress, port, &tempPath);
    if (strcpy_s(prefix, prefixLen, tempPrefix) < 0) {
        NETSTACK_LOGE("strcpy_s failed");
        return false;
    }
    if (std::find(WS_PREFIX.begin(), WS_PREFIX.end(), prefix) == WS_PREFIX.end()) {
        NETSTACK_LOGE("prefix failed");
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

void WebSocketExec::RunService(EventManager *manager)
{
    NETSTACK_LOGI("websocket run service start");
    if (manager == nullptr || manager->GetData() == nullptr) {
        NETSTACK_LOGE("RunService para error");
        return;
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());
    lws_context *context = userData->GetContext();
    if (context == nullptr) {
        NETSTACK_LOGE("context is null");
        return;
    }
    while (!userData->IsThreadStop()) {
        lws_service(context, 0);
    }
    lws_context_destroy(context);
    userData->SetContext(nullptr);
    delete userData;
    manager->SetData(nullptr);
    NETSTACK_LOGI("websocket run service end");
}

int WebSocketExec::RaiseError(EventManager *manager)
{
    OnError(manager, COMMON_ERROR_CODE);
    return -1;
}

int WebSocketExec::HttpDummy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    int ret = lws_callback_http_dummy(wsi, reason, user, in, len);
    if (ret < 0) {
        OnError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE);
    }
    return ret;
}

int WebSocketExec::LwsCallbackClientAppendHandshakeHeader(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                          size_t len)
{
    NETSTACK_LOGI("LwsCallbackClientAppendHandshakeHeader");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager->GetData() == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager);
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());

    auto payload = reinterpret_cast<unsigned char **>(in);
    if (payload == nullptr || (*payload) == nullptr || len == 0) {
        NETSTACK_LOGE("header payload is null, do not append header");
        return RaiseError(manager);
    }
    auto payloadEnd = (*payload) + len;
    for (const auto &pair : userData->header) {
        std::string name = pair.first + NAME_END;
        if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char *>(name.c_str()),
                                        reinterpret_cast<const unsigned char *>(pair.second.c_str()),
                                        static_cast<int>(strlen(pair.second.c_str())), payload, payloadEnd)) {
            NETSTACK_LOGE("add header failed");
            return RaiseError(manager);
        }
    }
    NETSTACK_LOGI("add header OK");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsPeerInitiatedClose(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                   size_t len)
{
    NETSTACK_LOGI("LwsCallbackWsPeerInitiatedClose");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager->GetData() == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager);
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());

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
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager->GetData() == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager);
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());
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
    NETSTACK_LOGI("send data length = %{public}d", sendLength);
    return HttpDummy(wsi, reason, user, in, len);
}

static napi_value CreateConnectError(napi_env env, void *callbackPara)
{
    auto code = reinterpret_cast<int32_t *>(callbackPara);
    auto deleter = [](const int32_t *p) { delete p; };
    std::unique_ptr<int32_t, decltype(deleter)> handler(code, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, *code);
    return err;
}

void OnConnectError(EventManager *manager, int32_t code)
{
    NETSTACK_LOGI("OnError %{public}d", code);
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (auto userData = reinterpret_cast<UserData *>(manager->GetData()); userData != nullptr) {
        NETSTACK_LOGI("OnConnectError SetThreadStop");
        userData->SetThreadStop(true);
    }
    if (!manager->HasEventListener(EventName::EVENT_ERROR)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_ERROR);
        return;
    }
    manager->EmitByUv(EventName::EVENT_ERROR, new int32_t(code), CallbackTemplate<CreateConnectError>);
}

int WebSocketExec::LwsCallbackClientConnectionError(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                    size_t len)
{
    NETSTACK_LOGI("LwsCallbackClientConnectionError %{public}s",
                  (in == nullptr) ? "null" : reinterpret_cast<char *>(in));
    // 200 means connect failed
    OnConnectError(reinterpret_cast<EventManager *>(user), COMMON_ERROR_CODE);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientReceive(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGD("LwsCallbackClientReceive");
    auto manager = reinterpret_cast<EventManager *>(user);
    auto isFinal = lws_is_final_fragment(wsi);
    OnMessage(manager, in, len, lws_frame_is_binary(wsi), isFinal);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientFilterPreEstablish(lws *wsi, lws_callback_reasons reason, void *user, void *in,
                                                       size_t len)
{
    NETSTACK_LOGI("LwsCallbackClientFilterPreEstablish");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager->GetData() == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager);
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());

    userData->openStatus = lws_http_client_http_response(wsi);
    char statusLine[MAX_HDR_LENGTH] = {0};
    if (lws_hdr_copy(wsi, statusLine, MAX_HDR_LENGTH, WSI_TOKEN_HTTP) < 0 || strlen(statusLine) == 0) {
        return HttpDummy(wsi, reason, user, in, len);
    }

    auto vec = CommonUtils::Split(statusLine, STATUS_LINE_SEP, STATUS_LINE_ELEM_NUM);
    if (vec.size() >= FUNCTION_PARAM_TWO) {
        userData->openMessage = vec[1];
    }

    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientEstablished(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("LwsCallbackClientEstablished");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager->GetData() == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager);
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());

    OnOpen(reinterpret_cast<EventManager *>(user), userData->openStatus, userData->openMessage);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackClientClosed(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("LwsCallbackClientClosed");
    auto manager = reinterpret_cast<EventManager *>(user);
    if (manager->GetData() == nullptr) {
        NETSTACK_LOGE("user data is null");
        return RaiseError(manager);
    }
    auto userData = reinterpret_cast<UserData *>(manager->GetData());
    userData->SetThreadStop(true);
    if ((userData->closeReason).empty()) {
        userData->Close(userData->closeStatus, LINK_DOWN);
    }
    if (userData->closeStatus == LWS_CLOSE_STATUS_NOSTATUS) {
        NETSTACK_LOGE("The link is down, onError");
        OnError(manager, COMMON_ERROR_CODE);
    }
    OnClose(reinterpret_cast<EventManager *>(user), userData->closeStatus, userData->closeReason);
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackWsiDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("LwsCallbackWsiDestroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallbackProtocolDestroy(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
    NETSTACK_LOGI("LwsCallbackProtocolDestroy");
    return HttpDummy(wsi, reason, user, in, len);
}

int WebSocketExec::LwsCallback(lws *wsi, lws_callback_reasons reason, void *user, void *in, size_t len)
{
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
    };

    for (const auto dispatcher : dispatchers) {
        if (dispatcher.reason == reason) {
            return dispatcher.callback(wsi, reason, user, in, len);
        }
    }

    return HttpDummy(wsi, reason, user, in, len);
}

static inline void FillContextInfo(lws_context_creation_info &info)
{
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = LWS_PROTOCOLS;
    info.fd_limit_per_thread = FD_LIMIT_PER_THREAD;
    info.client_ssl_ca_filepath = WEBSCOKET_PREPARE_CA_PATH;
}

bool WebSocketExec::CreatConnectInfo(ConnectContext *context, lws_context *lwsContext, EventManager *manager)
{
    lws_client_connect_info connectInfo = {};
    char prefix[MAX_URI_LENGTH] = {0};
    char address[MAX_URI_LENGTH] = {0};
    char pathWithoutStart[MAX_URI_LENGTH] = {0};
    int port = 0;
    if (!ParseUrl(context, prefix, MAX_URI_LENGTH, address, MAX_URI_LENGTH, pathWithoutStart, MAX_URI_LENGTH, &port)) {
        NETSTACK_LOGE("ParseUrl failed");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_URL_ERROR);
        return false;
    }
    std::string path = PATH_START + std::string(pathWithoutStart);

    if (lwsContext == nullptr) {
        NETSTACK_LOGE("no memory");
        return false;
    }
    connectInfo.context = lwsContext;
    connectInfo.port = port;
    connectInfo.address = address;
    connectInfo.path = path.c_str();
    connectInfo.host = address;
    connectInfo.origin = address;
    if (strcmp(prefix, PREFIX_HTTPS) == 0 || strcmp(prefix, PREFIX_WSS) == 0) {
        connectInfo.ssl_connection =
            LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_SELFSIGNED;
    }
    lws *wsi = nullptr;
    connectInfo.pwsi = &wsi;
    connectInfo.retry_and_idle_policy = &RETRY;
    connectInfo.userdata = reinterpret_cast<void *>(manager);
    if (lws_client_connect_via_info(&connectInfo) == nullptr) {
        NETSTACK_LOGI("ExecConnect websocket connect failed");
        context->SetErrorCode(-1);
        OnConnectError(manager, COMMON_ERROR_CODE);
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

static bool FillCaPath(ConnectContext *context, lws_context_creation_info &info)
{
    int32_t uid = getuid();
    int32_t userid = uid / UID_TRANSFORM_DIVISOR;
    if (!context->caPath_.empty()) {
        if (!CheckFilePath(context->caPath_)) {
            NETSTACK_LOGE("ca not exist");
            context->SetErrorCode(WEBSOCKET_ERROR_CODE_FILE_NOT_EXIST);
            return false;
        }
        info.client_ssl_ca_filepath = context->caPath_.c_str();
    }
    if (context->caPath_.empty()) {
        info.client_ssl_ca_dirs[1] = new char[MAX_DIR_LENGTH];
        if (info.client_ssl_ca_dirs[1] == nullptr) {
            return false;
        }
        (void)memset_s(const_cast<char *>(info.client_ssl_ca_dirs[1]), MAX_DIR_LENGTH, 0, MAX_DIR_LENGTH);
        std::string path = BASE_PATH + std::to_string(userid);
        info.client_ssl_ca_dirs[0] = WEBSOCKET_SYSTEM_PREPARE_CA_PATH;
        (void)memcpy_s(const_cast<char *>(info.client_ssl_ca_dirs[1]), MAX_DIR_LENGTH, path.c_str(),
                       strlen(path.c_str()));
    }
    NETSTACK_LOGD("caPath: %{public}s", info.client_ssl_ca_filepath);
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
    NETSTACK_LOGD("websocket_SSL ExecConnect begin\n");
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return false;
    }
    NETSTACK_LOGD("begin connect, parse url");
    auto manager = context->GetManager();
    if (manager == nullptr) {
        return false;
    }
    lws_context_creation_info info = {};
    FillContextInfo(info);
    if (!FillCaPath(context, info)) {
        return false;
    }
    lws_context *lwsContext = nullptr;
    UserData *userData = nullptr;
    if (manager->GetData() == nullptr) {
        lwsContext = lws_create_context(&info);
        userData = new UserData(lwsContext);
        userData->header = context->header;
        manager->SetData(userData);
    } else {
        NETSTACK_LOGE("Websocket connect already exist");
        context->SetErrorCode(WEBSOCKET_ERROR_CODE_CONNECT_AlREADY_EXIST);
        return false;
    }
    if (!CreatConnectInfo(context, lwsContext, manager)) {
        manager->SetData(nullptr);
        userData->SetContext(nullptr);
        lws_context_destroy(lwsContext);
        delete userData;
        if (info.client_ssl_ca_dirs[1] != nullptr) {
            delete[] info.client_ssl_ca_dirs[1];
        }
        return false;
    }
    std::thread serviceThread(RunService, manager);
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
    if (context->GetManager() == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }

    auto manager = context->GetManager();
    auto userData = reinterpret_cast<UserData *>(manager->GetData());
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return false;
    }

    userData->Push(context->data, context->length, context->protocol);
    NETSTACK_LOGI("ExecSend OK");
    return true;
}

napi_value WebSocketExec::SendCallback(SendContext *context)
{
    NETSTACK_LOGI("SendCallback success");
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
    if (context->GetManager() == nullptr) {
        NETSTACK_LOGE("context is null");
        return false;
    }

    auto manager = context->GetManager();
    auto userData = reinterpret_cast<UserData *>(manager->GetData());
    if (userData == nullptr) {
        NETSTACK_LOGE("user data is null");
        return false;
    }

    userData->Close(static_cast<lws_close_status>(context->code), context->reason);
    NETSTACK_LOGI("ExecClose OK");
    return true;
}

napi_value WebSocketExec::CloseCallback(CloseContext *context)
{
    NETSTACK_LOGI("CloseCallback success");
    return NapiUtils::GetBoolean(context->GetEnv(), true);
}

static napi_value CreateDataEnd(napi_env env, void *callbackPara)
{
    (void)callbackPara;
    return NapiUtils::GetUndefined(env);
}

static napi_value CreateError(napi_env env, void *callbackPara)
{
    auto code = reinterpret_cast<int32_t *>(callbackPara);
    auto deleter = [](const int32_t *p) { delete p; };
    std::unique_ptr<int32_t, decltype(deleter)> handler(code, deleter);
    napi_value err = NapiUtils::CreateObject(env);
    if (NapiUtils::GetValueType(env, err) != napi_object) {
        return NapiUtils::GetUndefined(env);
    }
    NapiUtils::SetInt32Property(env, err, EVENT_KEY_CODE, *code);
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
    auto msg = reinterpret_cast<std::string *>(callbackPara);
    auto text = NapiUtils::CreateStringUtf8(env, *msg);
    delete msg;
    return text;
}

static napi_value CreateBinaryMessagePara(napi_env env, void *callbackPara)
{
    auto msg = reinterpret_cast<std::string *>(callbackPara);
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

void WebSocketExec::OnError(EventManager *manager, int32_t code)
{
    NETSTACK_LOGI("OnError %{public}d", code);
    if (manager == nullptr) {
        NETSTACK_LOGE("manager is null");
        return;
    }
    if (!manager->HasEventListener(EventName::EVENT_ERROR)) {
        NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_ERROR);
        return;
    }
    manager->EmitByUv(EventName::EVENT_ERROR, new int32_t(code), CallbackTemplate<CreateError>);
}

void WebSocketExec::OnOpen(EventManager *manager, uint32_t status, const std::string &message)
{
    NETSTACK_LOGI("OnOpen %{public}u %{public}s", status, message.c_str());
    if (manager == nullptr) {
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
    manager->EmitByUv(EventName::EVENT_OPEN, para, CallbackTemplate<CreateOpenPara>);
}

void WebSocketExec::OnClose(EventManager *manager, lws_close_status closeStatus, const std::string &closeReason)
{
    NETSTACK_LOGI("OnClose %{public}u %{public}s", closeStatus, closeReason.c_str());
    if (manager == nullptr) {
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
    manager->EmitByUv(EventName::EVENT_CLOSE, para, CallbackTemplate<CreateClosePara>);
}

void WebSocketExec::OnMessage(EventManager *manager, void *data, size_t length, bool isBinary, bool isFinal)
{
    NETSTACK_LOGD("OnMessage %{public}d", isBinary);
    if (manager == nullptr) {
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

    if (isBinary) {
        manager->AppendWebSocketBinaryData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWebSocketBinaryData();
            auto msg = new std::string;
            msg->append(msgFromManager.data(), msgFromManager.size());
            manager->EmitByUv(EventName::EVENT_MESSAGE, msg, CallbackTemplate<CreateBinaryMessagePara>);
            manager->ClearWebSocketBinaryData();
            NETSTACK_LOGI("onDataEnd");
            if (!manager->HasEventListener(EventName::EVENT_DATA_END)) {
                NETSTACK_LOGI("no event listener: %{public}s", EventName::EVENT_DATA_END);
                return;
            }
            manager->EmitByUv(EventName::EVENT_DATA_END, nullptr, CallbackTemplate<CreateDataEnd>);
        }
    } else {
        manager->AppendWebSocketTextData(data, length);
        if (isFinal) {
            const std::string &msgFromManager = manager->GetWebSocketTextData();
            auto msg = new std::string;
            msg->append(msgFromManager.data(), msgFromManager.size());
            manager->EmitByUv(EventName::EVENT_MESSAGE, msg, CallbackTemplate<CreateTextMessagePara>);
            manager->ClearWebSocketTextData();
        }
    }
}
} // namespace OHOS::NetStack::Websocket
