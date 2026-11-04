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

#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <libwebsockets.h>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <signal.h>
#include <string.h>
#include <string>
#include <thread>
#include "netstack_log.h"
#include "secure_char.h"

namespace OHOS {
namespace NetStack {
namespace WebSocketClient {
class WebSocketClient;

struct SendData {
    SendData(char *paraData, size_t paraLength, lws_write_protocol paraProtocol)
        : data(paraData), length(paraLength), protocol(paraProtocol)
    {
    }

    SendData() = delete;

    ~SendData() = default;

    char *data;
    size_t length;
    lws_write_protocol protocol;
};

enum class WebsocketProxyType {
    NOT_USE,
    USE_SYSTEM,
    USE_SPECIFIED,
};

class ClientContext {
public:
    ClientContext() : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), errorCode(0), closed_(false),
                      threadStop_(std::make_shared<std::atomic_bool>(false)), context_(nullptr), clientId(0) {}

    ~ClientContext()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!dataQueue_.empty()) {
            std::free(dataQueue_.front().data);
            dataQueue_.pop();
        }
    }

    bool IsClosed()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    bool IsThreadStop()
    {
        return threadStop_->load();
    }

    void SetThreadStop(bool threadStop)
    {
        threadStop_->store(threadStop);
    }

    std::shared_ptr<std::atomic_bool> GetThreadStopFlag()
    {
        return threadStop_;
    }

    void Close(lws_close_status status, const std::string &reason)
    {
        NETSTACK_LOGD("ClientContext  Close");
        std::lock_guard<std::mutex> lock(mutex_);
        closeStatus = status;
        closeReason = reason;
        closed_ = true;
    }

    void CloseIfReasonEmpty(const std::string &reason)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closeReason.empty()) {
            closeReason = reason;
            closed_ = true;
        }
    }

    lws_close_status GetCloseStatus()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closeStatus;
    }

    std::string GetCloseReason()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closeReason;
    }

    void Push(char *data, size_t length, lws_write_protocol protocol)
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
        std::shared_ptr<lws_context> newContext;
        if (context != nullptr) {
            newContext.reset(context, [](lws_context *value) {
                if (value != nullptr) {
                    lws_context_destroy(value);
                }
            });
        }
        std::lock_guard<std::mutex> lock(mutexForContext_);
        context_.swap(newContext);
    }

    lws_context *GetContext()
    {
        std::lock_guard<std::mutex> lock(mutexForContext_);
        return context_.get();
    }

    std::shared_ptr<lws_context> GetContextShared()
    {
        std::lock_guard<std::mutex> lock(mutexForContext_);
        return context_;
    }

    void ReleaseUserDataIfContext(lws_context *context)
    {
        std::lock_guard<std::mutex> contextLock(mutexForContext_);
        if (context_.get() != context) {
            return;
        }
        std::lock_guard<std::mutex> userDataLock(mutexForUserData_);
        userData_.reset();
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

    void SetClientId(int id)
    {
        clientId = id;
    }

    void ResetConnectionState()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = false;
        closeStatus = LWS_CLOSE_STATUS_NOSTATUS;
        closeReason.clear();
        openStatus.store(0);
        threadStop_->store(false);
    }

    int GetClientId()
    {
        return clientId;
    }

    void SetUserCertPath(std::string path)
    {
        userCertPath_ = path;
    }

    std::string GetUserCertPath()
    {
        return userCertPath_;
    }

    void SetUserData(std::shared_ptr<WebSocketClient> userData);

    ClientContext *AsLwsUserData()
    {
        return this;
    }

    std::shared_ptr<WebSocketClient> GetUserDataCopy()
    {
        std::lock_guard<std::mutex> lock(mutexForUserData_);
        return userData_.lock();
    }

    void ReleaseUserData()
    {
        std::lock_guard<std::mutex> lock(mutexForUserData_);
        userData_.reset();
    }

    std::map<std::string, std::string> header;

    std::string caPath;

    std::string clientCert;

    Secure::SecureChar clientKey;

    Secure::SecureChar keyPassword;

    bool permissionDenied = false;

    bool isAtomicService = false;

    bool noAllowedHost = false;

    std::string bundleName;

    std::string url;
    bool supportOriginPort = false;
    std::string serverName;
    WebsocketProxyType usingWebsocketProxyType = WebsocketProxyType::USE_SYSTEM;

    std::string websocketProxyHost;

    int32_t websocketProxyPort = 0;

    std::string websocketProxyExclusions;

    lws_close_status closeStatus;

    std::string closeReason;

    std::atomic<uint32_t> openStatus = 0;

    uint32_t errorCode = 0;

    std::string openMessage;

    bool isWss = false;

    std::string dstIpForStats;

    std::string hostNameForStats;

    std::string httpVersion = "HTTP/1.1";
    std::string openProtocol;

private:
    bool closed_ = false;

    std::string userCertPath_;

    std::shared_ptr<std::atomic_bool> threadStop_;

    std::mutex mutex_;

    std::shared_ptr<lws_context> context_;

    std::mutex mutexForContext_;

    std::queue<SendData> dataQueue_;

    std::mutex mutexForLws_;

    lws *wsi_ = nullptr;

    int clientId = 0;

    std::weak_ptr<WebSocketClient> userData_;

    std::mutex mutexForUserData_;
};
}; // namespace WebSocketClient
} // namespace NetStack
} // namespace OHOS
#endif
