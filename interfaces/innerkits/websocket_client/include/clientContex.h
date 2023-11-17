#include <atomic>
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

namespace OHOS {
namespace NetStack {
namespace WebsocketClient {

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

class ClientContex {
public:
    ClientContex(lws_context *context)
        : closeStatus(LWS_CLOSE_STATUS_NOSTATUS), openStatus(0), closed_(false), threadStop_(false), context_(context)
    {
    }

    ClientContex(){
        //
    };

    bool IsClosed()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    bool IsThreadStop()
    {
        // std::cout <<"TS:inner api: "<< __func__ << ", line= " <<__LINE__<< std::endl;
        return threadStop_.load();
    }

    void SetThreadStop(bool threadStop)
    {
        std::cout << "TS:inner api: " << __func__ << ", line= " << __LINE__ << std::endl;
        threadStop_.store(threadStop);
    }

    void Close(lws_close_status status, const std::string &reason)
    { 
        NETSTACK_LOGI("ClientContex  Close, function at:  %{public}d", __LINE__);
        std::lock_guard<std::mutex> lock(mutex_);
        closeStatus = status;
        closeReason = reason;
        closed_ = true;
    }

    void Push(char *data, size_t length, lws_write_protocol protocol)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dataQueue_.push(SendData(data, length, protocol));
        // std::cout <<"TS:inner api: Push"<< __func__ << ", line= " <<__LINE__<<", SendData.data:"<<data<<std::endl;
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

    uint32_t errorCode;

    std::string openMessage;

private:
    volatile bool closed_;

    std::atomic_bool threadStop_;

    std::mutex mutex_;

    lws_context *context_;

    std::queue<SendData> dataQueue_;
};

}; // namespace WebsocketClient
} // namespace NetStack
} // namespace OHOS