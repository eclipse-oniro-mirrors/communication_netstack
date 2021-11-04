#ifndef __NETD_SOCKET_BASE_H__
#define __NETD_SOCKET_BASE_H__

#include "logger.h"
#include <functional>
#include <memory>
#include <netinet/in.h>
#include <sys/epoll.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
namespace common {

typedef struct end_point {
    int port;
} end_point;
class socket_base {
protected:
    int socketFd_;
    int epollFd_ = 0;
    int eventCnt_ = 0;
    struct epoll_event *epollEvents_;
    struct epoll_event event_ {};
    std::function<void(const int, const uint8_t *, const size_t)> handler_;

private:
    int create(int domain, int protocol);

public:
    socket_base();
    virtual ~socket_base();

    int createInet();
    int createUnix();
    int listenSocket();
    int acceptSocket();
    int connectSocket(struct sockaddr_in serverAddr);
    ssize_t sendSocket(int socketFd, const char *buffer);
    ssize_t sendSocket(const char *buffer);
    virtual ssize_t sendMsg(const int socketFd, const msghdr &msg);
    char *receiveSocket(char *buffer);

    template<typename R, typename... Params>
    void setRecevedHandler(R (*)(Params...))
    {}

    template<typename R, typename C, typename... Params>
    void setRecevedHandler(R (C::*func)(Params...), C *instance)
    {
        NETNATIVE_LOGD("setRecevedHandler bind begin");
        this->handler_ =
            std::bind(func, instance, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        NETNATIVE_LOGD("setRecevedHandler bind end");
    }

    int getSocketFileDescriptor()
    {
        return this->socketFd_;
    }
};

} // namespace common
} // namespace nmd
} // namespace OHOS
#endif // !__NETD_SOCKET_BASE_H__
