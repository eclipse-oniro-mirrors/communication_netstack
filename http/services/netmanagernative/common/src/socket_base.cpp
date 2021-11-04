#include "socket_base.h"
#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "netnative_log_wrapper.h"
static const int EPOLL_SIZE = 50;

namespace OHOS {
namespace nmd {
nmd::common::socket_base::socket_base(/* args */) {}

nmd::common::socket_base::~socket_base() {}

int nmd::common::socket_base::create(int domain, int protocol)
{
    this->socketFd_ = -1;
    if ((this->socketFd_ = socket(domain, SOCK_STREAM, protocol)) == -1) {
        // logger::info() << "[Socket] Unable to Open the Socket: " << strerror(errno) << endl;
        NETNATIVE_LOGE("[Socket] Unable to Open the Socket: %{public}s", strerror(errno));
        exit(0);
    }
    this->epollFd_ = epoll_create(EPOLL_SIZE);
    this->epollEvents_ = new epoll_event[EPOLL_SIZE];

    event_.events = EPOLLIN;
    event_.data.fd = this->socketFd_;
    epoll_ctl(this->epollFd_, EPOLL_CTL_ADD, this->socketFd_, &this->event_);

    return this->socketFd_;
}

int nmd::common::socket_base::createInet()
{
    return this->create(AF_INET, 0);
}

int nmd::common::socket_base::createUnix()
{
    return this->create(AF_UNIX, 0);
}

int nmd::common::socket_base::listenSocket()
{
    int listenFd = -1;
    if ((listenFd = listen(this->socketFd_, 50)) == -1) {
        // logger::error() << "[Socket] Unable to listen the Socket: " << strerror(errno) << endl;
        NETNATIVE_LOGE("[Socket] Unable to listen the Socket: %{public}s", strerror(errno));
        exit(0);
    }
    return listenFd;
}

static const int BUF_SIZE = 4096;
int nmd::common::socket_base::acceptSocket()
{
    int clientFd = 0;
    this->eventCnt_ = epoll_wait(this->epollFd_, this->epollEvents_, EPOLL_SIZE, -1);
    if (this->eventCnt_ == -1) {
        // logger::error() << "[Socket]  epoll_wait() error: " << strerror(errno) << endl;
        NETNATIVE_LOGE("[Socket]  epoll_wait() error:  %{public}s", strerror(errno));
        return this->eventCnt_;
    }

    for (int i = 0; i < this->eventCnt_; i++) {
        if (this->epollEvents_[i].data.fd == this->socketFd_) {
            struct sockaddr_in clientAddr;
            socklen_t adr_sz = sizeof(clientAddr);
            clientFd = accept(this->socketFd_, reinterpret_cast<sockaddr *>(&clientAddr), &adr_sz);
            char clientStr[20] = {'\0'};
            const char *clientAddrStr =
                inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr, clientStr, sizeof(clientAddr));
            if (nullptr == clientAddrStr) {
                // logger::info() << "[Socket] new unix socket client connected." << endl;
                NETNATIVE_LOGI("[Socket] new unix socket client connected.");
            } else {
                // logger::info() << "[Socket] new client:" << std::string(clientAddrStr) << endl;
                NETNATIVE_LOGI("[Socket] new client: %{public}s", std::string(clientAddrStr).c_str());
            }

            this->event_.events = EPOLLIN;
            this->event_.data.fd = clientFd;
            epoll_ctl(this->epollFd_, EPOLL_CTL_ADD, clientFd, &this->event_);
        } else {
            uint8_t buf[BUF_SIZE] = {'\0'};
            ssize_t readSize = read(this->epollEvents_[i].data.fd, buf, BUF_SIZE);
            if (readSize == 0) {
                epoll_ctl(this->epollFd_, EPOLL_CTL_DEL, this->epollEvents_[i].data.fd, NULL);
                close(this->epollEvents_[i].data.fd);
                // logger::info() << "[Socket]  closed client:" << this->epollEvents_[i].data.fd << endl;
                NETNATIVE_LOGI("[Socket]  closed client: %{public}d", this->epollEvents_[i].data.fd);
            } else if (readSize < 0) {
                if (errno == ECONNRESET) {
                    epoll_ctl(this->epollFd_, EPOLL_CTL_DEL, this->epollEvents_[i].data.fd, NULL);
                    close(this->epollEvents_[i].data.fd);
                    // logger::info() << "[Socket]  closed client:" << this->epollEvents_[i].data.fd << endl;
                    NETNATIVE_LOGI("[Socket]  closed client: %{public}d", this->epollEvents_[i].data.fd);
                } else {
                    // logger::info() << "[Socket]  read error fd:" << this->epollEvents_[i].data.fd << endl;
                    NETNATIVE_LOGI("[Socket]  read error fd: %{public}d", this->epollEvents_[i].data.fd);
                }
            } else {
                this->handler_(this->epollEvents_[i].data.fd, buf, static_cast<size_t>(readSize));
            }
        }
    }
    return 0;
}

int nmd::common::socket_base::connectSocket(struct sockaddr_in serverAddr)
{
    int connectFd = -1;
    if ((connectFd = connect(this->socketFd_, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr))) ==
        -1) {
        // logger::error() << "[Socket] Unable to connect the Socket" << endl;
        NETNATIVE_LOGE("[Socket] Unable to connect the Socket");
        exit(0);
    };
    return connectFd;
}

ssize_t nmd::common::socket_base::sendSocket(const char *buffer)
{
    ssize_t size = -1;
    if ((size = send(this->socketFd_, buffer, strlen(buffer), 0)) == -1) {
        // logger::error() << "[Socket] Unable to send to Socket" << this->socketFd_ << endl;
        NETNATIVE_LOGE("[Socket] Unable to send to Socket  %{public}d", this->socketFd_);
    };
    return size;
}

ssize_t nmd::common::socket_base::sendSocket(int socketFd, const char *buffer)
{
    ssize_t size = -1;
    if ((size = send(socketFd, buffer, strlen(buffer), 0)) == -1) {
        // logger::error() << "[Socket] Unable to send to Socket" << socketFd << endl;
        NETNATIVE_LOGE("[Socket] Unable to send to Socket %{public}d", socketFd);
    };
    return size;
}

ssize_t nmd::common::socket_base::sendMsg(const int socketFd, const msghdr &msg)
{
    ssize_t size = -1;
    if ((size = sendmsg(socketFd, &msg, 0)) == -1) {
        // logger::error() << "[Socket] Unable to sendmsg to Socket" << socketFd << endl;
        NETNATIVE_LOGE("[Socket] Unable to sendmsg to Socket %{public}d", socketFd);
    };
    return size;
}
} // namespace nmd
} // namespace OHOS