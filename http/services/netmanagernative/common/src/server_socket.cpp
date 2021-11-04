#include "server_socket.h"
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <unistd.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
common::server_socket::server_socket() {}

common::server_socket::~server_socket() {}

int common::server_socket::bindPort(uint16_t port)
{
    struct sockaddr_in addr {};
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    struct sockaddr *ad = reinterpret_cast<sockaddr *>(&addr);
    memcpy(&(this->addr_), ad, sizeof(*ad));

    int bindFd = 0;
    if ((bindFd = bind(this->socketFd_, &this->addr_, sizeof(this->addr_))) != 0) {
        // logger::error() << "[Socket] Unable to bind the Socket: " << strerror(errno) << endl;
        NETNATIVE_LOGE("[Socket] Unable to bind the Socket: %{public}s", strerror(errno));
        exit(0);
    }
    return bindFd;
}

int common::server_socket::bindFile(const char *filePath, const char *name)
{
    NETNATIVE_LOGI("server_socket::bindFile start:");
    int openSock = open(std::string(filePath).append("/").append(name).c_str(), O_CREAT | O_WRONLY, 0643);
    if (openSock == -1) {
        // logger::error() << "[Socket] Unable to create file: '" << name << "'," << strerror(errno) << endl;
        NETNATIVE_LOGE("[Socket] Unable to create file: '%{public}s', %{public}s", name, strerror(errno));
        exit(0);
    }
    fsync(openSock);
    close(openSock);

    // logger::info() << "[Socket]: will bind at:" << std::string(filePath).append("/").append(name).c_str() << endl;
    NETNATIVE_LOGI("[Socket]: will bind at: %{public}s", std::string(filePath).append("/").append(name).c_str());
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, std::string(filePath).append("/").append(name).c_str());

    struct sockaddr *ad = reinterpret_cast<sockaddr *>(&addr);
    memcpy(&(this->addr_), ad, sizeof(*ad));
    int bindFd = 0;
    if ((bindFd = bind(this->socketFd_, &this->addr_, sizeof(this->addr_))) != 0) {
        // logger::error() << "[Socket] Unable to bind the unix Socket:'"
        //                << std::string(filePath).append("/").append(name).c_str() << "'," << strerror(errno)
        //                << endl;
        NETNATIVE_LOGE("[Socket] Unable to bind the unix Socket:'%{public}s',', %{public}s",
            std::string(filePath).append("/").append(name).c_str(), strerror(errno));
        exit(-1);
    }
    return bindFd;
}

} // namespace nmd
} // namespace OHOS