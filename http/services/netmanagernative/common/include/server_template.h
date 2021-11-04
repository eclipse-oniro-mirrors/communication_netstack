#ifndef __INCLUDE_SERVER_TEMPLATE_H__
#define __INCLUDE_SERVER_TEMPLATE_H__

#include "server_socket.h"
#include "thread_pool.h"
#include <memory>
#include <string>
namespace OHOS {
namespace nmd {
namespace common {
class server_template {
    const char *const SOCKET_FILE_PATH = "/dev/socket";

public:
    void start();
    void stop();
    void handler(int socketFd, const uint8_t *msg, const size_t msgLen);

public:
    explicit server_template(const char *socketName, const char *serverName)
        : socketName_(socketName), serverName_(serverName), server_(std::make_shared<nmd::common::server_socket>()),
          pool_(std::make_shared<nmd::thread_pool>(16, 256)), job_(nullptr)
    {}
    virtual ~server_template() = default;

protected:
    virtual void initJob(const int socketFd, const uint8_t *msg, const size_t msgLen) = 0;

protected:
    std::string socketName_;
    std::string serverName_;
    std::shared_ptr<nmd::common::server_socket> server_;
    std::shared_ptr<thread_pool> pool_;
    nmd::job *job_;
    bool mRunning = false;
};

} // namespace common
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_SERVER_TEMPLATE_H__