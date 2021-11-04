#ifndef __INCLUDE_JOB_H__
#define __INCLUDE_JOB_H__

#include "server_socket.h"
#include <vector>
namespace OHOS {
namespace nmd {
class job {
public:
    job(const int fd, const uint8_t *msg, const size_t msgLen,
        const std::shared_ptr<common::socket_base> serverSocket)
        : fd_(fd), msg_(msg, msg + msgLen), serverSocket_(serverSocket)
    {}
    virtual ~job() = default;
    virtual void run() = 0;

protected:
    int fd_;
    std::vector<uint8_t> msg_;
    std::shared_ptr<common::socket_base> serverSocket_;
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_JOB_H__