#ifndef __INCLUDE_FWMARK_SERVER_H__
#define __INCLUDE_FWMARK_SERVER_H__

#include "job.h"
#include "server_template.h"
#include <memory>
namespace OHOS {
namespace nmd {
const char *const FWMARK_SERVER_SOCK_NAME = "fwmarkd.sock";
const char *const FWMARK_SERVER_NAME = "FWMarkServer";

class fwmark_job : public job {
public:
    fwmark_job(const int fd, const uint8_t *msg, const size_t msgLen,
        const std::shared_ptr<common::server_socket> &serverSocket)
        : job(fd, msg, msgLen, serverSocket)
    {}
    ~fwmark_job() = default;

    virtual void run() override;

private:
    void responseOk();
    void responseFailed();
};

class fwmark_server : public common::server_template {
public:
    fwmark_server() : common::server_template(FWMARK_SERVER_SOCK_NAME, FWMARK_SERVER_NAME) {}

    virtual ~fwmark_server() = default;

private:
    virtual void initJob(const int socketFd, const uint8_t *msg, const size_t msgLen) override;
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_FWMARK_SERVER_H__