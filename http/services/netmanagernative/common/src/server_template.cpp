#include "server_template.h"
#include "logger.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
void common::server_template::start()
{
    // common::logger::info() << serverName_ << " start ." << endl;
    NETNATIVE_LOGD("%{public}s start .", serverName_.c_str());
    this->server_->createUnix();
    NETNATIVE_LOGI("setRecevedHandler start:");
    this->server_->setRecevedHandler<void, common::server_template, const int, const uint8_t *, const size_t>(
        &common::server_template::handler, this);
    NETNATIVE_LOGI("setRecevedHandler end:");
    this->server_->bindFile(SOCKET_FILE_PATH, socketName_.c_str());
    this->server_->listenSocket();

    this->mRunning = true;
    while (this->mRunning) {
        this->server_->acceptSocket();
    }
}

void common::server_template::stop()
{
    this->mRunning = false;
}

void common::server_template::handler(int socketFd, const uint8_t *msg, const size_t msgLen)
{
    // common::logger::info() << "socket:" << socketFd << ",msg:" << msg << endl;
    NETNATIVE_LOGD("socket: %{public}d ,msg: %{public}s", socketFd, msg);
    initJob(socketFd, msg, msgLen);
    this->pool_->execute(job_);
}
} // namespace nmd
} // namespace OHOS