#include "fwmark_server.h"
#include "fwmark.h"
#include "fwmark_command.h"
#include "logger.h"
#include "string.h"
#include <errno.h>
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace nmd {
void fwmark_server::initJob(const int socketFd, const uint8_t *msg, const size_t msgLen)
{
    this->job_ = new nmd::fwmark_job(socketFd, msg, msgLen, this->server_);
}

void fwmark_job::run()
{
    if (fd_ < 0 || msg_.empty() || nullptr == serverSocket_) {
        return;
    }
    struct fwmark_command *command = reinterpret_cast<struct fwmark_command *>(msg_.data());
    fwmark mark;
    socklen_t fwmarkLen = sizeof(mark.val);
    if (getsockopt(static_cast<int>(command->fd), SOL_SOCKET, SO_MARK, &mark.val, &fwmarkLen) == -1) {
        // LogError << "[FwmarkServer]: socket get " << command->fd << "'s fwmark failed: " << strerror(errno) << endl;
        NETNATIVE_LOGE(
            "[FwmarkServer]: socket get %{public}d 's fwmark failed: %{public}s", command->fd, strerror(errno));
        this->responseFailed();
        return;
    }

    mark.bits.netId = command->netId;
    if (setsockopt(static_cast<int>(command->fd), SOL_SOCKET, SO_MARK, &mark.val, sizeof(mark.val)) == -1) {
        // LogError << "[FwmarkServer]: socket set fwmark failed: " << strerror(errno) << endl;
        NETNATIVE_LOGD("[FwmarkServer]: socket set fwmark failed: %{public}s", strerror(errno));
        this->responseFailed();
        return;
    }
    this->responseOk();
}

void fwmark_job::responseOk()
{
    this->serverSocket_->sendSocket(this->fd_, "1");
}

void fwmark_job::responseFailed()
{
    this->serverSocket_->sendSocket(this->fd_, "0");
}
} // namespace nmd
} // namespace OHOS