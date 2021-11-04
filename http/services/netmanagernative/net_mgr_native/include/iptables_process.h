#ifndef __INCLUDE_IPTABLES_PROCESS_H__
#define __INCLUDE_IPTABLES_PROCESS_H__

#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <functional>
namespace OHOS {
namespace nmd {
class iptables_process {
public:
    pid_t pid_;
    int stdin_;
    int stdout_;
    int stderr_;

private:
    std::string errBuf;

    struct pollfd pollFds_[2];

public:
    iptables_process();
    iptables_process(pid_t pid, int in, int out, int err);
    ~iptables_process();

    bool waitForAck(std::string &output);
    void terminate();

    static std::shared_ptr<nmd::iptables_process> forkAndExecute();
};

} // namespace nmd

} // namespace OHOS
#endif //!__INCLUDE_IPTABLES_PROCESS_H__