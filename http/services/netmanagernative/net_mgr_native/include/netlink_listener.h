#ifndef __INCLUDE_NETLINK_LISTENER_H__
#define __INCLUDE_NETLINK_LISTENER_H__

#include <netlink_socket.h>
#include <functional>
#include "netlink_event.h"

namespace OHOS {
namespace nmd {
class netlink_listener : public netlink_socket {
private:
    bool running_ = false;
    std::function<void(std::shared_ptr<netlink_event>)> onEventHandler_;

    void onDataAvaliable(int fd, char *buf, ssize_t size);

public:
    netlink_listener(int protocol, int pid);
    ~netlink_listener();

    void setOnEventHandler(const std::function<void(std::shared_ptr<netlink_event>)> &handler);
    int listen();

    void stopListen();
    bool getNetlinkListenerState();
};

} // namespace nmd
} // namespace OHOS

#endif //!__INCLUDE_NETLINK_LISTENER_H__