#ifndef __INCLUDE_SOCK_DIAG_H__
#define __INCLUDE_SOCK_DIAG_H__

#include <string>
#include <linux/netlink.h>
#include <functional>
#include <linux/inet_diag.h>
#include <netlink_socket.h>

#define IN_LOOPBACK(a) ((((long int)(a)) & 0xff000000) == 0x7f000000)
namespace OHOS {
namespace nmd {
typedef std::function<void(struct nlmsghdr *)> netlink_dump_callback;

class sock_diag {
private:
    void closeSocks();

    netlink_socket sock_;
    netlink_socket writeSock_;

public:
    sock_diag() = default;
    ~sock_diag();
    bool open();
    void destroySockets(std::string ifName);
    int sockDestroy(int proto, const struct inet_diag_msg *msg);
    int processDestroy(int sock, netlink_dump_callback callback);
    bool isLoopbackSocket(const inet_diag_msg *msg);
    void socketDump(int proto, int family, int states);
};
} // namespace nmd
} // namespace OHOS
#endif //!__INCLUDE_SOCK_DIAG_H__