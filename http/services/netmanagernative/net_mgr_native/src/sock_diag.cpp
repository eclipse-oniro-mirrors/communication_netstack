#include <sock_diag.h>
#include <sys/socket.h>
#include <functional>
#include <unistd.h>
#include <errno.h>
#include <netlink_msg.h>
#include <net/if.h>
#include <linux/tcp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netlink_socket.h>
#include <network_controller.h>
#include <logger.h>
#include "netnative_log_wrapper.h"

DISABLE_WARNING_PUSH
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_IMPLICIT_INT_CONVERSION
DISABLE_WARNING_SHORTEN_64_TO_32
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_SIGN_COMPARE
DISABLE_WARNING_OLD_STYLE_CAST
DISABLE_WARNING_CAST_ALIGN
DISABLE_WARNING_SIGN_CONVERSION
DISABLE_WARNING_C99_EXTENSIONS

namespace OHOS {
namespace nmd {
void sock_diag::closeSocks()
{
    this->writeSock_.shutdown();
    this->sock_.shutdown();
}

sock_diag::~sock_diag()
{
    closeSocks();
}

bool sock_diag::isLoopbackSocket(const inet_diag_msg *msg)
{
    switch (msg->idiag_family) {
        case AF_INET:
            // Old kernels only copy the IPv4 address and leave the other 12 bytes uninitialized.
            return IN_LOOPBACK(htonl(msg->id.idiag_src[0])) || IN_LOOPBACK(htonl(msg->id.idiag_dst[0])) ||
                msg->id.idiag_src[0] == msg->id.idiag_dst[0];

        case AF_INET6: {
            const struct in6_addr *src = (const struct in6_addr *)&msg->id.idiag_src;
            const struct in6_addr *dst = (const struct in6_addr *)&msg->id.idiag_dst;
            return (IN6_IS_ADDR_V4MAPPED(src) && IN_LOOPBACK(src->s6_addr32[3])) ||
                (IN6_IS_ADDR_V4MAPPED(dst) && IN_LOOPBACK(dst->s6_addr32[3])) || IN6_IS_ADDR_LOOPBACK(src) ||
                IN6_IS_ADDR_LOOPBACK(dst) || !memcmp(src, dst, sizeof(*src));
        }
        default:
            return false;
    }
}

bool sock_diag::open()
{
    this->sock_.create(SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_INET_DIAG);
    this->writeSock_.create(SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_INET_DIAG);

    if (this->sock_.socketFd_ == -1 || this->writeSock_.socketFd_ == -1) {
        closeSocks();
        return false;
    }

    sockaddr_nl nl = {.nl_family = AF_NETLINK};
    if ((connect(this->sock_.socketFd_, reinterpret_cast<sockaddr *>(&nl), sizeof(nl)) == -1) ||
        (connect(this->writeSock_.socketFd_, reinterpret_cast<sockaddr *>(&nl), sizeof(nl)) == -1)) {
        // LogError << "[Diag] connect sock failed." << endl;
        NETNATIVE_LOGE("[Diag] connect sock failed.");
        closeSocks();
        return false;
    }
    return true;
}

int sock_diag::sockDestroy(int proto, const struct inet_diag_msg *msg)
{
    if (msg == nullptr) {
        return 0;
    }

    netlink_msg nlMsg(NLM_F_REQUEST, 4096, getpid());
    inet_diag_req_v2 diagMsg;
    diagMsg.sdiag_family = msg->idiag_family, diagMsg.sdiag_protocol = proto,
    diagMsg.idiag_states = (uint32_t)(1 << msg->idiag_state), diagMsg.id = msg->id,
    nlMsg.addInetDiag(SOCK_DESTROY, diagMsg);

    if (write(writeSock_.socketFd_, nlMsg.getNetLinkMessage(), nlMsg.getNetLinkMessage()->nlmsg_len) <
        nlMsg.getNetLinkMessage()->nlmsg_len) {
        return -errno;
    }

    return 1;
}

int sock_diag::processDestroy(int sock, netlink_dump_callback callback)
{
    char buf[8192];

    ssize_t bytesread;
    do {
        bytesread = read(sock, buf, sizeof(buf));
        if (bytesread < 0) {
            return -errno;
        }

        uint32_t len = bytesread;
        for (nlmsghdr *nlh = reinterpret_cast<nlmsghdr *>(buf); NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            switch (nlh->nlmsg_type) {
                case NLMSG_DONE:
                    return 0;
                case NLMSG_ERROR: {
                    nlmsgerr *err = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(nlh));
                    // LogError << "[DiagNetlinkSocket] Socket error: " << strerror(-err->error)
                    //         << ", type=" << err->msg.nlmsg_type << ", seq=" << err->msg.nlmsg_seq
                    //         << ", pid=" << err->msg.nlmsg_pid << endl;
                    NETNATIVE_LOGE(
                        "[DiagNetlinkSocket] Socket error: %{public}s, type=%{public}d, seq=%{public}d, "
                        "pid=%{public}d",
                        strerror(-err->error), err->msg.nlmsg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);
                    return err->error;
                }
                default:
                    // common::logger::info() << "[DiagNetlinkSocket] dump: "
                    //                       << "type=" << nlh->nlmsg_type << endl;
                    NETNATIVE_LOGI("[DiagNetlinkSocket] dump: type=%{public}d", nlh->nlmsg_type);
                    callback(nlh);
            }
        }
    } while (bytesread > 0);

    return 0;
}

void sock_diag::socketDump(int proto, int family, int states)
{
    netlink_msg nlMsg(NLM_F_REQUEST | NLM_F_DUMP, 4096, getpid());
    inet_diag_req_v2 diagMsg;
    diagMsg.sdiag_family = family, diagMsg.sdiag_protocol = proto, diagMsg.idiag_states = states,
    nlMsg.addInetDiag(SOCK_DIAG_BY_FAMILY, diagMsg);
    this->sock_.sendNetlinkMsgToKernel(nlMsg.getNetLinkMessage());
}

void sock_diag::destroySockets(std::string ifName)
{
    enum {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT,
        TCP_SYN_RECV,
        TCP_FIN_WAIT1,
        TCP_FIN_WAIT2,
        TCP_TIME_WAIT,
        TCP_CLOSE,
        TCP_CLOSE_WAIT,
        TCP_LAST_ACK,
        TCP_LISTEN,
        TCP_CLOSING
    };

    const int proto = IPPROTO_TCP;
    const uint32_t states = (1 << TCP_ESTABLISHED) | (1 << TCP_SYN_SENT) | (1 << TCP_SYN_RECV);

    netlink_dump_callback callback = [this, ifName](nlmsghdr *nlh) {
        const inet_diag_msg *msg = reinterpret_cast<inet_diag_msg *>(NLMSG_DATA(nlh));
        if (msg != nullptr && msg->id.idiag_if == if_nametoindex(ifName.c_str()) && !isLoopbackSocket(msg)) {
            sockDestroy(proto, msg);
        }
    };
    for (const int family : {AF_INET, AF_INET6}) {
        socketDump(proto, family, states);
        processDestroy(sock_.socketFd_, callback);
    }
}
} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP
