#include "netlink_socket.h"
#include "traffic_controller.h"
#include "warning_disable.h"
#include <arpa/inet.h>
#include <asm/types.h>
#include <iostream>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <logger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
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

#define EPOLL_SIZE 50

#define MAX_PAYLOAD 4096

namespace OHOS {
namespace nmd {
namespace {
__u32 nl_mgrp(__u32 group)
{
    if (group > 31) {
        printf("Netlink: Use setsockopt for this group: %d\n", group);
        return 0;
    }
    return group ? (1 << (group - 1)) : 0;
}
} // namespace

netlink_socket::~netlink_socket()
{
    close(this->socketFd_);
}

int netlink_socket::create(int protocol)
{
    return this->create(SOCK_RAW, protocol);
}

int netlink_socket::create(int type, int protocol)
{
    this->socketFd_ = -1;
    if ((this->socketFd_ = socket(AF_NETLINK, type, protocol)) == -1) {
        // LogError << "[NetlinkSocket] create socket failed:" << strerror(errno) << endl;
        NETNATIVE_LOGE("[NetlinkSocket] create socket failed: %{public}s", strerror(errno));
        return -1;
    }
    return this->socketFd_;
}

int netlink_socket::binding()
{
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = this->pid_;
    local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE |
        nl_mgrp(RTNLGRP_NEIGH);

    struct sockaddr *ad = reinterpret_cast<sockaddr *>(&local);
    memcpy(&(this->addr_), ad, sizeof(*ad));

    int retval = bind(this->socketFd_, &this->addr_, sizeof(this->addr_));
    if (retval == -1) {
        // LogError << "[NetlinkSocket] bind socket(" << this->socketFd_ << ") failed: " << strerror(errno) << endl;
        NETNATIVE_LOGE(
            "[NetlinkSocket] bind socket %{public}d failed: %{public}s", this->socketFd_, strerror(errno));
        close(this->socketFd_);
        return -1;
    }
    return retval;
}

int netlink_socket::acceptAndListen()
{
    char buffer[8192] = {};
    struct iovec iov = {buffer, sizeof(buffer)};
    struct sockaddr_nl netlinkAddr;
    struct msghdr msg = {(void *)&netlinkAddr, sizeof(netlinkAddr), &iov, 1, ((void *)0), 0, 0};

    ssize_t size = recvmsg(this->socketFd_, &msg, 0);
    if (size < 0) {
        return 0;
    }

    if (netlinkAddr.nl_pid != 0) {
        // LogError << "[NetlinkSocket] Ignore non kernel message from pid:" << netlinkAddr.nl_pid << endl;
        NETNATIVE_LOGE("[NetlinkSocket] Ignore non kernel message from pid: %{public}d", netlinkAddr.nl_pid);
        return 0;
    }

    if (size == 0) {
        // LogError << "[NetlinkSocket] EOF." << endl;
        NETNATIVE_LOGE("[NetlinkSocket] EOF.");
        return -1;
    }

    if (msg.msg_namelen != sizeof(netlinkAddr)) {
        // LogError << "[NetlinkSocket] sender address length error." << endl;
        NETNATIVE_LOGE("[NetlinkSocket] sender address length error.");
        return -1;
    }

    for (struct nlmsghdr *hdr = (struct nlmsghdr *)buffer; NLMSG_OK(hdr, size); hdr = NLMSG_NEXT(hdr, size)) {
        switch (hdr->nlmsg_type) {
            case NLMSG_DONE:
                return 0;
            case NLMSG_ERROR: {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
                if (err->error == 0) {
                    return 0;
                }
                if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    // LogError << "[NetlinkSocket] Socket error: message truncated" << endl;
                    NETNATIVE_LOGE("[NetlinkSocket] Socket error: message truncated");
                    return -1;
                }
                // LogError << "[NetlinkSocket] Socket error: " << strerror(-err->error)
                //         << ", type=" << err->msg.nlmsg_type << ", seq=" << err->msg.nlmsg_seq
                //         << ", pid=" << err->msg.nlmsg_pid << endl;
                NETNATIVE_LOGE(
                    "[NetlinkSocket] Socket error: %{public}s, type=%{public}d, seq=%{public}d, pid=%{public}d",
                    strerror(-err->error), err->msg.nlmsg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);
                return -1;
            }
            case RTM_NEWNEIGH:
            case RTM_DELNEIGH: {
                int isTetherEnable = 1; // mock tether is enable
                if (isTetherEnable == 1) {
                    // nmd::traffic_controller::getTetherClientInfo();
                    nmd::traffic_controller::startTrafficTether();
                }
                return 0;
            }
            default:
                this->handler_(this->socketFd_, buffer, size);
                break;
        }
    }
    return 0;
}

int netlink_socket::sendNetlinkMsgToKernel(struct nlmsghdr *msg)
{
    if (!msg) {
        // LogError << "[NetlinkSocket] msg can not be null " << endl;
        NETNATIVE_LOGE("[NetlinkSocket] msg can not be null ");
        return -1;
    }
    struct iovec ioVector;
    ioVector.iov_base = msg;
    ioVector.iov_len = msg->nlmsg_len;

    struct msghdr msgHeader;
    memset(&msgHeader, 0, sizeof(msgHeader));

    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_groups = 0;

    msgHeader.msg_name = &kernel;
    msgHeader.msg_namelen = sizeof(kernel);
    msgHeader.msg_iov = &ioVector;
    msgHeader.msg_iovlen = 1;

    long msgState = sendmsg(this->socketFd_, &msgHeader, 0);
    if (msgState == -1) {
        // LogError << "[NetlinkSocket] socket: " << this->socketFd_ << ",msg send failed: " << strerror(errno)
        //         << endl;
        NETNATIVE_LOGE("[NetlinkSocket] msg can not be null ");
        return -1;
    } else if (msgState == 0) {
        // LogError << "[NetlinkSocket] 0 bytes send." << endl;
        NETNATIVE_LOGE("[NetlinkSocket] 0 bytes send.");
        return -1;
    }
    return msgState;
}

ssize_t netlink_socket::receive(void *buf)
{
    struct nlmsghdr *msg = reinterpret_cast<struct nlmsghdr *>(buf);
    memset(msg, 0, NLMSG_SPACE(MAX_PAYLOAD));
    ssize_t size = recv(this->socketFd_, reinterpret_cast<char *>(msg), MAX_PAYLOAD, 0);
    return size;
}

int netlink_socket::shutdown()
{
    return close(this->socketFd_);
}

void netlink_socket::setOnDataReceiveHandler(const std::function<void(int, char *, ssize_t)> &handler)
{
    this->handler_ = handler;
}

} // namespace nmd
} // namespace OHOS
DISABLE_WARNING_POP