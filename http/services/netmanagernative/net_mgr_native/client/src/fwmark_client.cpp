#include "fwmark_client.h"
#include <errno.h>
#include <linux/un.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <logger.h>
#include <stdio.h>
#include <stdlib.h>

const char *FWMARK_SERVICE_SOCK_PATH = "/dev/socket/fwmarkd.sock";
nmd::fwmark_client::fwmark_client(/* args */) {}

nmd::fwmark_client::~fwmark_client() {}

int nmd::fwmark_client::send(fwmark_command *data)
{
    this->channel_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (this->channel_ == -1) {
        return -errno;
    }

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, FWMARK_SERVICE_SOCK_PATH);

    struct sockaddr addr_ {};
    struct sockaddr *ad = reinterpret_cast<sockaddr *>(&addr);
    memcpy(&(addr_), ad, sizeof(*ad));
    if (connect(this->channel_, &addr_, sizeof(addr_)) == -1) {
        close(this->channel_);
        return -errno;
    }

    iovec iov[1] = {{data, sizeof(*data)}};

    msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    if (sendmsg(this->channel_, &hdr, 0) == -1) {
        close(this->channel_);
        return -errno;
    }
    char buf[sizeof(int)] = {'\0'};
    auto ret = recv(this->channel_, buf, sizeof(int), 0);
    if (ret == -1 || ret == 0) {
        close(this->channel_);
        return -errno;
    }
    close(this->channel_);
    common::logger::info() << "[FwmarkClient] recv:" << atoi(buf) << endl;
    return atoi(buf);
}