#ifndef __NETD_COMMON_SERVER_SOCKET_H__
#define __NETD_COMMON_SERVER_SOCKET_H__

#include "socket_base.h"
namespace OHOS {
namespace nmd {
namespace common {
class server_socket : public socket_base {
private:
    struct sockaddr addr_ {};

public:
    server_socket();
    ~server_socket();

    int bindPort(uint16_t port);
    int bindFile(const char *filePath, const char *name);
};

} // namespace common

} // namespace nmd
} // namespace OHOS
#endif // __NETD_COMMON_SERVER_SOCKET_H__