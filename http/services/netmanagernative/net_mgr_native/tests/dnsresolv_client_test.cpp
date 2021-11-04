
#include "dnsresolv_client_test.h"
#include <stdio.h>
#include <cstring>

nmd::dnsresolv_client dnsresolv_client_test::dnsresolvClient_;

int dnsresolv_client_test::initConfig()
{
    dnsresolvClient_.init();
    auto ret = dnsresolvClient_.initConfiguration(params);
    if (ret != 0) {
        printf("getaddrinfo: error, can not initConfiguration\n");
        return -1;
    }
    return 0;
}

int dnsresolv_client_test::get_addr_info_test(const char *hostname)
{
    int ret = 0;

    if (!hostname) {
        printf("invalid params\n");
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *res, *res_p;
    std::memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    ret = dnsresolvClient_.getaddrinfo(hostname, NULL, &hints, &res);
    if (ret != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next) {
        char host[1024] = {0};
        ret = getnameinfo(res_p->ai_addr, res_p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if (ret != 0)
            printf("getnameinfo: %s\n", gai_strerror(ret));
        else
            printf("ip: %s\n", host);
    }

    freeaddrinfo(res);
    return ret;
}
