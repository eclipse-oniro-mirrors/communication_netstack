#ifndef __CASE_DNSRESOLV_CLIENT_TEST_H__
#define __CASE_DNSRESOLV_CLIENT_TEST_H__
#include "dnsresolv_client.h"

class dnsresolv_client_test {
    const nmd::dnsresolver_params params = {
        nmd::NETID_UNSET, 0, 1, {"8.8.8.8", "114.114.114.114"}, {"baidu.com", "google.com"}};

private:
    static nmd::dnsresolv_client dnsresolvClient_;

public:
    dnsresolv_client_test() {}

    ~dnsresolv_client_test()
    {
        dnsresolvClient_.unInitConfiguration(params);
    }

public:
    int initConfig();
    int get_addr_info_test(const char *hostname);
};

#endif //!__CASE_DNSRESOLV_CLIENT_TEST_H__