#ifndef __NETD_MAIN_TEST_H__
#define __NETD_MAIN_TEST_H__
#include <stdint.h>
#include <iostream>
#include <map>

const int32_t SET_RESOLVER_CONFIG = 0;
const int32_t CREATE_NETWORK_CACHE = 1;
const int32_t FLUSH_NETWORK_CACHE = 2;
const int32_t DESTORY_NETWORK_CACHE = 3;
const int32_t GET_ADDR_INFO = 4;
const int32_t INTERFACE_SET_MTU = 5;
const int32_t NETWORK_SET_DEFAULT = 6;
const int32_t NETWORK_GET_DEFAULT = 7;
const int32_t NETWORK_ClEAR_DEFAULT = 8;
const int32_t NETWORK_CREATE_PHYSICAL = 9;
const int32_t INTERFACE_ADD_ADDRESS = 10;
const int32_t INTERFACE_DEL_ADDRESS = 11;
const int32_t NETWORK_ADD_INTERFACE = 12;
const int32_t NETWORK_REMOVE_INTERFACE = 13;
const int32_t GET_FWMARK_FOR_NETWORK = 14;
const int32_t INTERFACE_SET_CFG = 15;
const int32_t INPUT_QUIT = 100;
using NetdTestFunc = void (*)();

void TestSetResolverConfig();

void TestCreateNetworkCache();

void TestFlushNetworkCache();

void TestDestoryNetworkCache();

void TestGetaddrinfo();

void TestInterfaceSetMtu();

void TestNetworkSetDefault();

void TestNetworkGetDefault();

void TestNetworkClearDefault();

void TestNetworkCreatePhysical();

void TestInterfaceAddAddress();

void TestInterfaceDelAddress();

void TestNetworkAddInterface();

void TestNetworkRemoveInterface();

void TestGetFwmarkForNetwork();

void TestInterfaceSetCfg();
#endif //!__NETD_MAIN_TEST_H__