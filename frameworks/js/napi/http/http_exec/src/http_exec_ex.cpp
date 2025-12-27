/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "http_exec.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <pthread.h>
#include <sstream>
#include <thread>
#include <unistd.h>
#ifdef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#endif
#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
#ifndef HTTP_MULTIPATH_CERT_ENABLE
#include <openssl/ssl.h>
#endif
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#endif
#if HAS_NETMANAGER_BASE
#include <netdb.h>
#endif

#ifdef HTTP_PROXY_ENABLE
#include "parameter.h"
#endif
#ifdef HAS_NETMANAGER_BASE
#include "http_proxy.h"
#include "net_conn_client.h"
#include "network_security_config.h"
#include "netsys_client.h"
#endif
#include "base64_utils.h"
#include "cache_proxy.h"
#include "constant.h"
#if HAS_NETMANAGER_BASE
#include "epoll_request_handler.h"
#endif
#include "event_list.h"
#if HAS_NETMANAGER_BASE
#include "hitrace_meter.h"
#include "netstack_hisysevent.h"
#include "netstack_log.h"
#endif
#include "http_async_work.h"
#include "http_time.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "secure_char.h"
#include "securec.h"

#include "http_utils.h"
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_info.h"
#endif

#ifdef HAS_NETMANAGER_BASE
#define NETSTACK_CURL_EASY_SET_OPTION(handle, opt, data, asyncContext)                                   \
    do {                                                                                                 \
        CURLcode result = curl_easy_setopt(handle, opt, data);                                           \
        if (result != CURLE_OK) {                                                                        \
            const char *err = curl_easy_strerror(result);                                                \
            NETSTACK_LOGE("Failed to set option: %{public}s, %{public}s %{public}d", #opt, err, result); \
            (asyncContext)->SetErrorCode(result);                                                        \
            return false;                                                                                \
        }                                                                                                \
    } while (0)

#endif

#ifdef HAS_NETMANAGER_BASE
#define MIN_NON_SYSTEM_NETID 100
#define DUAL_NETWORK_BOOT_COUNT 2
#define SINGLE_CELLULAR_NETWORK_COUNT 1
#endif

namespace OHOS::NetStack::Http {
#ifdef HAS_NETMANAGER_BASE
bool HttpExec::SetInterface(CURL *curl, RequestContext *context)
{
    if (curl == nullptr || context == nullptr) {
        return false;
    }
    std::string interfaceName;
    int32_t netId;
    bool ret = GetInterfaceName(curl, context, interfaceName, netId);
    if (ret && !interfaceName.empty() && netId >= MIN_NON_SYSTEM_NETID) {
        bool ipv6Enable = NetSysIsIpv6Enable(netId);
        bool ipv4Enable = NetSysIsIpv4Enable(netId);
        if (!ipv6Enable) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4, context);
        } else if (!ipv4Enable) {
            NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6, context);
        }
#ifdef HTTP_HANDOVER_FEATURE
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_OHOS_SOCKET_BIND_NET_ID, netId, context);
#endif
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_INTERFACE, interfaceName.c_str(), context);
        NETSTACK_CURL_EASY_SET_OPTION(curl, CURLOPT_DNS_INTERFACE, interfaceName.c_str(), context);
        return true;
    }
    return false;
}

bool HttpExec::GetInterfaceName(CURL *curl, RequestContext *context, std::string &interfaceName, int32_t &netId)
{
    if (curl == nullptr || context == nullptr) {
        return false;
    }
    if (context->options.GetPathPreference() == PathPreference::autoPath) {
        return false;
    }
    std::list<sptr<NetManagerStandard::NetHandle>> netList;
    if (NetManagerStandard::NetConnClient::GetInstance().GetAllNets(netList)
        == NetManagerStandard::NetConnResultCode::NET_CONN_SUCCESS) {
        netList.remove_if([](const sptr<NetManagerStandard::NetHandle>& net) {
            return net->GetNetId() < MIN_NON_SYSTEM_NETID;
        });
    }
    if (netList.size() == DUAL_NETWORK_BOOT_COUNT) {
        if (context->options.GetPathPreference() == PathPreference::primaryCellular) {
            bool ret = GetPrimaryCellularInterface(curl, context, netList, interfaceName, netId);
            return ret;
        } else if (context->options.GetPathPreference() == PathPreference::secondaryCellular) {
            bool ret = GetSecondaryCellularInterface(curl, context, netList, interfaceName, netId);
            return ret;
        } else if (context->options.GetPathPreference() == PathPreference::autoPath) {
            return false;
        }
    }
    return false;
}

bool HttpExec::GetPrimaryCellularInterface(CURL *curl, RequestContext *context,
    std::list<sptr<NetManagerStandard::NetHandle>> netList, std::string &interfaceName, int32_t &netId)
{
    if (curl == nullptr || context == nullptr) {
        return false;
    }
    if (netList.size() != DUAL_NETWORK_BOOT_COUNT) {
        return false;
    }

    NetManagerStandard::NetHandle defaultHandle;
    if (NetManagerStandard::NetConnClient::GetInstance().GetDefaultNet(defaultHandle) !=
        NetManagerStandard::NETMANAGER_SUCCESS) {
        return false;
    }
    NetManagerStandard::NetAllCapabilities netAllCap;
    if (NetManagerStandard::NetConnClient::GetInstance().GetNetCapabilities(defaultHandle, netAllCap) ==
        NetManagerStandard::NETMANAGER_SUCCESS) {
        if (netAllCap.bearerTypes_.find(NetManagerStandard::NetBearType::BEARER_CELLULAR) !=
            netAllCap.bearerTypes_.end()) {
            return false;
        }
    }

    uint8_t cellCount = 0;
    uint8_t wifiCount = 0;
    std::list<sptr<NetManagerStandard::NetHandle>> cellularNetworks;
    if (!GetNetStatus(netList, cellularNetworks, cellCount, wifiCount)) {
        return false;
    }

    if (cellCount == SINGLE_CELLULAR_NETWORK_COUNT && netList.size() == DUAL_NETWORK_BOOT_COUNT) {
        NetManagerStandard::NetLinkInfo info;
        if (!cellularNetworks.empty() && cellularNetworks.size() == SINGLE_CELLULAR_NETWORK_COUNT &&
            NetManagerStandard::NetConnClient::GetInstance().GetConnectionProperties(*(cellularNetworks.front()),
            info) == NetManagerStandard::NETMANAGER_SUCCESS) {
            interfaceName = info.ifaceName_;
            netId = cellularNetworks.front()->GetNetId();
            return true;
        }
    }

    return false;
}

bool HttpExec::GetSecondaryCellularInterface(CURL *curl, RequestContext *context,
    std::list<sptr<NetManagerStandard::NetHandle>> netList, std::string &interfaceName, int32_t &netId)
{
    if (curl == nullptr || context == nullptr) {
        return false;
    }
    if (netList.size() != DUAL_NETWORK_BOOT_COUNT) {
        return false;
    }
    uint8_t cellCount = 0;
    uint8_t wifiCount = 0;
    std::list<sptr<NetManagerStandard::NetHandle>> cellularNetworks;
    
    if (!GetNetStatus(netList, cellularNetworks, cellCount, wifiCount)) {
        return false;
    }
    
    if (cellCount == SINGLE_CELLULAR_NETWORK_COUNT) {
        return false;
    } else if (cellCount == DUAL_NETWORK_BOOT_COUNT) {
        NetManagerStandard::NetHandle defaultHandle;
        if (NetManagerStandard::NetConnClient::GetInstance().GetDefaultNet(defaultHandle) !=
            NetManagerStandard::NETMANAGER_SUCCESS) {
            return false;
        }
        for (auto net : cellularNetworks) {
            if (defaultHandle.GetNetId() == net->GetNetId()) {
                continue;
            }
            NetManagerStandard::NetLinkInfo info;
            if (NetManagerStandard::NetConnClient::GetInstance().GetConnectionProperties(*net, info) ==
                NetManagerStandard::NETMANAGER_SUCCESS) {
                interfaceName = info.ifaceName_;
                netId = net->GetNetId();
                return true;
            }
        }
    }
    return false;
}

bool HttpExec::GetNetStatus(std::list<sptr<NetManagerStandard::NetHandle>> netList,
    std::list<sptr<NetManagerStandard::NetHandle>> &cellularNetworks, uint8_t &cellCount, uint8_t &wifiCount)
{
    if (netList.size() != DUAL_NETWORK_BOOT_COUNT) {
        return false;
    }
    
    for (auto net : netList) {
        NetManagerStandard::NetAllCapabilities netAllCap;
        if (net != nullptr && NetManagerStandard::NetConnClient::GetInstance().GetNetCapabilities(*net, netAllCap) ==
            NetManagerStandard::NETMANAGER_SUCCESS) {
            if (netAllCap.bearerTypes_.find(NetManagerStandard::NetBearType::BEARER_CELLULAR) !=
                netAllCap.bearerTypes_.end()) {
                cellCount++;
                cellularNetworks.push_back(net);
            }
            if (netAllCap.bearerTypes_.find(NetManagerStandard::NetBearType::BEARER_WIFI) !=
                netAllCap.bearerTypes_.end()) {
                wifiCount++;
            }
        }
    }
    return true;
}
#endif
} // namespace OHOS::NetStack::Http