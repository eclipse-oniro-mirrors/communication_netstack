/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NETD_CONTROLLER_H
#define NETD_CONTROLLER_H

#include <string>
#include <singleton.h>

#include "native_netd_service.h"

#include "fwmark_server.h"
#include "dnsresolv_service.h"
#include "netlink_manager.h"
#ifdef NATIVE_NETD_FEATURE

#endif
#include "route.h"
#include "netmgr_log_wrapper.h"

namespace OHOS {
namespace NetManagerStandard {
class NetdController {
    DECLARE_DELAYED_SINGLETON(NetdController)
public:
    void Init();

    /**
     * @brief Create a physical network
     *
     * @param netId
     * @param permission Permission to create a physical network
     * @return Return the return value of the netd interface call
     */
    int32_t NetworkCreatePhysical(int32_t netId, int32_t permission);

    /**
     * @brief Destroy the network
     *
     * @param netId
     * @return Return the return value of the netd interface call
     */
    int32_t NetworkDestroy(int32_t netId);

    /**
     * @brief Add network port device
     *
     * @param netId
     * @param iface Network port device name
     * @return Return the return value of the netd interface call
     */
    int32_t NetworkAddInterface(int32_t netId, const std::string &iface);

    /**
     * @brief Delete network port device
     *
     * @param netId
     * @param iface Network port device name
     * @return Return the return value of the netd interface call
     */
    int32_t NetworkRemoveInterface(int32_t netId, const std::string &iface);

    /**
     * @brief Add route
     *
     * @param netId
     * @param ifName Network port device name
     * @param destination Target host ip
     * @param nextHop Next hop address
     * @return Return the return value of the netd interface call
     */
    int32_t NetworkAddRoute(
        int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop);

    /**
     * @brief Remove route
     *
     * @param netId
     * @param ifName Network port device name
     * @param destination Target host ip
     * @param nextHop Next hop address
     * @return Return the return value of the netd interface call
     */
    int32_t NetworkRemoveRoute(
        int32_t netId, const std::string &ifName, const std::string &destination, const std::string &nextHop);

    /**
     * @brief Turn off the device
     *
     * @param iface Network port device name
     */
    void SetInterfaceDown(const std::string &iface);

    /**
     * @brief Turn on the device
     *
     * @param iface Network port device name
     */
    void SetInterfaceUp(const std::string &iface);

    /**
     * @brief Clear the network interface ip address
     *
     * @param ifName Network port device name
     */
    void InterfaceClearAddrs(const std::string &ifName);

    /**
     * @brief Obtain mtu from the network interface device
     *
     * @param ifName Network port device name
     * @return Return the return value of the netd interface call
     */
    int32_t InterfaceGetMtu(const std::string &ifName);

    /**
     * @brief Set mtu to network interface device
     *
     * @param ifName Network port device name
     * @param mtu
     * @return Return the return value of the netd interface call
     */
    int32_t InterfaceSetMtu(const std::string &ifName, int32_t mtu);

    /**
     * @brief Add ip address
     *
     * @param ifName Network port device name
     * @param addrString    ip address
     * @param prefixLength  subnet mask
     * @return Return the return value of the netd interface call
     */
    int32_t InterfaceAddAddress(const std::string &ifName, const std::string &addrString, int32_t prefixLength);

    /**
     * @brief Delete ip address
     *
     * @param ifName Network port device name
     * @param addrString ip address
     * @param prefixLength subnet mask
     * @return Return the return value of the netd interface call
     */
    int32_t InterfaceDelAddress(const std::string &ifName, const std::string &addrString, int32_t prefixLength);

    /**
     * @brief Set dns
     *
     * @param netId
     * @param baseTimeoutMsec
     * @param retryCount
     * @param servers
     * @param domains
     * @return Return the return value of the netd interface call
     */
    int32_t SetResolverConfig(uint16_t netId, uint16_t baseTimeoutMsec, uint8_t retryCount,
        const std::vector<std::string> &servers, const std::vector<std::string> &domains);

private:
    std::unique_ptr<nmd::NativeNetdService> netdService_ = nullptr;

    std::unique_ptr<nmd::netlink_manager> manager_ = nullptr;
    std::unique_ptr<nmd::fwmark_server> fwmarkServer_ = nullptr;
    std::unique_ptr<nmd::dnsresolv_service> dnsResolvService_ = nullptr;
#ifdef NATIVE_NETD_FEATURE

#endif
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NETD_CONTROLLER_H
