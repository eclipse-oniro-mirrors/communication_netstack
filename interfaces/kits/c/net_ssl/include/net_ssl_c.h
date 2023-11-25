/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NET_SSL_C_H
#define NET_SSL_C_H

/**
 * @addtogroup netstack
 * @{
 *
 * @brief Provides C APIs for the SSL/TLS certificate chain verification module.
 *
 * @since 11
 * @version 1.0
 */

/**
 * @file net_ssl_c.h
 *
 * @brief Defines C APIs for the SSL/TLS certificate chain verification module.
 *
 * @library libnet_ssl.so
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */

#include "net_ssl_c_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Provides certificate chain verification APIs for external systems.
 *
 * @param cert Certificate to be verified.
 * @param caCert CA certificate specified by the user. If this parameter is left blank, the preset certificate is used.
 * @return 0 if success; non-0 otherwise.
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
uint32_t OH_NetStack_VerifyCertification(const struct OH_NetStack_CertBlob *cert,
                                         const struct OH_NetStack_CertBlob *caCert);
#ifdef __cplusplus
}
#endif

#endif // NET_SSL_C_H
