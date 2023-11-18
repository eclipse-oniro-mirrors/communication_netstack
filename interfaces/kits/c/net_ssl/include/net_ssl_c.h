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
 * @brief 为SSL/TLS证书链校验模块提供C接口
 *
 * @since 11
 * @version 1.0
 */

/**
 * @file net_ssl_c.h
 *
 * @brief 为SSL/TLS证书链校验模块定义C接口
 *
 * @library libnet_ssl.so
 * @syscap SystemCapability.Communication.Netstack
 * @since 11
 * @version 1.0
 */

#include "net_ssl_c_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  对外暴露的证书链校验接口
 *
 * @param cert 用户传入的待校验证书
 * @param caCert   用户指定的证书，若为空则以系统预置证书进行校验
 * @return 返回0表示校验成功，否则，表示校验失败
 * @syscap SystemCapability.Communication.Netstack
 * @since 11
 * @version 1.0
 */
uint32_t OH_NetStack_VerifyCertification(const struct OH_NetStack_CertBlob *cert,
                                         const struct OH_NetStack_CertBlob *caCert);
#ifdef __cplusplus
}
#endif

#endif // NET_SSL_C_H
