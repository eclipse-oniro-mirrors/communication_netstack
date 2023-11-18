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

#ifndef NET_SSL_C_TYPE_H
#define NET_SSL_C_TYPE_H

/**
 * @addtogroup netstack
 * @{
 *
 * @brief  为SSL/TLS证书链校验模块提供C接口
 *
 * @since 11
 * @version 1.0
 */

/**
 * @file net_ssl_c_type.h
 * @brief 定义SSL/TLS证书链校验模块的C接口需要的数据结构
 *
 * @library libnet_ssl.so
 * @syscap SystemCapability.Communication.Netstack
 * @since 11
 * @version 1.0
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 证书类型枚举
 *
 * @since 11
 * @version 1.0
 */
enum OH_NetStack_CertType {
    /** PEM证书类型 */
    OH_NetStack_CERT_TYPE_PEM = 0,
    /** DER证书类型 */
    OH_NetStack_CERT_TYPE_DER = 1,
    /** 错误证书类型 */
    OH_NetStack_CERT_TYPE_MAX
};

/**
 * @brief 证书数据结构体
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_CertBlob {
    /** 证书类型 */
    enum OH_NetStack_CertType type;
    /** 证书内容长度 */
    uint32_t size;
    /** 证书内容 */
    uint8_t *data;
};

#ifdef __cplusplus
}
#endif

#endif // NET_SSL_C_TYPE_H
