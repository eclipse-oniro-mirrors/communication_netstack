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

#ifndef COMMUNICATIONNETSTACK_NET_SSL_TYPE_H
#define COMMUNICATIONNETSTACK_NET_SSL_TYPE_H

enum CertType {
    /** PEM证书类型 */
    CERT_TYPE_PEM = 0,
    /** DER证书类型 */
    CERT_TYPE_DER = 1,
    /** 错误证书类型 */
    CERT_TYPE_MAX
};

struct CertBlob {
    /** 证书类型 */
    CertType type;
    /** 证书内容长度 */
    uint32_t size;
    /** 证书内容 */
    uint8_t *data;
};

#endif // COMMUNICATIONNETSTACK_NET_SSL_TYPE_H
