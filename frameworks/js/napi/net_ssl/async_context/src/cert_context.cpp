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

#include "cert_context.h"

#include <algorithm>
#include <node_api.h>

#include "napi_utils.h"
#include "net_ssl_exec.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

static constexpr const int PARAM_JUST_CERT = 1;

static constexpr const int PARAM_CERT_AND_CACERT = 2;

namespace OHOS::NetStack::Ssl {
CertContext::CertContext(napi_env env, EventManager *manager)
    : BaseContext(env, manager), certBlob_(nullptr), certBlobClient_(nullptr),
{
    if (manager_ == nullptr) {
        manager_ = new EventManager;
    }
}

void CertContext::ParseParams(napi_value *params, size_t paramsCount)
{
    bool valid = CheckParamsType(params, paramsCount);
    if (valid) {
        if (paramsCount == PARAM_JUST_CERT) {
            certBlob_ = ParseCertBlobFromParams(GetEnv(), params[0]);
            SetParseOK(certBlob_ != nullptr);
        } else if (paramsCount == PARAM_CERT_AND_CACERT) {
            certBlob_ = ParseCertBlobFromParams(GetEnv(), params[0]);
            certBlobClient_ = ParseCertBlobFromParams(GetEnv(), params[1]);
            SetParseOK(certBlob_ != nullptr && certBlobClient_ != nullptr);
        }
    }
}

bool CertContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_CERT) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object;
    } else if (paramsCount == PARAM_CERT_AND_CACERT) {
        return NapiUtils::GetValueType(GetEnv(), params[0]) == napi_object &&
               NapiUtils::GetValueType(GetEnv(), params[1]) == napi_object;
    }
    return false;
}

CertBlob *CertContext::ParseCertBlobFromParams(napi_env env, napi_value value)
{
    napi_value typeValue, dataValue;
    napi_get_named_property(env, value, "type", &typeValue);
    napi_get_named_property(env, value, "data", &dataValue);
    if (typeValue == nullptr || dataValue == nullptr) {
        return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
    }
    size_t dataSize = 0;
    uint32_t type;
    uint32_t size = 0;
    uint8_t *data = nullptr;
    napi_get_value_uint32(env, typeValue, &type);
    CertType certType = static_cast<CertType>(type);
    if (certType == CERT_TYPE_PEM) {
        napi_valuetype valueType;
        napi_typeof(env, dataValue, &valueType);
        if (valueType != napi_string) {
            NETSTACK_LOGE("pem but not string\n");
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
        napi_get_value_string_utf8(env, dataValue, nullptr, 0, &dataSize);
        if (dataSize + 1 < SIZE_MAX / sizeof(uint8_t)) {
            data = new uint8_t[dataSize + 1];
            napi_get_value_string_utf8(env, dataValue, reinterpret_cast<char *>(data), dataSize + 1, &dataSize);
            size = static_cast<uint32_t>(dataSize);
        } else {
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
    } else if (certType == CERT_TYPE_DER) {
        bool isArrayBuffer = false;
        napi_is_buffer(env, dataValue, &isArrayBuffer);
        if (!isArrayBuffer) {
            NETSTACK_LOGE("der but bot arraybuffer\n");
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
        void *dataArray = nullptr;
        napi_get_arraybuffer_info(env, dataValue, &dataArray, &dataSize);
        if (dataSize < SIZE_MAX / sizeof(uint8_t)) {
            data = new uint8_t[dataSize];
            std::copy(static_cast<uint8_t *>(dataArray), static_cast<uint8_t *>(dataArray) + dataSize, data);
            size = static_cast<uint32_t>(dataSize);
        } else {
            return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
        }
    } else {
        return new CertBlob{CERT_TYPE_MAX, 0, nullptr};
    }
    return new CertBlob{static_cast<CertType>(type), static_cast<uint32_t>(size), static_cast<uint8_t *>(data)};
}

CertBlob *CertContext::GetCertBlob()
{
    return certBlob_;
}

CertBlob *CertContext::GetCertBlobClient()
{
    return certBlobClient_;
}

void CertContext::SetVerifyResult(const uint32_t &verifyResult)
{
    verifyResult_ = verifyResult;
}

uint32_t CertContext::GetVerifyResult()
{
    return verifyResult_;
}

CertContext::~CertContext()
{
    if (certBlob_ != nullptr) {
        if (certBlob_->data != nullptr) {
            delete certBlob_->data;
            certBlob_->data = nullptr;
        }
        delete certBlob_;
        certBlob_ = nullptr;
    }

    if (certBlobClient_ != nullptr) {
        if (certBlobClient_->data != nullptr) {
            delete certBlobClient_->data;
            certBlobClient_->data = nullptr;
        }
        delete certBlobClient_;
        certBlobClient_ = nullptr;
    }
    if (manager_ != nullptr) {
        delete manager_;
        manager_ = nullptr;
    }
    NETSTACK_LOGD("CertContext is destructed by the destructor");
}
} // namespace OHOS::NetStack::Ssl
