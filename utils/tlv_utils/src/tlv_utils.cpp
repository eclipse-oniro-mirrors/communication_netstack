/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "tlv_utils.h"

#include "securec.h"
#include "netstack_log.h"

namespace OHOS::NetStack {

#define DFX_MSG_FIELD_NUM 30
#define BUFFER_MAX_SIZE (1 * 256 * 1024)

#define TLV_TAG_LEN sizeof(uint32_t)
#define TLV_LENGTH_LEN sizeof(uint32_t)
#define TLV_TLV_HEAD_LEN (TLV_TAG_LEN + TLV_LENGTH_LEN)

uint8_t *TlvUtils::AppendTlv(uint8_t *buffer, const TlvCommon *tlv, const uint8_t *boundary, uint32_t *retCode)
{
    if (buffer >= boundary) {
        *retCode = TLV_ERR_BUFF_NO_ENOUGH;
        return nullptr;
    }
    if (buffer + (reinterpret_cast<TlvCommon *>(const_cast<uint8_t *>(buffer)))->len_ + TLV_TLV_HEAD_LEN >= boundary) {
        *retCode = TLV_ERR_BUFF_NO_ENOUGH;
        return nullptr;
    }
    (reinterpret_cast<TlvCommon *>(const_cast<uint8_t *>(buffer)))->tag_ = tlv->tag_;
    (reinterpret_cast<TlvCommon *>(const_cast<uint8_t *>(buffer)))->len_ = tlv->len_;
    if (tlv->len_ != 0 && tlv->value_ != nullptr) {
        if (memcpy_s(buffer + TLV_TLV_HEAD_LEN, boundary - buffer - TLV_TLV_HEAD_LEN, tlv->value_, tlv->len_) !=
            EOK) {
            *retCode = TLV_ERR_BUFF_NO_ENOUGH;
            return nullptr;
        }
    }
    *retCode = TLV_OK;
    return buffer + tlv->len_ + TLV_TLV_HEAD_LEN;
}

uint32_t TlvUtils::Serialize(const TlvCommon *tlv, uint32_t tlvCount, uint8_t *buff, uint32_t maxBuffSize,
                             uint32_t *buffSize)
{
    if (tlv == nullptr || buff == nullptr || buffSize == nullptr) {
        return TLV_ERR_INVALID_PARA;
    }
    uint8_t *curr = buff;
    uint8_t *boundary = buff + maxBuffSize;

    uint32_t retCode = TLV_OK;
    for (uint32_t index = 0; index < tlvCount; index++) {
        curr = AppendTlv(curr, &tlv[index], boundary, &retCode);
        if (curr == nullptr || retCode != TLV_OK) {
            return retCode;
        }
    }
    *buffSize = curr - buff;
    return TLV_OK;
}

uint32_t TlvUtils::GenerateTlv(DfxMessage &msg, TlvCommon *tlvs, uint32_t *tlvCount)
{
    uint32_t index = 0;
    tlvs[index++] = TlvCommon{U64, sizeof(msg.requestBeginTime_), &msg.requestBeginTime_};
    tlvs[index++] = TlvCommon{U64, sizeof(msg.dnsEndTime_), &msg.dnsEndTime_};
    tlvs[index++] = TlvCommon{U64, sizeof(msg.tcpConnectEndTime_), &msg.tcpConnectEndTime_};
    tlvs[index++] = TlvCommon{U64, sizeof(msg.tlsHandshakeEndTime_), &msg.tlsHandshakeEndTime_};
    tlvs[index++] = TlvCommon{U64, sizeof(msg.firstSendTime_), &msg.firstSendTime_};
    tlvs[index++] = TlvCommon{U64, sizeof(msg.firstRecvTime_), &msg.firstRecvTime_};
    tlvs[index++] = TlvCommon{U64, sizeof(msg.requestEndTime_), &msg.requestEndTime_};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.requestId_.size()),
                              const_cast<char *>(msg.requestId_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.requestUrl_.size()),
                              const_cast<char *>(msg.requestUrl_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.requestMethod_.size()),
                              const_cast<char *>(msg.requestMethod_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.requestHeader_.size()),
                              const_cast<char *>(msg.requestHeader_.data())};
    tlvs[index++] = TlvCommon{U32, sizeof(msg.responseStatusCode_), &msg.responseStatusCode_};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.responseHeader_.size()),
                              const_cast<char *>(msg.responseHeader_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.responseEffectiveUrl_.size()),
                              const_cast<char *>(msg.responseEffectiveUrl_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.responseIpAddress_.size()),
                              const_cast<char *>(msg.responseIpAddress_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.responseHttpVersion_.size()),
                              const_cast<char *>(msg.responseHttpVersion_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.responseReasonPhrase_.size()),
                              const_cast<char *>(msg.responseReasonPhrase_.data())};
    tlvs[index++] = TlvCommon{STRING, static_cast<uint32_t>(msg.responseBody_.size()),
                              const_cast<char *>(msg.responseBody_.data())};
    *tlvCount = index;
    return TLV_OK;
}

uint32_t TlvUtils::Encode(DfxMessage &msg, void *data, uint32_t &dataSize)
{
    void *tlvsTemp = malloc(sizeof(TlvCommon) * DFX_MSG_FIELD_NUM);
    if (tlvsTemp == nullptr) {
        NETSTACK_LOGE("tlv encode malloc tlvList failed");
        return TLV_ERR;
    }
    auto *tlvs = static_cast<TlvCommon *>(tlvsTemp);
    (void) memset_s(&tlvs[0], sizeof(TlvCommon) * DFX_MSG_FIELD_NUM, 0,
                    sizeof(TlvCommon) * DFX_MSG_FIELD_NUM);
    uint32_t fieldCount = 0;
    GenerateTlv(msg, tlvs, &fieldCount);

    if (data == nullptr) {
        data = malloc(BUFFER_MAX_SIZE);
        if (data == nullptr) {
            NETSTACK_LOGE("tlv encode malloc data failed");
            free(tlvsTemp);
            return TLV_ERR;
        }
    }
    (void) memset_s(data, BUFFER_MAX_SIZE, 0, BUFFER_MAX_SIZE);
    uint32_t ret = Serialize(tlvs, fieldCount, static_cast<uint8_t *>(data), BUFFER_MAX_SIZE,
                             &dataSize);
    free(tlvsTemp);
    NETSTACK_LOGI("tlv encode finished. code=%{public}u", ret);
    return ret;
}
}