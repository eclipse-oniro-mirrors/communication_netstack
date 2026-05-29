/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NET_SOCKET_CONSTANT_H
#define NET_SOCKET_CONSTANT_H

#include <map>
#include <string>

namespace OHOS::NetStack::Socket {

constexpr const int DEFAULT_BUFFER_SIZE = 8192;
constexpr const int MAX_SOCKET_BUFFER_SIZE = 262144;
constexpr const int DEFAULT_TIMEOUT_MS = 20000;
constexpr const int DEFAULT_POLL_TIMEOUT = 500;
constexpr const int ADDRESS_INVALID = 99;
constexpr const int OTHER_ERROR = 100;
constexpr const int UNKNOW_ERROR = -1;
constexpr const int NO_MEMORY = -2;
constexpr const int USER_LIMIT = 511;
constexpr const int MAX_CLIENTS = 1024;
constexpr const int ERRNO_BAD_FD = 9;
constexpr const int UNIT_CONVERSION_1000 = 1000;
constexpr const int DEFAULT_CONNECT_TIMEOUT = 60000;

constexpr const char *EVENT_MESSAGE = "message";
constexpr const char *EVENT_LISTENING = "listening";
constexpr const char *EVENT_ERROR = "error";
constexpr const char *EVENT_CONNECT = "connect";
constexpr const char *EVENT_CLOSE = "close";

constexpr const char *KEY_ADDRESS = "address";
constexpr const char *KEY_FAMILY = "family";
constexpr const char *KEY_PORT = "port";
constexpr const char *KEY_TIMEOUT = "timeout";
constexpr const char *KEY_DATA = "data";
constexpr const char *KEY_ENCODING = "encoding";

enum SocketErrorCode {
    SOCKET_ERROR_CODE_BASE = 2301000,
    SOCKET_SERVER_ERROR_CODE_BASE = 2303100,
};

constexpr const int32_t ERR_OK = 0;
constexpr const int32_t ERR_INVALID_INSTANCE_CODE = -1;
constexpr const int32_t PERMISSION_DENIED_CODE = 201;
constexpr const int32_t PARAMETER_ERROR_CODE = 401;

inline int32_t ConvertErrCode(int err)
{
    if (err <= 0) {
        return SOCKET_ERROR_CODE_BASE;
    }
    return err + SOCKET_ERROR_CODE_BASE;
}

static const std::map<int32_t, std::string> SOCKET_ERR_MAP = {
    {SOCKET_ERROR_CODE_BASE, "Unknown Other Error"},
    {201, "Permission denied"},
    {401, "Parameter error"},
};

enum OnOffType {
    EVENT_TYPE_MESSAGE = 1,
    EVENT_TYPE_CONNECT = 2,
    EVENT_TYPE_CLOSE = 3,
    EVENT_TYPE_ERROR = 4,
    EVENT_TYPE_LISTENING = 5,
};

}
#endif
