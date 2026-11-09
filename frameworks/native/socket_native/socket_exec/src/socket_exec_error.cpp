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

#include "socket_exec_error.h"
#include "socket_constant.h"
#include "socks5.h"
#include "socket_error.h"
#include <cerrno>
#include <string>
#include <map>

namespace OHOS {
namespace NetStack {
namespace Socket {

const static std::map<int32_t, std::string> SOCKET_ERROR_MESSAGE_MAP = {
    {UNKNOWN_ERROR, "Unknown Other Error"},
    {PERMISSION_DENIED_CODE, PERMISSION_DENIED_MSG},
    {PARAM_ERROR_CODE, PARAM_ERROR_MSG},
    {SYSTEM_INTERNAL_ERROR, SYSTEM_INTERNAL_ERROR_MSG},

    {SOCKET_ERROR_CODE_BASE + EBADF, "Bad file descriptor"},
    {SOCKET_ERROR_CODE_BASE + EAGAIN, "Operation would block"},
    {SOCKET_ERROR_CODE_BASE + EACCES, "Insufficient permissions"},
    {SOCKET_ERROR_CODE_BASE + EINVAL, "Invalid argument"},
    {SOCKET_ERROR_CODE_BASE + ENOTSOCK, "Not a socket"},
    {SOCKET_ERROR_CODE_BASE + EADDRINUSE, "Address already in use"},
    {SOCKET_ERROR_CODE_BASE + EADDRNOTAVAIL, "Cannot assign requested address"},
    {SOCKET_ERROR_CODE_BASE + ECONNREFUSED, "Connection refused"},

    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_FAIL_TO_CONNECT_PROXY),
        "Socks5 failed to connect to the proxy server"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_USER_PASS_INVALID),
        "Socks5 username or password is invalid"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_FAIL_TO_CONNECT_REMOTE),
        "Socks5 failed to connect to the remote server"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_METHOD_NEGO_ERROR),
        "Socks5 failed to negotiate the authentication method"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_FAIL_TO_SEND_MSG),
        "Socks5 failed to send the message"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_FAIL_TO_RECV_MSG),
        "Socks5 failed to receive the message"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_SERIALIZE_ERROR),
        "Socks5 serialization error"},
    {SOCKET_ERROR_CODE_BASE + static_cast<int32_t>(Socks5::Socks5Status::SOCKS5_DESERIALIZE_ERROR),
        "Socks5 deserialization error"},

    {SOCKET_SERVER_ERROR_CODE_BASE + EINTR, "Interrupted system call"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EIO, "I/O error"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EBADF, "Bad file number"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EAGAIN, "Resource temporarily unavailable. Try again"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EACCES, "System permission denied"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EFAULT, "Bad address"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EINVAL, "Invalid system argument"},
    {SOCKET_SERVER_ERROR_CODE_BASE + ENOTSOCK, "Socket operation on non-socket"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EPROTOTYPE, "Incorrect socket protocol type"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EADDRINUSE, "Address already in use"},
    {SOCKET_SERVER_ERROR_CODE_BASE + EADDRNOTAVAIL, "Cannot assign requested address"},
    {SOCKET_SERVER_ERROR_CODE_BASE + ENOTCONN, "Transport endpoint is not connected"},
    {SOCKET_SERVER_ERROR_CODE_BASE + ETIMEDOUT, "Connection timed out"},

    {TlsSocket::TLS_ERR_SSL_NULL, "SSL is null"},
    {TlsSocket::TLS_ERR_WANT_READ, "An error occurred when reading data on the TLS socket"},
    {TlsSocket::TLS_ERR_WANT_WRITE, "An error occurred when writing data on the TLS socket"},
    {TlsSocket::TLS_ERR_WANT_X509_LOOKUP, "An error occurred when verifying the x509 certificate"},
    {TlsSocket::TLS_ERR_SYSCALL, "An error occurred in the TLS system call"},
    {TlsSocket::TLS_ERR_ZERO_RETURN, "Failed to close the TLS connection"},
    {TlsSocket::TLS_ERR_WANT_CONNECT, "Error occurred in the tls connection"},
    {TlsSocket::TLS_ERR_WANT_ACCEPT, "Error occurred in the tls accept"},
    {TlsSocket::TLS_ERR_WANT_ASYNC, "Error occurred in the tls async"},
    {TlsSocket::TLS_ERR_WANT_ASYNC_JOB, "Error occurred in the tls async work"},
    {TlsSocket::TLS_ERR_WANT_CLIENT_HELLO_CB, "Error occured in client hello"},
    {TlsSocket::TLS_ERR_NO_BIND, "No bind socket"},
    {TlsSocket::TLS_ERR_SOCK_INVALID_FD, "Invalid socket FD"},
    {TlsSocket::TLS_ERR_SOCK_NOT_CONNECT, "Socket is not connected"},
    {TlsSocket::TLS_ERR_SSL_HOSTNAME_VERIFY_FAILED, "SSL server hostname verification failed"},
};

int32_t ConvertSocketClientErrno(int32_t errCode)
{
    if (errCode == UNKNOWN_ERROR || errCode == PERMISSION_DENIED_CODE ||
        errCode == PARAM_ERROR_CODE || errCode == SYSTEM_INTERNAL_ERROR) {
        return errCode;
    }
#if defined(IOS_PLATFORM)
    return SOCKET_ERROR_CODE_BASE + ErrCodePlatformAdapter::GetOHOSErrCode(errCode);
#else
    return SOCKET_ERROR_CODE_BASE + errCode;
#endif
}

int32_t ConvertSocketServerErrno(int32_t errCode)
{
    if (errCode == UNKNOWN_ERROR || errCode == PERMISSION_DENIED_CODE ||
        errCode == PARAM_ERROR_CODE || errCode == SYSTEM_INTERNAL_ERROR) {
        return errCode;
    }
#if defined(IOS_PLATFORM)
    return SOCKET_SERVER_ERROR_CODE_BASE + ErrCodePlatformAdapter::GetOHOSErrCode(errCode);
#else
    return SOCKET_SERVER_ERROR_CODE_BASE + errCode;
#endif
}

std::string GetSocketErrorMessage(int32_t errCode)
{
    auto search = SOCKET_ERROR_MESSAGE_MAP.find(errCode);
    if (search != SOCKET_ERROR_MESSAGE_MAP.end()) {
        return search->second;
    }

    return "Unknown error";
}
} // namespace Socket
} // namespace NetStack
} // namespace OHOS
