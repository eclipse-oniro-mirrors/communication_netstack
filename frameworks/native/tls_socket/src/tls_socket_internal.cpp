/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "tls_socket_internal.h"

#include <thread>
#include <unistd.h>
#include <utility>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <map>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "socket_exec.h"
#include "socket_state_base.h"
#include "tls_context.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"

#include "securec.h"

namespace OHOS {
namespace NetStack {

namespace {
constexpr int REMOTE_CERT_LEN = 8192;
constexpr int PROTOCOL_V1_2 = 0x303;
constexpr int PROTOCOL_V1_3 = 0x304;
constexpr const char *TLS_VERSION_1_1 = "TLSv1.1";
constexpr const char * UNKNOWN_ERROR = "SSL_ERROR_UNKNOWN_";
}
struct ErrorInfo {
    int32_t errorCode;
    const char *errorString;
};
ErrorInfo g_errorInfos[] = {
    { SSL_ERROR_NONE, "SSL_ERROR_NONE" },
    { SSL_ERROR_WANT_READ, "SSL_ERROR_WANT_READ"},
    { SSL_ERROR_WANT_WRITE, "SSL_ERROR_WANT_WRITE"},
    { SSL_ERROR_ZERO_RETURN, "SSL_ERROR_ZERO_RETURN"},
    { SSL_ERROR_WANT_CONNECT, "SSL_ERROR_WANT_CONNECT"},
    { SSL_ERROR_WANT_ACCEPT, "SSL_ERROR_WANT_ACCEPT"},
    { SSL_ERROR_WANT_X509_LOOKUP, "SSL_ERROR_WANT_X509_LOOKUP"},
    { SSL_ERROR_WANT_ASYNC, "SSL_ERROR_WANT_ASYNC"},
    { SSL_ERROR_WANT_ASYNC_JOB, "SSL_ERROR_WANT_ASYNC_JOB"},
    { SSL_ERROR_SSL, "SSL_ERROR_SSL"},
    { SSL_ERROR_SYSCALL, "SSL_ERROR_SYSCALL"}
};

std::string GetErrorString(int32_t errorCode)
{
    for (const auto &p : g_errorInfos) {
        if (p.errorCode == errorCode) {
            return p.errorString;
        }
    }
    return UNKNOWN_ERROR + std::to_string(errorCode);
}

void SetIsBound(SocketStateBase state,
                       sa_family_t family,
                       const sockaddr_in *addr4,
                       const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        state.SetIsBound(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        state.SetIsBound(ntohs(addr6->sin6_port) != 0);
    }
}

void SetIsConnected(SocketStateBase state,
                           sa_family_t family,
                           const sockaddr_in *addr4,
                           const sockaddr_in6 *addr6)
{
    if (family == AF_INET) {
        state.SetIsConnected(ntohs(addr4->sin_port) != 0);
    } else if (family == AF_INET6) {
        state.SetIsConnected(ntohs(addr6->sin6_port) != 0);
    }
}

std::string MakeAddressString(sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        auto *addr4 = reinterpret_cast<sockaddr_in *>(addr);
        const char *str = inet_ntoa(addr4->sin_addr);
        if (str == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    } else if (addr->sa_family == AF_INET6) {
        auto *addr6 = reinterpret_cast<sockaddr_in6 *>(addr);
        char str[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN) == nullptr || strlen(str) == 0) {
            return {};
        }
        return str;
    }
    return {};
}

bool SetBaseOptions(int sock, ExtraOptionsBase *option)
{
    if (option->GetReceiveBufferSize() != 0) {
        int size = (int)option->GetReceiveBufferSize();
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option->GetSendBufferSize() != 0) {
        int size = (int)option->GetSendBufferSize();
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<void *>(&size), sizeof(size)) < 0) {
            return false;
        }
    }

    if (option->IsReuseAddress()) {
        int reuse = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void *>(&reuse), sizeof(reuse)) < 0) {
            return false;
        }
    }

    if (option->GetSocketTimeout() != 0) {
        timeval timeout = {(int)option->GetSocketTimeout(), 0};
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<void *>(&timeout), sizeof(timeout)) < 0) {
            return false;
        }
    }
    return true;
}

int MakeIpSocket(sa_family_t family)
{
    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }
    int sock = socket(family, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        NETSTACK_LOGE("make tcp socket failed errno is %{public}d %{public}s", errno, strerror(errno));
        return -1;
    }
    return sock;
}

bool ExecSocketConnect(const std::string &hostName, int port, sa_family_t family, int socketDescriptor)
{
    struct sockaddr_in dest = {0};
    bzero(&dest, sizeof(dest));
    dest.sin_family = family;
    dest.sin_port = htons(port);
    if (inet_aton(hostName.c_str(), (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        NETSTACK_LOGE("hostName is %s", hostName.c_str());
        return false;
    }
    int connectResult = connect(socketDescriptor, reinterpret_cast<struct sockaddr *>(&dest), sizeof(dest));
    if (connectResult == -1) {
        NETSTACK_LOGE("socket connect error.");
        return false;
    }
    return true;
}

bool TLSSocketInternal::TlsConnectToHost(TlsConnectOptions options)
{
    configuration_.SetPrivateKey(options.GetTlsSecureOptions().GetKey(), options.GetTlsSecureOptions().GetPasswd());
    configuration_.SetCaCertificate(options.GetTlsSecureOptions().GetCa());
    configuration_.SetLocalCertificate(options.GetTlsSecureOptions().GetCert());
    configuration_.SetCipherSuite(options.GetTlsSecureOptions().GetCipherSuite());
    X509_print_fp(stdout, (X509*)configuration_.GetLocalCertificate().handle());
    int result = 0;
    result = MakeIpSocket(address_.GetSaFamily());
    if (!result) {
        return false;
    }
    socketDescriptor_ = result;
    if (!ExecSocketConnect(options.GetAddress().GetAddress(),
                           options.GetAddress().GetPort(),
                           options.GetAddress().GetSaFamily(),
                           socketDescriptor_)) {
        return false;
    }
    return StartTlsConnected();
}

bool TLSSocketInternal::StartTlsConnected()
{
    if (!CreatTlsContext()) {
        return false;
    }
    if (!StartShakingHands()) {
        return false;
    }
    return true;
}

bool TLSSocketInternal::CreatTlsContext()
{
    tlsContextPointer_ = TLSContext::CreateConfiguration(SSL_CLIENT_MODE, configuration_,
                                                         IsRootsOnDemandAllowed());
    if (!tlsContextPointer_) {
        return false;
    }
    if (!(ssl_ = tlsContextPointer_->CreateSsl())) {
        NETSTACK_LOGI("Error creating SSL session");
        return false;
    }
    SSL_set_fd(ssl_, socketDescriptor_);
    SSL_set_connect_state(ssl_);
    return true;
}

bool TLSSocketInternal::StartShakingHands()
{
    int result = SSL_connect(ssl_);
    if (result == -1) {
        if (errorCallback_) {
            errorCallback_(errno, strerror(errno));
        }
        ERR_print_errors_fp(stderr);
        int errorStatus = SSL_get_error(ssl_, result);
        NETSTACK_LOGE("%{public}s", GetErrorString(errorStatus).c_str());
        return false;
    }
    configuration_.SetProtocol(SSL_get_version(ssl_));
    std::string list = SSL_get_cipher_list(ssl_, 0);
    NETSTACK_LOGI("SSL_get_cipher_list: %{public}s", list.c_str());
    configuration_.SetCipherSuite(list);
    if (!SetSharedSigalgs()) {
        NETSTACK_LOGE("TlsSocket::StartShakingHands SetSharedSigalgs is false");
    }
    if (!SetRemoteCertificate()) {
        NETSTACK_LOGE("TlsSocket::StartShakingHands SetRemoteCertificate is false");
    }
    NETSTACK_LOGI("SSL Get Version: %{public}s, SSL Get Cipher: %{public}s",
                  SSL_get_version(ssl_),
                  SSL_get_cipher(ssl_));
    return true;
}

TLSConfiguration TLSSocketInternal::GetTlsConfiguration() const
{
    return configuration_;
}

bool TLSSocketInternal::IsRootsOnDemandAllowed() const
{
    return allowRootCertOnDemandLoading_;
}

void TLSSocketInternal::SetTlsConfiguration(const TLSConfiguration &config)
{
    configuration_.GetPrivateKey() = config.PrivateKey();
    configuration_.GetLocalCertificate() = config.GetLocalCertificate();
    configuration_.GetCaCertificate() = config.GetCaCertificate();
}

bool TLSSocketInternal::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    int len = 0, i = 0;
    for (const auto &str : alpnProtocols) {
        len += str.length();
    }
    auto result = std::make_unique<unsigned char[]>(alpnProtocols.size() + len);
    for (const auto &str : alpnProtocols) {
        len = str.length();
        result[i++] = len;
        strcpy(reinterpret_cast<char *>(&result[i]), (const char *) str.c_str());
        i = i + len;
    }

    NETSTACK_LOGI("%{public}s", result.get());
    if (SSL_set_alpn_protos(ssl_, result.get(), i)) {
        if (errorCallback_) {
            errorCallback_(errno, strerror(errno));
        }
        NETSTACK_LOGE("Failed to set negotiable protocol list");
        return false;
    }
    return true;
}

bool TLSSocketInternal::Send(const std::string &data)
{
    NETSTACK_LOGI("data to send :%{public}s", data.c_str());
    int len = 0;
    len = SSL_write(ssl_, data.c_str(), data.length());
    if (len < 0) {
        if (errorCallback_) {
            errorCallback_(errno, strerror(errno));
        }
        NETSTACK_LOGE("data '%{public}s' send failed!The error code is %{public}d, The error message is'%{public}s'",
                      data.c_str(), errno, strerror(errno));
        return false;
    } else {
        NETSTACK_LOGI("data '%{public}s' Sent successfully,sent in total %{public}d bytes!", data.c_str(), len);
    }
    return true;
}

int TLSSocketInternal::GetRead(char *buffer, int MAX_BUFFER_SIZE)
{
    return SSL_read(ssl_, buffer, MAX_BUFFER_SIZE);
}

void TLSSocketInternal::MakeRemoteInfo(SocketRemoteInfo &remoteInfo)
{
    remoteInfo.SetAddress(hostName_);
    remoteInfo.SetPort(port_);
    remoteInfo.SetFamily(family_);
}

void TLSSocketInternal::Recv()
{
    std::thread thread([this]() {
        int len;
        char buffer[MAX_BUF_LEN + 1];
        bzero(buffer, MAX_BUF_LEN + 1);

        while (1) {
            bzero(buffer, MAX_BUF_LEN + 1);
            len = SSL_read(ssl_, buffer, MAX_BUF_LEN);
            if (len > 0) {
                NETSTACK_LOGD("Receive message successfully:'%{public}s'，total %{public}d bytes of data", buffer, len);
                if (recvCallback_) {
                    SocketRemoteInfo remoteInfo;
                    remoteInfo.SetAddress(hostName_);
                    remoteInfo.SetPort(port_);
                    remoteInfo.SetFamily(family_);
                    recvCallback_(buffer, remoteInfo);
                }
                break;
            } else {
                if (errorCallback_) {
                    errorCallback_(errno, strerror(errno));
                }
            }
        }
    });
    thread.detach();
}

bool TLSSocketInternal::GetRemoteAddress(NetAddress &address) const
{
    sa_family_t family;
    socklen_t len = sizeof(family);
    int ret = getsockname(socketDescriptor_, reinterpret_cast<sockaddr *>(&family), &len);
    if (ret < 0) {
        if (errorCallback_) {
            errorCallback_(errno, strerror(errno));
        }
        NETSTACK_LOGE("Error in getsockname");
        return false;
    }
    if (family == AF_INET) {
        sockaddr_in addr4 = {0};
        socklen_t len4 = sizeof(sockaddr_in);
        ret = getpeername(socketDescriptor_, reinterpret_cast<sockaddr *>(&addr4), &len4);
        if (ret < 0) {
            if (errorCallback_) {
                errorCallback_(errno, strerror(errno));
            }
            NETSTACK_LOGE("Error in getpeername");
            return false;
        }
        std::string addressStr = MakeAddressString(reinterpret_cast<sockaddr *>(&addr4));
        if (addressStr.empty()) {
            NETSTACK_LOGE("Error in MakeAddressString");
            return false;
        }
        address.SetAddress(addressStr);
        address.SetFamilyBySaFamily(family);
        address.SetPort(ntohs(addr4.sin_port));
        return true;
    } else if (family == AF_INET6) {
        sockaddr_in6 addr6 = {0};
        socklen_t len6 = sizeof(sockaddr_in6);
        ret = getpeername(socketDescriptor_, reinterpret_cast<sockaddr *>(&addr6), &len6);
        if (ret < 0) {
            if (errorCallback_) {
                errorCallback_(errno, strerror(errno));
            }
            NETSTACK_LOGE("Error in getpeername");
            return false;
        }
        std::string addressStr = MakeAddressString(reinterpret_cast<sockaddr *>(&addr6));
        if (addressStr.empty()) {
            NETSTACK_LOGE("MakeAddressString is empty");
            return false;
        }
        address.SetAddress(addressStr);
        address.SetFamilyBySaFamily(family);
        address.SetPort(ntohs(addr6.sin6_port));
        return true;
    }
    return false;
}

bool TLSSocketInternal::SetRemoteCertificate()
{
    peerX509_ = SSL_get_peer_certificate(ssl_);
    if (peerX509_ == nullptr) {
        NETSTACK_LOGE("open fail errno = %{public}d reason = %{public}s \n", errno, strerror(errno));
        return false;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    X509_print(bio, peerX509_);
    if (!bio) {
        NETSTACK_LOGE("TlsSocket::SetRemoteCertificate bio is null");
        return false;
    }
    char data[REMOTE_CERT_LEN];
    if (!BIO_read(bio, data, REMOTE_CERT_LEN)) {
        NETSTACK_LOGE("TlsSocket::SetRemoteCertificate BIO_read is error");
        BIO_free(bio);
        return false;
    }
    BIO_free(bio);
    remoteCert_ = std::string(data);
    NETSTACK_LOGI("TlsSocket::SetRemoteCertificate %{public}s", remoteCert_.c_str());
    return true;
}

std::string TLSSocketInternal::GetRemoteCertificate() const
{
    return remoteCert_;
}

std::string TLSSocketInternal::GetCertificate() const
{
    return configuration_.GetCertificate();
}

bool TLSSocketInternal::SetSharedSigalgs()
{
    if (!ssl_) {
        NETSTACK_LOGE("TlsSocket::SetSharedSigalgs ssl_ is null");
        return false;
    }
    int number = SSL_get_shared_sigalgs(ssl_, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!number) {
        NETSTACK_LOGE("TlsSocket::SetSharedSigalgs SSL_get_shared_sigalgs number is 0");
        return false;
    }
    for (int i = 0; i < number; i++) {
        int hash_nid;
        int sign_nid;
        std::string sig_with_md;
        SSL_get_shared_sigalgs(ssl_, i, &sign_nid, &hash_nid, nullptr, nullptr, nullptr);
        switch (sign_nid) {
            case EVP_PKEY_RSA:
                sig_with_md = "RSA+";
                break;
            case EVP_PKEY_RSA_PSS:
                sig_with_md = "RSA-PSS+";
                break;
            case EVP_PKEY_DSA:
                sig_with_md = "DSA+";
                break;
            case EVP_PKEY_EC:
                sig_with_md = "ECDSA+";
                break;
            case NID_ED25519:
                sig_with_md = "Ed25519+";
                break;
            case NID_ED448:
                sig_with_md = "Ed448+";
                break;
            default:
                const char* sn = OBJ_nid2sn(sign_nid);
                if (sn != nullptr) {
                    sig_with_md = std::string(sn) + "+";
                } else {
                    sig_with_md = "UNDEF+";
                }
                break;
        }
        const char* sn_hash = OBJ_nid2sn(hash_nid);
        if (sn_hash != nullptr) {
            sig_with_md += std::string(sn_hash);
        } else {
            sig_with_md += "UNDEF";
        }
        signatureAlgorithms_.push_back(sig_with_md);
    }
    for (auto l : signatureAlgorithms_) {
        NETSTACK_LOGI("signatureAlgorithms_ =%{public}s ", l.c_str());
    }
    return true;
}

std::vector<std::string> TLSSocketInternal::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

bool TLSSocketInternal::GetPasswd()
{
    if (configuration_.GetPrivateKey().GetPasswd().empty()) {
       return false;
    }
    passwd_ = configuration_.GetPrivateKey().GetPasswd();
    NETSTACK_LOGI("--- GetPasswd is %{public}s", passwd_.c_str());
    return true;
}

bool TLSSocketInternal::ExtraOptions(const TCPExtraOptions &options) const
{
    if (!SetBaseOptions(socketDescriptor_, (ExtraOptionsBase *) &options)) {
        NETSTACK_LOGE("Error in SetBaseOptions");
        return false;
    }

    if (options.IsKeepAlive()) {
        int keepalive = 1;
        if (setsockopt(socketDescriptor_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
            if (errorCallback_) {
                errorCallback_(errno, strerror(errno));
            }
            NETSTACK_LOGE("Error in setsockopt KeepAlive");
            return false;
        }
    }

    if (options.IsOOBInline()) {
        int oobInline = 1;
        if (setsockopt(socketDescriptor_, SOL_SOCKET, SO_OOBINLINE, &oobInline, sizeof(oobInline)) < 0) {
            if (errorCallback_) {
                errorCallback_(errno, strerror(errno));
            }
            NETSTACK_LOGE("Error in setsockopt OOBInline");
            return false;
        }
    }

    if (options.IsTCPNoDelay()) {
        int tcpNoDelay = 1;
        if (setsockopt(socketDescriptor_, IPPROTO_TCP, TCP_NODELAY, &tcpNoDelay, sizeof(tcpNoDelay)) < 0) {
            if (errorCallback_) {
                errorCallback_(errno, strerror(errno));
            }
            NETSTACK_LOGE("Error in setsockopt TCPNoDelay");
            return false;
        }
    }

    linger soLinger = {0};
    soLinger.l_onoff = options.socketLinger.IsOn();
    soLinger.l_linger = (int)options.socketLinger.GetLinger();
    if (setsockopt(socketDescriptor_, SOL_SOCKET, SO_LINGER, &soLinger, sizeof(soLinger)) < 0) {
        if (errorCallback_) {
            errorCallback_(errno, strerror(errno));
        }
        NETSTACK_LOGE("Error in setsockopt SO_LINGER");
        return false;
    }
    return true;
}

bool TLSSocketInternal::GetPeerCertificate()
{
    peerX509_ = SSL_get_peer_certificate(ssl_);
    X509_print_fp(stdout, peerX509_);
    BIO *bio = BIO_new(BIO_s_mem());
    X509_print(bio, peerX509_);
    char data[REMOTE_CERT_LEN];
    if (BIO_read(bio, data, REMOTE_CERT_LEN)) {
        NETSTACK_LOGI("wo is PeerCertToString is success ");
    }
    NETSTACK_LOGI("%{public}s", data);
    return true;
}

TLSProtocol TLSSocketInternal::GetProtocol() const
{
    if (!ssl_) {
        return UNKNOW_PROTOCOL;
    }
    const int version = SSL_version(ssl_);
    switch (version) {
        case PROTOCOL_V1_2:
            return TLS_V1_2;
        case PROTOCOL_V1_3:
            return TLS_V1_3;
        default:
            return UNKNOW_PROTOCOL;
    }
}

std::vector<std::string> TLSSocketInternal::GetCipherSuite()
{
    if (!ssl_) {
        return {};
    }
    STACK_OF(SSL_CIPHER)* sk = SSL_get_ciphers(ssl_);
    CipherSuite cipherSuite;
    std::vector<std::string> cipherSuiteVec;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER* c = sk_SSL_CIPHER_value(sk, i);
        cipherSuite.cipherId_ = SSL_CIPHER_get_id(c);
        cipherSuite.cipherName_ = SSL_CIPHER_get_name(c);
        cipherSuiteVec.push_back(cipherSuite.cipherName_);
        NETSTACK_LOGI("SSL_CIPHER_get_id = %{public}lu, SSL_CIPHER_get_name = %{public}s", cipherSuite.cipherId_, cipherSuite.cipherName_.c_str());
    }
    return cipherSuiteVec;
}

bool TLSSocketInternal::Close()
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl in NULL");
        return false;
    }
    int result = SSL_shutdown(ssl_);
    if (result < 0) {
        if (errorCallback_) {
            errorCallback_(errno, strerror(errno));
        }
        NETSTACK_LOGE("Error in shutdown");
        return false;
    }
    SSL_free(ssl_);
    close(socketDescriptor_);
    tlsContextPointer_->CloseCtx();
    return true;
}

std::string TLSSocketInternal::GetProtocol()
{
    if (ssl_) {
        return SSL_get_version(ssl_);
    }
    return TLS_VERSION_1_1;
}

ssl_st *TLSSocketInternal::GetSSL()
{
    return ssl_;
}
} } // namespace OHOS::NetStack
