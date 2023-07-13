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

#include "tls_socket_server.h"

#include <chrono>
#include <memory>
#include <netinet/tcp.h>
#include <numeric>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <regex>
#include <securec.h>
#include <sys/ioctl.h>

#include "base_context.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
namespace {
constexpr int SSL_RET_CODE = 0;

constexpr int BUF_SIZE = 2048;
constexpr int OFFSET = 2;
constexpr int SSL_ERROR_RETURN = -1;
constexpr int COMMON_NAME_BUF_SIZE = 256;
constexpr int LISETEN_COUNT = 516;
constexpr const char *SPLIT_HOST_NAME = ".";
constexpr const char *SPLIT_ALT_NAMES = ",";
constexpr const char *DNS = "DNS:";
constexpr const char *HOST_NAME = "hostname: ";
constexpr const char *IP_ADDRESS = "IP Address:";
constexpr const char *UNKNOW_REASON = "Unknown reason";
constexpr const char *IP = "IP: ";
const std::regex JSON_STRING_PATTERN{R"(/^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/)"};
const std::regex PATTERN{
    "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|"
    "2[0-4][0-9]|[01]?[0-9][0-9]?)"};
int g_userCounter = 0;
bool IsIP(const std::string &ip)
{
    std::regex pattern(PATTERN);
    std::smatch res;
    return regex_match(ip, res, pattern);
}

std::vector<std::string> SplitHostName(std::string &hostName)
{
    transform(hostName.begin(), hostName.end(), hostName.begin(), ::tolower);
    return CommonUtils::Split(hostName, SPLIT_HOST_NAME);
}

bool SeekIntersection(std::vector<std::string> &vecA, std::vector<std::string> &vecB)
{
    std::vector<std::string> result;
    set_intersection(vecA.begin(), vecA.end(), vecB.begin(), vecB.end(), inserter(result, result.begin()));
    return !result.empty();
}
int ConvertErrno()
{
    return TlsSocket::TlsSocketError::TLS_ERR_SYS_BASE + errno;
}

int ConvertSSLError(ssl_st *ssl)
{
    if (!ssl) {
        return TlsSocket::TLS_ERR_SSL_NULL;
    }
    return TlsSocket::TlsSocketError::TLS_ERR_SSL_BASE + SSL_get_error(ssl, SSL_RET_CODE);
}

std::string MakeErrnoString()
{
    return strerror(errno);
}

std::string MakeSSLErrorString(int error)
{
    char err[TlsSocket::MAX_ERR_LEN] = {0};
    ERR_error_string_n(error - TlsSocket::TlsSocketError::TLS_ERR_SYS_BASE, err, sizeof(err));
    return err;
}
std::vector<std::string> SplitEscapedAltNames(std::string &altNames)
{
    std::vector<std::string> result;
    std::string currentToken;
    size_t offset = 0;
    while (offset != altNames.length()) {
        auto nextSep = altNames.find_first_of(", ");
        auto nextQuote = altNames.find_first_of('\"');
        if (nextQuote != std::string::npos && (nextSep != std::string::npos || nextQuote < nextSep)) {
            currentToken += altNames.substr(offset, nextQuote);
            std::regex jsonStringPattern(JSON_STRING_PATTERN);
            std::smatch match;
            std::string altNameSubStr = altNames.substr(nextQuote);
            bool ret = regex_match(altNameSubStr, match, jsonStringPattern);
            if (!ret) {
                return {""};
            }
            currentToken += result[0];
            offset = nextQuote + result[0].length();
        } else if (nextSep != std::string::npos) {
            currentToken += altNames.substr(offset, nextSep);
            result.push_back(currentToken);
            currentToken = "";
            offset = nextSep + OFFSET;
        } else {
            currentToken += altNames.substr(offset);
            offset = altNames.length();
        }
    }
    result.push_back(currentToken);
    return result;
}
} // namespace

void TLSServerSendOptions::SetSocket(const int &socketFd)
{
    socketFd_ = socketFd;
}

void TLSServerSendOptions::SetSendData(const std::string &data)
{
    data_ = data;
}

const int &TLSServerSendOptions::GetSocket() const
{
    return socketFd_;
}

const std::string &TLSServerSendOptions::GetSendData() const
{
    return data_;
}

void TLSSocketServer::Listen(const TlsSocket::TLSConnectOptions &tlsListenOptions, const ListenCallback &callback)
{
    if (!CommonUtils::HasInternetPermission()) {
        CallListenCallback(PERMISSION_DENIED_CODE, callback);
        return;
    }
    NETSTACK_LOGE("Listen 1 %{public}d", listenSocketFd_);
    if (listenSocketFd_ >= 0) {
        CallListenCallback(TlsSocket::TLSSOCKET_SUCCESS, callback);
        return;
    }
    NETSTACK_LOGE("Listen 2 %{public}d", listenSocketFd_);
    if (ExecBind(tlsListenOptions.GetNetAddress(), callback)) {
        NETSTACK_LOGE("Listen 3 %{public}d", listenSocketFd_);
        ExecAccept(tlsListenOptions, callback);
    } else {
        shutdown(listenSocketFd_, SHUT_RDWR);
        close(listenSocketFd_);
        listenSocketFd_ = -1;
    }

    PollThread(tlsListenOptions);
}

bool TLSSocketServer::ExecBind(const Socket::NetAddress &address, const ListenCallback &callback)
{
    MakeIpSocket(address.GetSaFamily());
    if (listenSocketFd_ < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("make tcp socket failed errno is %{public}d %{public}s", errno, MakeErrnoString().c_str());
        CallOnErrorCallback(resErr, MakeErrnoString());
        CallListenCallback(resErr, callback);
        return false;
    }
    sockaddr_in addr4 = {0};
    sockaddr_in6 addr6 = {0};
    sockaddr *addr = nullptr;
    socklen_t len;
    GetAddr(address, &addr4, &addr6, &addr, &len);
    if (addr == nullptr) {
        NETSTACK_LOGE("TLSSocket::Bind Address Is Invalid");
        CallOnErrorCallback(-1, "Address Is Invalid");
        CallListenCallback(ConvertErrno(), callback);
        return false;
    }
    if (bind(listenSocketFd_, addr, len) < 0) {
        if (errno != EADDRINUSE) {
            NETSTACK_LOGE("bind error is %{public}s %{public}d", strerror(errno), errno);
            CallOnErrorCallback(-1, "Address binding failed");
            CallListenCallback(ConvertErrno(), callback);
            return false;
        }
        if (addr->sa_family == AF_INET) {
            NETSTACK_LOGI("distribute a random port");
            addr4.sin_port = 0; /* distribute a random port */
        } else if (addr->sa_family == AF_INET6) {
            NETSTACK_LOGI("distribute a random port");
            addr6.sin6_port = 0; /* distribute a random port */
        }
        if (bind(listenSocketFd_, addr, len) < 0) {
            NETSTACK_LOGE("rebind error is %{public}s %{public}d", strerror(errno), errno);
            CallOnErrorCallback(-1, "Duplicate binding address failed");
            CallListenCallback(ConvertErrno(), callback);
            return false;
        }
        NETSTACK_LOGI("rebind success");
    }
    NETSTACK_LOGI("bind success");
    address_ = address;
    return true;
}

void TLSSocketServer::ExecAccept(const TlsSocket::TLSConnectOptions &tlsAcceptOptions, const ListenCallback &callback)
{
    if (listenSocketFd_ < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("accept error is %{public}s %{public}d", MakeErrnoString().c_str(), errno);
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }
    SetLocalTlsConfiguration(tlsAcceptOptions);
    int ret = 0;

    NETSTACK_LOGE(
        "accept error is listenSocketFd_=  %{public}d LISETEN_COUNT =%{public}d .GetVerifyMode()  = %{public}d ",
        listenSocketFd_, LISETEN_COUNT, tlsAcceptOptions.GetTlsSecureOptions().GetVerifyMode());
    ret = listen(listenSocketFd_, LISETEN_COUNT);
    if (ret < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("tcp server listen error");
        CallOnErrorCallback(resErr, MakeErrnoString());
        callback(resErr);
        return;
    }
    CallListenCallback(TlsSocket::TLSSOCKET_SUCCESS, callback);
}

bool TLSSocketServer::Send(const TLSServerSendOptions &data, const TlsSocket::SendCallback &callback)
{
    int socketFd = data.GetSocket();
    std::string info = data.GetSendData();

    auto connect_iterator = clientIdConnections_.find(socketFd);
    if (connect_iterator == clientIdConnections_.end()) {
        NETSTACK_LOGE("socket = %{public}d The connection has been disconnected", socketFd);
        CallOnErrorCallback(TlsSocket::TLS_ERR_SYS_EINVAL, "The send failed with no corresponding socketFd");
        return false;
    }
    auto connect = connect_iterator->second;
    auto res = connect->Send(info);
    if (!res) {
        int resErr = ConvertSSLError(connect->GetSSL());
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        CallSendCallback(resErr, callback);
        return false;
    }
    CallSendCallback(TlsSocket::TLSSOCKET_SUCCESS, callback);
    return res;
}

void TLSSocketServer::CallSendCallback(int32_t err, TlsSocket::SendCallback callback) {}

void TLSSocketServer::Close(const int socketFd, const TlsSocket::CloseCallback &callback) {}

void TLSSocketServer::Stop(const TlsSocket::CloseCallback &callback) {}

void TLSSocketServer::GetRemoteAddress(const int socketFd, const TlsSocket::GetRemoteAddressCallback &callback) {}

void TLSSocketServer::GetState(const TlsSocket::GetStateCallback &callback) {}

void TLSSocketServer::CallGetStateCallback(int32_t err, const Socket::SocketStateBase &state,
                                           TlsSocket::GetStateCallback callback)
{
}

bool TLSSocketServer::SetExtraOptions(const Socket::TCPExtraOptions &tcpExtraOptions,
                                      const TlsSocket::SetExtraOptionsCallback &callback)
{
    return true;
}

void TLSSocketServer::SetLocalTlsConfiguration(const TlsSocket::TLSConnectOptions &config)
{
    TLSServerConfiguration_.SetPrivateKey(config.GetTlsSecureOptions().GetKey(),
                                          config.GetTlsSecureOptions().GetKeyPass());
    TLSServerConfiguration_.SetLocalCertificate(config.GetTlsSecureOptions().GetCert());
    TLSServerConfiguration_.SetCaCertificate(config.GetTlsSecureOptions().GetCaChain());

    TLSServerConfiguration_.SetVerifyMode(config.GetTlsSecureOptions().GetVerifyMode());
}

void TLSSocketServer::GetCertificate(const TlsSocket::GetCertificateCallback &callback) {}

void TLSSocketServer::GetRemoteCertificate(const int socketFd, const TlsSocket::GetRemoteCertificateCallback &callback)
{
}

void TLSSocketServer::GetProtocol(const TlsSocket::GetProtocolCallback &callback)
{
    if (TLSServerConfiguration_.GetProtocol() == TlsSocket::TLS_V1_3) {
        callback(TlsSocket::TLSSOCKET_SUCCESS, TlsSocket::PROTOCOL_TLS_V13);
    }
    callback(TlsSocket::TLSSOCKET_SUCCESS, TlsSocket::PROTOCOL_TLS_V12);
}

void TLSSocketServer::GetCipherSuite(const int socketFd, const TlsSocket::GetCipherSuiteCallback &callback) {}

void TLSSocketServer::GetSignatureAlgorithms(const int socketFd,
                                             const TlsSocket::GetSignatureAlgorithmsCallback &callback)
{
}

void TLSSocketServer::Connection::OnMessage(const OnMessageCallback &onMessageCallback)
{
    onMessageCallback_ = onMessageCallback;
}

void TLSSocketServer::Connection::OnClose(const OnCloseCallback &onCloseCallback)
{
    onCloseCallback_ = onCloseCallback;
}

void TLSSocketServer::OnConnect(const OnConnectCallback &onConnectCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onConnectCallback_ = onConnectCallback;
}

void TLSSocketServer::OnError(const TlsSocket::OnErrorCallback &onErrorCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    onErrorCallback_ = onErrorCallback;
}

void TLSSocketServer::Connection::OffMessage()
{
    if (onMessageCallback_) {
        onMessageCallback_ = nullptr;
    }
}

void TLSSocketServer::OffConnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (onConnectCallback_) {
        onConnectCallback_ = nullptr;
    }
}

void TLSSocketServer::Connection::OnError(const TlsSocket::OnErrorCallback &onErrorCallback)
{
    onErrorCallback_ = onErrorCallback;
}

void TLSSocketServer::Connection::OffClose()
{
    if (onCloseCallback_) {
        onCloseCallback_ = nullptr;
    }
}

void TLSSocketServer::Connection::OffError()
{
    onErrorCallback_ = nullptr;
}

void TLSSocketServer::Connection::CallOnErrorCallback(int32_t err, const std::string &errString) {}

void TLSSocketServer::OffError() {}

void TLSSocketServer::MakeIpSocket(sa_family_t family) {}

void TLSSocketServer::CallOnErrorCallback(int32_t err, const std::string &errString) {}

void TLSSocketServer::GetAddr(const Socket::NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6,
                              sockaddr **addr, socklen_t *len)
{
}

std::shared_ptr<TLSSocketServer::Connection> TLSSocketServer::GetConnectionByClientID(int clientid)
{
    return nullptr;
}

void TLSSocketServer::CallListenCallback(int32_t err, ListenCallback callback) {}

void TLSSocketServer::Connection::SetAddress(const Socket::NetAddress address)
{
    address_ = address;
}

const TlsSocket::X509CertRawData &TLSSocketServer::Connection::GetRemoteCertRawData() const
{
    return remoteRawData_;
}

bool TLSSocketServer::Connection::TlsAcceptToHost(int sock, const TlsSocket::TLSConnectOptions &options)
{
    SetTlsConfiguration(options);
    std::string cipherSuite = options.GetTlsSecureOptions().GetCipherSuite();
    if (!cipherSuite.empty()) {
        connectionConfiguration_.SetCipherSuite(cipherSuite);
    }
    std::string signatureAlgorithms = options.GetTlsSecureOptions().GetSignatureAlgorithms();
    if (!signatureAlgorithms.empty()) {
        connectionConfiguration_.SetSignatureAlgorithms(signatureAlgorithms);
    }
    const auto protocolVec = options.GetTlsSecureOptions().GetProtocolChain();
    if (!protocolVec.empty()) {
        connectionConfiguration_.SetProtocol(protocolVec);
    }

    connectionConfiguration_.SetVerifyMode(options.GetTlsSecureOptions().GetVerifyMode());
    NETSTACK_LOGI("TLSSocketServer::Connection::TlsAcceptToHost  connectionConfiguration_GetVerifyMode() :%{public}d",
                  connectionConfiguration_.GetVerifyMode());
    socketFd_ = sock;
    return StartTlsAccept(options);
}

void TLSSocketServer::Connection::SetTlsConfiguration(const TlsSocket::TLSConnectOptions &config) {}

bool TLSSocketServer::Connection::Send(const std::string &data)
{
    return true;
}

int TLSSocketServer::Connection::Recv(char *buffer, int maxBufferSize)
{
    return 0;
}

bool TLSSocketServer::Connection::Close()
{
    return true;
}

bool TLSSocketServer::Connection::SetAlpnProtocols(const std::vector<std::string> &alpnProtocols)
{
    return true;
}

void TLSSocketServer::Connection::MakeRemoteInfo(Socket::SocketRemoteInfo &remoteInfo) {}

TlsSocket::TLSConfiguration TLSSocketServer::Connection::GetTlsConfiguration() const
{
    return connectionConfiguration_;
}

std::vector<std::string> TLSSocketServer::Connection::GetCipherSuite() const
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl in null");
        return {};
    }
    STACK_OF(SSL_CIPHER) *sk = SSL_get_ciphers(ssl_);
    if (!sk) {
        NETSTACK_LOGE("get ciphers failed");
        return {};
    }
    TlsSocket::CipherSuite cipherSuite;
    std::vector<std::string> cipherSuiteVec;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
        cipherSuite.cipherName_ = SSL_CIPHER_get_name(c);
        cipherSuiteVec.push_back(cipherSuite.cipherName_);
    }
    return cipherSuiteVec;
}

std::string TLSSocketServer::Connection::GetRemoteCertificate() const
{
    return remoteCert_;
}

const TlsSocket::X509CertRawData &TLSSocketServer::Connection::GetCertificate() const
{
    return connectionConfiguration_.GetCertificate();
}

std::vector<std::string> TLSSocketServer::Connection::GetSignatureAlgorithms() const
{
    return signatureAlgorithms_;
}

std::string TLSSocketServer::Connection::GetProtocol() const
{
    return TlsSocket::PROTOCOL_TLS_V12;
}

bool TLSSocketServer::Connection::SetSharedSigals()
{
    return true;
}

ssl_st *TLSSocketServer::Connection::GetSSL() const
{
    return ssl_;
}

Socket::NetAddress TLSSocketServer::Connection::GetAddress() const
{
    return address_;
}

int TLSSocketServer::Connection::GetSocketFd() const
{
    return socketFd_;
}

std::shared_ptr<EventManager> TLSSocketServer::Connection::GetEventManager() const
{
    return eventManager_;
}

void TLSSocketServer::Connection::SetEventManager(std::shared_ptr<EventManager> eventManager)
{
    eventManager_ = eventManager;
}

void TLSSocketServer::Connection::SetClientID(int32_t clientID)
{
    clientID_ = clientID;
}

int TLSSocketServer::Connection::GetClientID()
{
    return clientID_;
}

bool TLSSocketServer::Connection::StartTlsAccept(const TlsSocket::TLSConnectOptions &options)
{
    if (!CreatTlsContext()) {
        NETSTACK_LOGE("failed to create tls context");
        return false;
    }
    if (!StartShakingHands(options)) {
        NETSTACK_LOGE("failed to shaking hands");
        return false;
    }
    return true;
}

bool TLSSocketServer::Connection::CreatTlsContext()
{
    tlsContextServerPointer_ = TlsSocket::TLSContextServer::CreateConfiguration(connectionConfiguration_);
    if (!tlsContextServerPointer_) {
        NETSTACK_LOGE("failed to create tls context pointer");
        return false;
    }
    if (!(ssl_ = tlsContextServerPointer_->CreateSsl())) {
        NETSTACK_LOGE("failed to create ssl session");
        return false;
    }
    SSL_set_fd(ssl_, socketFd_);
    SSL_set_accept_state(ssl_);
    return true;
}

bool TLSSocketServer::Connection::StartShakingHands(const TlsSocket::TLSConnectOptions &options)
{
    if (!ssl_) {
        NETSTACK_LOGE("ssl is null");
        return false;
    }
    int result = SSL_accept(ssl_);
    if (result == -1) {
        int errorStatus = ConvertSSLError(ssl_);
        NETSTACK_LOGE("SSL connect is error, errno is %{public}d, error info is %{public}s", errorStatus,
                      MakeSSLErrorString(errorStatus).c_str());
        return false;
    }
    std::string list = SSL_get_cipher_list(ssl_, 0);
    NETSTACK_LOGI("SSL_get_cipher_list: %{public}s", list.c_str());
    connectionConfiguration_.SetCipherSuite(list);
    if (!SetSharedSigals()) {
        NETSTACK_LOGE("Failed to set sharedSigalgs");
    }

    if (!GetRemoteCertificateFromPeer()) {
        NETSTACK_LOGE("Failed to get remote certificate");
    }
    if (peerX509_ != nullptr) {
        NETSTACK_LOGE("peer x509Certificates is null");

        if (!SetRemoteCertRawData()) {
            NETSTACK_LOGE("Failed to set remote x509 certificata Serialization data");
        }
        TlsSocket::CheckServerIdentity checkServerIdentity = options.GetCheckServerIdentity();
        if (!checkServerIdentity) {
            CheckServerIdentityLegal(hostName_, peerX509_);
        } else {
            checkServerIdentity(hostName_, {remoteCert_});
        }
    }
    return true;
}

bool TLSSocketServer::Connection::GetRemoteCertificateFromPeer()
{
    return true;
}

bool TLSSocketServer::Connection::SetRemoteCertRawData()
{
    if (peerX509_ == nullptr) {
        NETSTACK_LOGE("peerX509 is null");
        return false;
    }
    int32_t length = i2d_X509(peerX509_, nullptr);
    if (length <= 0) {
        NETSTACK_LOGE("Failed to convert peerX509 to der format");
        return false;
    }
    unsigned char *der = nullptr;
    (void)i2d_X509(peerX509_, &der);
    TlsSocket::SecureData data(der, length);
    remoteRawData_.data = data;
    OPENSSL_free(der);
    remoteRawData_.encodingFormat = TlsSocket::EncodingFormat::DER;
    return true;
}

static bool StartsWith(const std::string &s, const std::string &prefix)
{
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}
void CheckIpAndDnsName(const std::string &hostName, std::vector<std::string> dnsNames, std::vector<std::string> ips,
                       const X509 *x509Certificates, std::tuple<bool, std::string> &result)
{
    bool valid = false;
    std::string reason = UNKNOW_REASON;
    int index = X509_get_ext_by_NID(x509Certificates, NID_commonName, -1);
    if (IsIP(hostName)) {
        auto it = find(ips.begin(), ips.end(), hostName);
        if (it == ips.end()) {
            reason = IP + hostName + " is not in the cert's list";
        }
        result = {valid, reason};
        return;
    }
    std::string tempHostName = "" + hostName;
    std::string tempMsg = "";
    if (!dnsNames.empty() || index > 0) {
        std::vector<std::string> hostParts = SplitHostName(tempHostName);
        if (!dnsNames.empty()) {
            valid = SeekIntersection(hostParts, dnsNames);
            tempMsg = ". is not in the cert's altnames";
        } else {
            char commonNameBuf[COMMON_NAME_BUF_SIZE] = {0};
            X509_NAME *pSubName = nullptr;
            int len = X509_NAME_get_text_by_NID(pSubName, NID_commonName, commonNameBuf, COMMON_NAME_BUF_SIZE);
            if (len > 0) {
                std::vector<std::string> commonNameVec;
                commonNameVec.emplace_back(commonNameBuf);
                valid = SeekIntersection(hostParts, commonNameVec);
                tempMsg = ". is not cert's CN";
            }
        }
        if (!valid) {
            reason = HOST_NAME + tempHostName + tempMsg;
        }

        result = {valid, reason};
        return;
    }
    reason = "Cert does not contain a DNS name";
    result = {valid, reason};
}

std::string TLSSocketServer::Connection::CheckServerIdentityLegal(const std::string &hostName,
                                                                  const X509 *x509Certificates)
{
    std::string hostname = hostName;
    X509_NAME *subjectName = X509_get_subject_name(x509Certificates);
    if (!subjectName) {
        return "subject name is null";
    }
    char subNameBuf[BUF_SIZE] = {0};
    X509_NAME_oneline(subjectName, subNameBuf, BUF_SIZE);
    int index = X509_get_ext_by_NID(x509Certificates, NID_subject_alt_name, -1);
    if (index < 0) {
        return "X509 get ext nid error";
    }
    X509_EXTENSION *ext = X509_get_ext(x509Certificates, index);
    if (ext == nullptr) {
        return "X509 get ext error";
    }
    ASN1_OBJECT *obj = nullptr;
    obj = X509_EXTENSION_get_object(ext);
    char subAltNameBuf[BUF_SIZE] = {0};
    OBJ_obj2txt(subAltNameBuf, BUF_SIZE, obj, 0);
    NETSTACK_LOGD("extions obj : %{public}s\n", subAltNameBuf);

    return CheckServerIdentityLegal(hostName, ext, x509Certificates);
}

std::string TLSSocketServer::Connection::CheckServerIdentityLegal(const std::string &hostName, X509_EXTENSION *ext,
                                                                  const X509 *x509Certificates)
{
    ASN1_OCTET_STRING *extData = X509_EXTENSION_get_data(ext);
    std::string altNames = reinterpret_cast<char *>(extData->data);
    std::string hostname = "" + hostName;
    BIO *bio = BIO_new(BIO_s_file());
    if (!bio) {
        return "bio is null";
    }
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    ASN1_STRING_print(bio, extData);
    std::vector<std::string> dnsNames = {};
    std::vector<std::string> ips = {};
    constexpr int DNS_NAME_IDX = 4;
    constexpr int IP_NAME_IDX = 11;
    if (!altNames.empty()) {
        std::vector<std::string> splitAltNames;
        if (altNames.find('\"') != std::string::npos) {
            splitAltNames = SplitEscapedAltNames(altNames);
        } else {
            splitAltNames = CommonUtils::Split(altNames, SPLIT_ALT_NAMES);
        }
        for (auto const &iter : splitAltNames) {
            if (StartsWith(iter, DNS)) {
                dnsNames.push_back(iter.substr(DNS_NAME_IDX));
            } else if (StartsWith(iter, IP_ADDRESS)) {
                ips.push_back(iter.substr(IP_NAME_IDX));
            }
        }
    }
    std::tuple<bool, std::string> result;
    CheckIpAndDnsName(hostName, dnsNames, ips, x509Certificates, result);
    if (!std::get<0>(result)) {
        return "Hostname/IP does not match certificate's altnames: " + std::get<1>(result);
    }
    return HOST_NAME + hostname + ". is cert's CN";
}

void TLSSocketServer::RemoveConnect(int socketFd)
{
    std::lock_guard<std::mutex> its_lock(connectMutex_);
    for (auto it = connections_.begin(); it != connections_.end();) {
        if (it->first == socketFd) {
            it->second->CallOnCloseCallback(socketFd);
            it->second->Close();
            it = connections_.erase(it);
            break;
        } else {
            ++it;
        }
    }

    for (auto it = clientIdConnections_.begin(); it != clientIdConnections_.end();) {
        if (it->second->GetSocketFd() == socketFd) {
            it = clientIdConnections_.erase(it);
            break;
        } else {
            ++it;
        }
    }
}
int TLSSocketServer::RecvRemoteInfo(int socketFd, int index)
{
    {
        std::lock_guard<std::mutex> its_lock(connectMutex_);
        for (auto it = connections_.begin(); it != connections_.end();) {
            if (it->first == socketFd) {
                char buffer[MAX_BUFFER_SIZE];
                if (memset_s(buffer, MAX_BUFFER_SIZE, 0, MAX_BUFFER_SIZE) != EOK) {
                    NETSTACK_LOGE("memcpy_s failed!");
                    break;
                }
                int len = it->second->Recv(buffer, MAX_BUFFER_SIZE);
                NETSTACK_LOGE("revc message is size is  %{public}d  buffer is   %{public}s ", len, buffer);
                if (len > 0) {
                    Socket::SocketRemoteInfo remoteInfo;
                    remoteInfo.SetSize(strlen(buffer));
                    it->second->MakeRemoteInfo(remoteInfo);
                    it->second->CallOnMessageCallback(socketFd, buffer, remoteInfo);
                    return len;
                }
                break;
            } else {
                ++it;
            }
        }
    }
    RemoveConnect(socketFd);
    DropFdFromPollList(index);
    return -1;
}
void TLSSocketServer::Connection::CallOnMessageCallback(int32_t socketFd, const std::string &data,
                                                        const Socket::SocketRemoteInfo &remoteInfo)
{
}
void TLSSocketServer::AddConnect(int socketFd, std::shared_ptr<Connection> connection)
{
    std::lock_guard<std::mutex> its_lock(connectMutex_);
    connections_[socketFd] = connection;
    clientIdConnections_[connection->GetClientID()] = connection;
}
void TLSSocketServer::Connection::CallOnCloseCallback(const int32_t socketFd) {}
void TLSSocketServer::CallOnConnectCallback(const int32_t socketFd, std::shared_ptr<EventManager> eventManager) {}
void TLSSocketServer::ProcessTcpAccept(const TlsSocket::TLSConnectOptions &tlsListenOptions, int clientID)
{
    struct sockaddr_in clientAddress;
    socklen_t clientAddrLength = sizeof(clientAddress);
    int connectFD = accept(listenSocketFd_, (struct sockaddr *)&clientAddress, &clientAddrLength);
    if (connectFD < 0) {
        int resErr = ConvertErrno();
        NETSTACK_LOGE("Server accept new client ERROR");
        CallOnErrorCallback(resErr, MakeErrnoString());
        return;
    }
    NETSTACK_LOGI("Server accept new client SUCCESS");
    std::shared_ptr<Connection> connection = std::make_shared<Connection>();
    Socket::NetAddress netAddress;
    char clientIp[INET_ADDRSTRLEN];
    inet_ntop(address_.GetSaFamily(), &clientAddress.sin_addr, clientIp, INET_ADDRSTRLEN);
    int clientPort = ntohs(clientAddress.sin_port);
    netAddress.SetAddress(clientIp);
    netAddress.SetPort(clientPort);
    netAddress.SetFamilyBySaFamily(address_.GetSaFamily());
    connection->SetAddress(netAddress);
    connection->SetClientID(clientID);

    auto res = connection->TlsAcceptToHost(connectFD, tlsListenOptions);
    if (!res) {
        int resErr = ConvertSSLError(connection->GetSSL());
        CallOnErrorCallback(resErr, MakeSSLErrorString(resErr));
        return;
    }
    if (g_userCounter >= USER_LIMIT) {
        const std::string info = "Too many users!";
        connection->Send(info);
        connection->Close();
        NETSTACK_LOGE("Too many users");
        close(connectFD);
        CallOnErrorCallback(-1, "Too many users");
        return;
    }
    g_userCounter++;
    fds_[g_userCounter].fd = connectFD;
    fds_[g_userCounter].events = POLLIN | POLLRDHUP | POLLERR;
    fds_[g_userCounter].revents = 0;
    AddConnect(connectFD, connection);
    auto ptrEventManager = std::make_shared<EventManager>();

    ptrEventManager->SetData(this);
    CallOnConnectCallback(clientID, ptrEventManager);
    connection->SetEventManager(ptrEventManager);
    NETSTACK_LOGI("New client come in, fd is %{public}d", connectFD);
}

void TLSSocketServer::InitPollList(int &listendFd)
{
    for (int i = 1; i <= USER_LIMIT; ++i) {
        fds_[i].fd = -1;
        fds_[i].events = 0;
    }
    fds_[0].fd = listendFd;
    fds_[0].events = POLLIN | POLLERR;
    fds_[0].revents = 0;
}

void TLSSocketServer::DropFdFromPollList(int &fd_index)
{
    fds_[fd_index].fd = fds_[g_userCounter].fd;

    fds_[g_userCounter].fd = -1;
    fds_[g_userCounter].events = 0;
    fd_index--;
    g_userCounter--;
}

void TLSSocketServer::PollThread(const TlsSocket::TLSConnectOptions &tlsListenOptions)
{
    int on = 1;
    ioctl(listenSocketFd_, FIONBIO, (void *)&on);
    std::thread thread_([this, &tlsListenOptions]() {
        InitPollList(listenSocketFd_);
        int clientId = 0;
        while (1) {
            int ret = poll(fds_, g_userCounter + 1, 2000);
            if (ret < 0) {
                int resErr = ConvertErrno();
                NETSTACK_LOGE("Poll ERROR");
                CallOnErrorCallback(resErr, MakeErrnoString());
                break;
            }
            if (ret == 0) {
                continue;
            }
            for (int i = 0; i < g_userCounter + 1; ++i) {
                if ((fds_[i].fd == listenSocketFd_) && (fds_[i].revents & POLLIN)) {
                    ProcessTcpAccept(tlsListenOptions, ++clientId);
                } else if ((fds_[i].revents & POLLRDHUP) || (fds_[i].revents & POLLERR)) {
                    RemoveConnect(fds_[i].fd);
                    DropFdFromPollList(i);
                    NETSTACK_LOGI("A client left");
                } else if (fds_[i].revents & POLLIN) {
                    auto res = RecvRemoteInfo(fds_[i].fd, i);
                }
            }
        }
    });
    thread_.detach();
}
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
