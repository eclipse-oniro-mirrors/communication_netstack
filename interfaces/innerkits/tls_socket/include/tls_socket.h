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

#ifndef COMMUNICATIONNETSTACK_TLS_SOCEKT_H
#define COMMUNICATIONNETSTACK_TLS_SOCEKT_H

#include <any>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <map>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

#include "extra_options_base.h"
#include "net_address.h"
#include "socket_remote_info.h"
#include "socket_state_base.h"
#include "tcp_connect_options.h"
#include "tcp_extra_options.h"
#include "tcp_send_options.h"

#include "tls_key.h"
#include "tls_certificate.h"
#include "tls_configuration.h"
#include "tls_context.h"
#include "tls_socket_internal.h"

namespace OHOS {
namespace NetStack {

using BindCallback = std::function<void(bool ok)>;
using ConnectCallback = std::function<void(bool ok)>;
using SendCallback = std::function<void(bool ok)>;
using CloseCallback = std::function<void(bool ok)>;
using GetRemoteAddressCallback = std::function<void(bool ok, const NetAddress &address)>;
using GetStateCallback = std::function<void(bool ok, const SocketStateBase &state)>;
using SetExtraOptionsCallback = std::function<void(bool ok)>;
using GetCertificateCallback = std::function<void(bool ok, const std::string &cert)>;
using GetRemoteCertificateCallback = std::function<void(bool ok, const std::string &cert)>;
using GetProtocolCallback = std::function<void(bool ok, const std::string &protocol)>;
using GetCipherSuiteCallback = std::function<void(bool ok, const std::vector<std::string> &suite)>;
using GetSignatureAlgorithmsCallback = std::function<void(bool ok, const std::vector<std::string> &algorithms)>;

using OnMessageCallback = std::function<void(const std::string &data, const SocketRemoteInfo &remoteInfo)>;
using OnConnectCallback = std::function<void(void)>;
using OnCloseCallback = std::function<void(void)>;
using OnErrorCallback = std::function<void(int32_t errorNumber, const std::string &errorString)>;

using CheckServerIdentity =
        std::function<std::tuple<int32_t, std::string>(const std::string &hostName,
                                                       const std::vector<std::string> &x509Certificates)>;

static constexpr const char *PROTOCOL_TLS_V12 = "TLSv1.2";
static constexpr const char *PROTOCOL_TLS_V13 = "TLSv1.3";

static constexpr const char *ALPN_PROTOCOLS_HTTP_1_1 = "http1.1";
static constexpr const char *ALPN_PROTOCOLS_HTTP_2 = "h2";

/**
* TODO:
*/
class TLSSecureOptions {
public:
    TLSSecureOptions() = default;
    ~TLSSecureOptions() = default;

    TLSSecureOptions& operator=(const TLSSecureOptions &tlsSecureOptions);
    /**
     * set root CA Chain to verify the server cert
     * @param caChain root certificate chain to verify the server
     */
    void SetCaChain(const std::vector<std::string> &caChain);

    /**
     * set cert chain to send to server/client for check
     * @param certChain cert chain to send to server/client for check
     */
    void SetCert(const std::string &cert);

    /**
     * set key chain to decrypt server data
     * @param keyChain key chain to decrypt server data
     */
    void SetKey(const std::string &key);

    /**
     * set cert password
     * @param passwd creating cert used password
     */
    void SetPassWd(const std::string &passwd);

    /**
     * set protocol Chain to encryption data
     * @param protocolChain protocol Chain to encryption data
     */
    void SetProtocolChain(const std::vector<std::string> &protocolChain);

    /**
     * set flag use Remote Cipher Prefer
     * @param useRemoteCipherPrefer is use Remote Cipher Prefer
     */
    void SetUseRemoteCipherPrefer(bool useRemoteCipherPrefer);

    /**
     * set signature Algorithms for encryption/decrypt data
     * @param signatureAlgorithms signature Algorithms e.g: rsa
     */
    void SetSignatureAlgorithms(const std::string &signatureAlgorithms);

    /**
     * set cipher Suite
     * @param cipherSuite cipher Suite
     */
    void SetCipherSuite(const std::string &cipherSuite);

    /**
     * set crl chain for to creat cert chain
     * @param crlChain crl chain for to creat cert chain TODO::
     */
    void SetCrlChain(const std::vector<std::string> &crlChain);

    /**
     * get root CA Chain to verify the server cert
     * @return root CA Chain to verify the server cert
     */
    [[nodiscard]] const std::vector<std::string>& GetCaChain() const;

    /**
     * get cert chain to send to server/client for check
     * @return cert chain to send to server/client for check
     */
    [[nodiscard]] const std::string& GetCert() const;

    /**
     * get key chain to decrypt server data
     * @return key chain to decrypt server data
     */
    [[nodiscard]] const std::string& GetKey() const;

    /**
     * get cert creat used password
     * @return password
     */
    [[nodiscard]] const std::string& GetPasswd() const;

    /**
     * get protocol Chain to encryption data
     * @return protocol Chain to encryption data
     */
    [[nodiscard]] const std::vector<std::string>& GetProtocolChain() const;

    /**
     * get flag use Remote Cipher Prefer
     * @return is use Remote Cipher Prefer
     */
    [[nodiscard]] bool UseRemoteCipherPrefer() const;

    /**
     * get signature Algorithms for encryption/decrypt data
     * @return signature Algorithms for encryption/decrypt data
     */
    [[nodiscard]] const std::string& GetSignatureAlgorithms() const;

    /**
     * get cipher suite
     * @return cipher suite
     */
    [[nodiscard]] const std::string& GetCipherSuite() const;

    /**
     * get crl chain for to creat cert chain
     * @return crl chain for to creat cert chain
     */
    [[nodiscard]] const std::vector<std::string>& GetCrlChain() const;

private:
    std::vector<std::string> caChain_;
    std::string cert_;
    std::string key_;
    std::string passwd_;
    std::vector<std::string> protocolChain_;
    bool useRemoteCipherPrefer_ = false;
    std::string signatureAlgorithms_;
    std::string cipherSuite_;
    std::vector<std::string> crlChain_;
};

/**
 * tls connect options
 */
class TLSConnectOptions {
public:
    /**
     * Set Net Socket Address
     * @param address socket address
     */
    void SetNetAddress(const NetAddress &address);

    /**
     * Set Tls Secure Options
     * @param tlsSecureOptions class TLSSecureOptions
     */
    void SetTlsSecureOptions(TLSSecureOptions &tlsSecureOptions);

    /**
     * Check Server Identity
     * @param checkServerIdentity TODO::
     */
    void SetCheckServerIdentity(const CheckServerIdentity &checkServerIdentity);

    /**
     * Set Alpn Protocols
     * @param alpnProtocols alpn Protocols
     */
    void SetAlpnProtocols(const std::vector<std::string> &alpnProtocols);

    /**
     * Get Net Socket Address
     * @return net socket address
     */
    [[nodiscard]] NetAddress GetNetAddress() const;

    /**
     * Get TLS Secure Options
     * @return tls secure options
     */
    [[nodiscard]] TLSSecureOptions GetTlsSecureOptions() const;

    /**
     * Check Server Indentity
     * @return Server Indentity
     */
    [[nodiscard]] CheckServerIdentity GetCheckServerIdentity() const;

    /**
     * Get Alpn Protocols
     * @return alpn protocols
     */
    [[nodiscard]] const std::vector<std::string>& GetAlpnProtocols() const;

private:
    NetAddress address_;
    TLSSecureOptions tlsSecureOptions_;
    CheckServerIdentity checkServerIdentity_;
    std::vector<std::string> alpnProtocols_;
};

/**
 * TLS socket interface class
 */
class TLSSocket {
public:
    TLSSocket(const TLSSocket &) = delete;
    TLSSocket(TLSSocket &&) = delete;

    TLSSocket &operator=(const TLSSocket &) = delete;
    TLSSocket &operator=(TLSSocket &&) = delete;

    TLSSocket() = default;
    ~TLSSocket();

    /**
     * Establish Bind Monitor
     * @param address Ip address
     * @param callback callback
     */
    void Bind(const NetAddress &address, const BindCallback &callback);

    /**
     * Establish connection
     * @param tlsConnectOptions tls connect options
     * @param callback callback
     */
    void Connect(TLSConnectOptions &tlsConnectOptions, const ConnectCallback &callback);

    /**
     * Send Data
     * @param tcpSendOptions tcp send options
     * @param callback callback
     */
    void Send(const TCPSendOptions &tcpSendOptions, const SendCallback &callback);

    /**
     * Close
     * @param callback callback
     */
    void Close(const CloseCallback &callback);

    /**
     * Get Remote Address
     * @param callback callback
     */
    void GetRemoteAddress(const GetRemoteAddressCallback &callback);

    /**
     * Get Tls State
     * @param callback callback state data
     */
    void GetState(const GetStateCallback &callback);

    /**
     * Set Extra Options
     * @param tcpExtraOptions tcp extra options
     * @param callback callback extra options
     */
    void SetExtraOptions(const TCPExtraOptions &tcpExtraOptions, const SetExtraOptionsCallback &callback);

    /**
     * Get Certificate
     * @param callback callback certificate
     */
    void GetCertificate(const GetCertificateCallback &callback);

    /**
     * Get Remote Certificate
     * @param needChain need chain
     * @param callback callback get remote certificate
     */
    void GetRemoteCertificate(const GetRemoteCertificateCallback &callback);

    /**
     * Get Protocol
     * @param callback callback protocol
     */
    void GetProtocol(const GetProtocolCallback &callback);

    /**
     * Get Cipher Suite
     * @param callback callback cipher suite
     */
    void GetCipherSuite(const GetCipherSuiteCallback &callback);

    /**
     * Get Signature Algorithms
     * @param callback callback signature algorithms
     */
    void GetSignatureAlgorithms(const GetSignatureAlgorithmsCallback &callback);

    /**
     * On Message
     * @param onMessageCallback callback on message
     */
    void OnMessage(const OnMessageCallback &onMessageCallback);

    /**
     * On Connect
     * @param onConnectCallback callback on connect
     */
    void OnConnect(const OnConnectCallback &onConnectCallback);

    /**
     * On Close
     * @param onCloseCallback callback on close
     */
    void OnClose(const OnCloseCallback &onCloseCallback);

    /**
     * On Error
     * @param onErrorCallback callback on error
     */
    void OnError(const OnErrorCallback &onErrorCallback);

    /**
     * On Error
     * @param onErrorCallback callback on error
     */
    void OffMessage();

    /**
     * Off Connect
     */
    void OffConnect();

    /**
     * Off Close
     */
    void OffClose();

    /**
     * Off Error
     */
    void OffError();

private:
    class OpenSSLContext {
    public:
        TLSContext tlsContext_;
        TLSConfiguration tlsConfiguration_;
        TLSCertificate tlsCertificate_;
        TLSKey tlsKey_;
        TLSSocketInternal tlsSocketInternal_;
    };
    OpenSSLContext openSslContext_;
    static std::string MakeErrnoString();

    static std::string MakeAddressString(sockaddr *addr);

    static void
        GetAddr(const NetAddress &address, sockaddr_in *addr4, sockaddr_in6 *addr6, sockaddr **addr, socklen_t *len);

    void CallOnMessageCallback(const std::string &data, const SocketRemoteInfo &remoteInfo);
    void CallOnConnectCallback();
    void CallOnCloseCallback();
    void CallOnErrorCallback(int32_t err, const std::string &errString);

    void CallBindCallback(bool ok, const BindCallback &callback);
    void CallConnectCallback(bool ok, const ConnectCallback &callback);
    void CallSendCallback(bool ok, const SendCallback &callback);
    void CallCloseCallback(bool ok, const CloseCallback &callback);
    void CallGetRemoteAddressCallback(bool ok, const NetAddress &address, const GetRemoteAddressCallback &callback);
    void CallGetStateCallback(bool ok, const SocketStateBase &state, const GetStateCallback &callback);
    void CallSetExtraOptionsCallback(bool ok, const SetExtraOptionsCallback &callback);
    void CallGetCertificateCallback(bool ok, const std::string &cert);
    void CallGetRemoteCertificateCallback(bool ok, const std::string &cert);
    void CallGetProtocolCallback(bool ok, const std::string &protocol);
    void CallGetCipherSuiteCallback(bool ok, const std::vector<std::string> &suite);
    void CallGetSignatureAlgorithmsCallback(bool ok, const std::vector<std::string>& algorithms);

    void StartReadMessage();

    void GetIp4RemoteAddress(const GetRemoteAddressCallback &callback);
    void GetIp6RemoteAddress(const GetRemoteAddressCallback &callback);

    [[nodiscard]] bool SetBaseOptions(const ExtraOptionsBase &option) const;
    [[nodiscard]] bool SetExtraOptions(const TCPExtraOptions &option) const;

    void MakeTcpSocket(sa_family_t family);

    static constexpr const size_t MAX_ERROR_LEN = 128;
    static constexpr const size_t MAX_BUFFER_SIZE = 8192;

    OnMessageCallback onMessageCallback_;
    OnConnectCallback onConnectCallback_;
    OnCloseCallback onCloseCallback_;
    OnErrorCallback onErrorCallback_;

    BindCallback bindCallback_;
    ConnectCallback connectCallback_;
    SendCallback sendCallback_;
    CloseCallback closeCallback_;
    GetRemoteAddressCallback getRemoteAddressCallback_;
    GetStateCallback getStateCallback_;
    SetExtraOptionsCallback setExtraOptionsCallback_;
    GetCertificateCallback getCertificateCallback_;
    GetRemoteCertificateCallback getRemoteCertificateCallback_;
    GetProtocolCallback getProtocolCallback_;
    GetCipherSuiteCallback getCipherSuiteCallback_;
    GetSignatureAlgorithmsCallback getSignatureAlgorithmsCallback_;

    std::mutex mutex_;
    bool isRunning_ = false;
    bool isRunOver_ = true;

    int sockFd_ = -1;
};
} } // namespace OHOS::NetStack

#endif // COMMUNICATIONNETSTACK_TLS_SOCEKT_H
