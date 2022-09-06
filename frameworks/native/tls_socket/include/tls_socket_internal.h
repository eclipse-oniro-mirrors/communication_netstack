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

#ifndef COMMUNICATIONNETSTACK_TLS_SOCKET_INTERNAL_H
#define COMMUNICATIONNETSTACK_TLS_SOCKET_INTERNAL_H

#include <charconv>
#include <functional>
#include <memory>

#include <openssl/ssl.h>

#include "net_address.h"
#include "socket_state_base.h"
#include "tcp_extra_options.h"
#include "socket_remote_info.h"
#include "tls.h"
#include "tls_configuration.h"
#include "tls_context.h"

namespace OHOS {
namespace NetStack {

static constexpr const char *SPLIT = " ";
using RecvCallback = std::function<void(const std::string& data, const SocketRemoteInfo &remoteInfo)>;
using ErrorCallback = std::function<void(int64_t errorNumber, const std::string& errorString)>;

class TLSSocketInternal final {
public:
    TLSSocketInternal() = default;
    ~TLSSocketInternal() = default;

    bool TlsConnectToHost(TlsConnectOptions options);

    void SetTlsConfiguration(const TLSConfiguration &config);
    [[nodiscard]] TLSConfiguration GetTlsConfiguration() const;

    [[nodiscard]] TLSProtocol GetProtocol() const;
    std::vector<std::string> GetCipherSuite();

    [[nodiscard]] bool IsRootsOnDemandAllowed() const;
    bool Send(const std::string &data);
    void Recv();
    bool Close();
    bool SetAlpnProtocols(const std::vector<std::string> &alpnProtocols);
    bool SetSharedSigalgs();
    [[nodiscard]] bool GetState(SocketStateBase &state) const;
    [[nodiscard]] bool ExtraOptions(const TCPExtraOptions &options) const;
    [[nodiscard]] bool GetRemoteAddress(NetAddress &address) const;
    [[nodiscard]] bool Bind(NetAddress &address) const;

    bool SetRemoteCertificate();
    [[nodiscard]] std::string GetRemoteCertificate() const;
    [[nodiscard]] std::string GetCertificate() const;
    bool GetPeerCertificate();
    [[nodiscard]] std::vector<std::string> GetSignatureAlgorithms() const;

    bool GetPasswd();
    std::string GetProtocol();

    int GetRead(char *buffer, int MAX_BUFFER_SIZE);
    void MakeRemoteInfo(SocketRemoteInfo &remoteInfo);

    ssl_st *GetSSL();

private:
    bool StartTlsConnected();
    bool CreatTlsContext();
    bool StartShakingHands();
    bool VerifyPeerCert(stack_st_X509 *caChain, const char* certFile);
private:
    std::shared_ptr<TLSContext> tlsContextPointer_ = nullptr;
private:
    std::string hostName_;
    uint16_t port_ = 0;
    std::vector<std::string> signatureAlgorithms_;
    sa_family_t family_ = 0;
    NetAddress address_;
    struct ssl_st *ssl_ = nullptr;
    X509 *peerX509_ = nullptr;
    std::string remoteCert_;
    std::string passwd_;
    TLSConfiguration configuration_;
    bool allowRootCertOnDemandLoading_ = false;
    int32_t socketDescriptor_ = 0;
    RecvCallback recvCallback_;
    ErrorCallback errorCallback_;
};
} } // namespace OHOS::NetStack
#endif // COMMUNICATIONNETSTACK_TLS_SOCKET_INTERNAL_H
