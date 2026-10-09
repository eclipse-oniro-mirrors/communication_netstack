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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_TASK_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_TASK_H

#include <atomic>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <string>

#include "http_client_error.h"
#include "http_client_request.h"
#include "http_client_response.h"
#include "http_client_tls_config.h"
#if HAS_NETMANAGER_BASE
#include "netstack_network_profiler.h"
#endif
#ifdef HTTP_HANDOVER_FEATURE
struct HttpHandoverInfo;
#endif
#if ENABLE_HTTP_GLOBAL_INTERCEPT
#include "http_interceptor_mgr.h"
#endif
#include "refbase.h"
struct cJSON;
namespace OHOS {
namespace NetManagerStandard {
    class NetHandle;
}
namespace NetStack {
namespace RequestTracer {
    class Trace;
}
namespace HttpClient {
enum TaskStatus {
    IDLE,
    RUNNING,
};

enum TaskType {
    DEFAULT,
    UPLOAD,
};

/**
 * Curl share handle for sharing cookies between requests with auto cookie enabled.
 * Mirrors the share handle created by NAPI CreateShareHandle in http_module.cpp.
 */
class CookieShareHandle {
public:
    CookieShareHandle();
    ~CookieShareHandle();

    /**
     * Gets the CURLSH handle.
     * @return The CURLSH handle, or nullptr if initialization failed.
     */
    [[nodiscard]] CURLSH *Get() const
    {
        return handle_;
    }

    /**
     * Gets the mutex used by the curl share lock/unlock callbacks.
     * @return The mutex.
     */
    std::mutex &GetMutex();

private:
    CURLSH *handle_ = nullptr;
    std::mutex mutex_;
};

std::shared_ptr<CookieShareHandle> CreateCookieShareHandle();

class HttpClientTask : public std::enable_shared_from_this<HttpClientTask> {
public:
    /**
     * Constructs an HttpClientTask object with the specified request.
     * @param request The HTTP request object.
     */
    HttpClientTask(const HttpClientRequest &request);

    /**
     * Constructs an HttpClientTask object with the specified request, type, and file path.
     * @param request The HTTP request object.
     * @param type The task type.
     * @param filePath The file path to save the response content.
     */
    HttpClientTask(const HttpClientRequest &request, TaskType type, const std::string &filePath);

    /**
     * Destructor that releases any allocated resources.
     */
    ~HttpClientTask();

    /**
     * Starts the HTTP request task.
     * @return Returns true if the task starts successfully, false otherwise.
     */
    bool Start();

    /**
     * Cancels the ongoing HTTP request task.
     */
    void Cancel();

    /**
     * Gets the status of the HTTP request task.
     * @return The current status of the task.
     */
    [[nodiscard]] TaskStatus GetStatus();

    /**
     * Gets the type of the HTTP request task.
     * @return The type of the task.
     */
    [[nodiscard]] TaskType GetType();

    /**
     * Gets the ID of the HTTP request task.
     * @return The ID of the task.
     */
    [[nodiscard]] unsigned int GetTaskId();

    /**
     * Gets the file path to save the response content.
     * @return The file path.
     */
    [[nodiscard]] const std::string &GetFilePath();

    /**
     * Gets the HTTP request object associated with this task.
     * @return A reference to the HTTP request object.
     */
    [[nodiscard]] HttpClientRequest &GetRequest()
    {
        return request_;
    }

    /**
     * Gets the HTTP response object associated with this task.
     * @return A reference to the HTTP response object.
     */
    [[nodiscard]] HttpClientResponse &GetResponse()
    {
        return response_;
    }

    /**
     * Gets the HTTP error object associated with this task.
     * @return A reference to the HTTP error object.
     */
    [[nodiscard]] HttpClientError &GetError()
    {
        return error_;
    }

    /**
     * Gets the handle for interacting with the CURL library.
     * @return The CURL handle.
     */
    [[nodiscard]] CURL *GetCurlHandle()
    {
        return curlHandle_;
    }

    /**
     * Sets a callback function to be called when the HTTP request succeeds.
     * @param onSucceeded The callback function to be called when the request succeeds.
     *                    It takes the HttpClientRequest object and the HttpClientResponse object as parameters.
     */
    void OnSuccess(
        const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> &onSucceeded);

    /**
     * Sets a callback function to be called when the HTTP request is canceled.
     * @param onCanceled The callback function to be called when the request is canceled.
     *                   It takes the HttpClientRequest object and the HttpClientResponse object as parameters.
     */
    void OnCancel(
        const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> &onCanceled);

    /**
     * Sets a callback function to be called when the HTTP request fails.
     * @param onFailed The callback function to be called when the request fails.
     *                 It takes the HttpClientRequest object, the HttpClientResponse object,
     *                 and the HttpClientError object as parameters.
     */
    void OnFail(const std::function<void(const HttpClientRequest &request, const HttpClientResponse &response,
                                         const HttpClientError &error)> &onFailed);

    /**
     * Sets a callback function to be called when data is received in the HTTP response.
     * @param onDataReceive The callback function to be called when data is received.
     *                      It takes the HttpClientRequest object, a pointer to the received data,
     *                      and the length of the received data as parameters.
     */
    void OnDataReceive(
        const std::function<void(const HttpClientRequest &request, const uint8_t *data, size_t length)> &onDataReceive);

    /**
     * Sets a callback function to be called to report the progress of the HTTP request.
     * @param onProgress The callback function to be called to report the progress.
     *                   It takes the HttpClientRequest object, the total number of bytes to download,
     *                   the number of bytes downloaded, the total number of bytes to upload,
     *                   and the number of bytes uploaded as parameters.
     */
    void OnProgress(const std::function<void(const HttpClientRequest &request, u_long dlTotal, u_long dlNow,
                                             u_long ulTotal, u_long ulNow)> &onProgress);

    /**
     * Sets a callback function to be called when headers is received in the HTTP response.
     * @param onHeadersReceive The callback function to be called when headers is received.
     */
    void OnHeadersReceive(const std::function<void(const HttpClientRequest &request,
        std::map<std::string, std::string> headersWithSetCookie)> &onHeadersReceive);

    /**
     * Sets the response received from the server for this HTTP request.
     * @param response The HttpClientResponse object representing the response from the server.
     */
    void SetResponse(const HttpClientResponse &response);

    void OnHeaderReceive(
        const std::function<void(const HttpClientRequest &request, const std::string &)> &onHeaderReceive);
    bool OffDataReceive();
    bool OffProgress();
    bool OffHeaderReceive();
    bool OffHeadersReceive();
    void SetIsHeaderOnce(bool isOnce);
    bool IsHeaderOnce() const;
    void SetIsHeadersOnce(bool isOnce);
    bool IsHeadersOnce() const;
    void SetIsRequestInStream(bool isRequestInStream);
    bool IsRequestInStream();
    void SetCookieShareHandle(std::shared_ptr<CookieShareHandle> shareHandle);
    bool ProcessUsingCache();
    RequestTracer::Trace &GetTrace();
    static bool IsBuiltWithOpenSSL();
#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
    bool IsRootCaVerified() const;
    void SetRootCaVerified();
    bool IsRootCaVerifiedOk() const;
    void SetRootCaVerifiedOk(bool ok);
#endif
private:
    friend class HttpSession;

    /**
     * Sets the status of the HTTP request task.
     * @param status The status to be set.
     */
    void SetStatus(TaskStatus status);

    /**
     * Sets the Curl options for the HTTP request.
     * @return Returns true if the Curl options are set successfully, false otherwise.
     */
    bool SetCurlOptions();

    /**
     * Sets the Curl options for the tracing stages.
     * @return Returns true if the trace options are set successfully, false otherwise.
     */
    bool SetTraceOptions(CURL *handle);

    /**
     * Sets other Curl options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the Curl options are set successfully, false otherwise.
     */
    bool SetOtherCurlOption(CURL *handle);

    /**
     * Sets the proxy option for the HTTP request.
     *
     * @param handle Curl handle.
     * @return Returns true if the proxy option is set successfully, false otherwise.
     */
    bool SetProxyOption(CURL *handle);

    /**
     * Sets the http proxy option for the HTTP request.
     *
     * @param handle Curl handle.
     * @return Returns true if the http proxy option is set successfully, false otherwise.
     */
    bool SetHttpProxyOption(CURL *handle);

    /**
     * Sets the socks5 proxy option for the HTTP request.
     *
     * @param handle Curl handle.
     * @return Returns true if the socks5 proxy option is set successfully, false otherwise.
     */
    bool SetSocks5ProxyOption(CURL *handle);

    /**
     * Sets the extra info option for the HTTP request.
     *
     * Registers a curl pre-request callback (CURLOPT_PREREQFUNCTION) that is invoked once the
     * connection is established and before the request is sent, and records the connection
     * layer details into the response extra info, including the remote/local IP addresses and
     * ports as well as the TLS version and cipher suite.
     *
     * @param handle The Curl handle.
     * @return Returns true if the extra info option is set successfully, false otherwise.
     */
    bool SetExtraInfoOption(CURL *handle);

    /**
     * Sets the authentication options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the authentication options are set successfully, false otherwise.
     */
    bool SetAuthOptions(CURL *handle);

    /**
     * Sets the range options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the request options are set successfully, false otherwise.
     */
    bool SetRequestOption(CURL *handle);

    /**
     * Sets the server ssl cert options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the set options are set successfully, false otherwise.
     */
    bool SetServerSSLCertOption(CURL *curl);

    /**
     * Sets the pinned pubkey of the network security config for the HTTP request.
     * VerifyRootCa mode stores the pinset into the request, otherwise it is applied as
     * CURLOPT_PINNEDPUBLICKEY.
     * @param curl The Curl handle.
     * @param hostname The hostname of the request URL.
     * @return Returns true if the options are set successfully, false otherwise.
     */
    bool SetPinnedPubkeyOption(CURL *curl, const std::string &hostname);

    /**
     * Registers the SslCtxFunction as the SSL context callback for the HTTP request.
     * The callback is not registered for the TLCP ssl type.
     * @param curl The Curl handle.
     * @return Returns true if the options are set successfully, false otherwise.
     */
    bool SetSslCtxFunctionOption(CURL *curl);

    /**
     * Sets the ssl cert options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the set options are set successfully, false otherwise.
     */
    bool SetSSLCertOption(CURL *curl);

    /**
     * Ssl verify function for the HTTP request.
     * @param handle The Curl handle.
     * @param sslCtl The SSL handle.
     * @return Returns CURLM_OK if the set options are set successfully, error code otherwise.
     */
    CURLcode SslCtxFunction(CURL *curl, void *sslCtx);
    /**
     * Loads the CA certificate paths and the CA data into the SSL context.
     * The CA paths are computed in SetServerSSLCertOption at setup time.
     * @param curl The Curl handle.
     * @param sslCtx The SSL context handle.
     * @return Returns CURLE_OK if the CA certificates are loaded successfully, error code otherwise.
     */
    CURLcode MultiPathSslCtxFunction(CURL *curl, void *sslCtx);

    /**
     * Sets the root CA only verification callback for the SSL context.
     * Only the root CA public key is checked against the pinned pubkey.
     * @param curl The Curl handle.
     * @param sslCtx The SSL context handle.
     * @return Returns CURLE_OK if the verify callback is set successfully, error code otherwise.
     */
    CURLcode VerifyRootCaSslCtxFunction(CURL *curl, void *sslCtx);

    /**
     * Sets the upload options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the upload options are set successfully, false otherwise.
     */
    bool SetUploadOptions(CURL *handle);

    /**
     * Converts the HttpProtocol enum value to the corresponding Http version.
     * @param ptcl The HttpProtocol enum value.
     * @return The Http version as an unsigned integer.
     */
    uint32_t GetHttpVersion(HttpProtocol ptcl) const;

    /**
     * Sets the upload options for the HTTP request.
     * @param host The output string to store the proxy host.
     * @param port The output integer to store the proxy port.
     * @param exclusions The output string to store the proxy exclusions.
     * @param tunnel The output bool to indicate if the proxy uses tunneling.
     */
    void GetHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions,
                          bool &tunnel);

    /**
     * Sets the upload options for the HTTP request.
     * @param host The output string to store the proxy host.
     * @param port The output integer to store the proxy port.
     * @param exclusions The output string to store the proxy exclusions.
     * @param username The output string to receive the proxy username.
     * @param password The output string to receive the proxy password.
     */
    void GetHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions,
                          SecureData &username, SecureData &password);

    /**
     * Callback function used to report the progress of the HTTP request.
     * @param userData User-defined data passed to the callback function.
     * @param dltotal The total number of bytes to download.
     * @param dlnow The number of bytes downloaded so far.
     * @param ultotal The total number of bytes to upload.
     * @param ulnow The number of bytes uploaded so far.
     * @return Returns 0 to continue the transfer, or a non-zero value to abort the transfer.
     */
    static int ProgressCallback(void *userData, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal,
                                curl_off_t ulnow);

    /**
     * Callback function used to receive data in the HTTP response.
     * @param data Pointer to the received data.
     * @param size Size of each element in the data buffer.
     * @param memBytes Number of elements in the data buffer.
     * @param userData User-defined data passed to the callback function.
     * @return The number of bytes processed by the callback function.
     */
    static size_t DataReceiveCallback(const void *data, size_t size, size_t memBytes, void *userData);

    /**
     * Callback function used to receive header data in the HTTP response.
     * @param data Pointer to the received header data.
     * @param size Size of each element in the data buffer.
     * @param memBytes Number of elements in the data buffer.
     * @param userData User-defined data passed to the callback function.
     * @return The number of bytes processed by the callback function.
     */
    static size_t HeaderReceiveCallback(const void *data, size_t size, size_t memBytes, void *userData);

    /**
     * Processes the Curl response message and updates the task status.
     * @param msg The Curl message.
     */
    void ProcessResponse(CURLMsg *msg);

    /**
     * Processes the net address.
     */
    void ProcessNetAddress();
    /**
     * @brief Cache the connection extra info of the HTTP response after the request finishes.
     */
    void ProcessConnectionExtraInfo();
    /**
     * @brief Get the TLS version and cipher suite of the connection.
     * @return Pair of the TLS version and the cipher suite.
     */
    std::pair<TlsVersion, CipherSuite> GetTlsVersionAndCipherSuite();

    /**
     * Processes the response code in the HTTP response.
     * @return Returns true if the response code is processed successfully, false otherwise.
     */
    bool ProcessResponseCode();

    /**
     * Get the timing from curl handle
     * @return Returns timing, unit is seconds.
     */
    double GetTimingFromCurl(CURL *handle, CURLINFO info) const;

    /**
     * Processes the cookie in the HTTP response.
     * @param handle The Curl handle.
     */
    void ProcessCookie(CURL *handle);

    /**
     * Get download or uploader size from curl handle
     * @return Returns size, unit is bytes.
     */
    curl_off_t GetSizeFromCurl(CURL *handle) const;

    /**
     * dump http informations from curl
     */
    void DumpHttpPerformance();

    /**
     * Sets the DNS servers options for the HTTP request.
     * @return Returns true if the Curl options are set successfully, false otherwise.
     */
    bool SetDnsOption(CURL *handle);

    /**
     * Sets the DNS cache options for the HTTP request.
     * @return Returns true if the Curl options are set successfully, false otherwise.
     */
    bool SetDnsCacheOption(CURL *handle);

    /**
     * Sets the addressFamily for the HTTP request.
     * @return Returns the string of addressFamily.
     */
    bool SetIpResolve(CURL *handle);

    /**
     * Set the request whether is success.
     */
    void SetSuccess(bool isSuccess);
#ifdef HTTP_HANDOVER_FEATURE
    /**
     * Get the flag which indicating whether the request is success.
     * @return Return flag indicating the request whether is success.
     */
    bool IsSuccess()
    {
        return isSuccess_;
    }

    /**
     * Get network switch information.
     * @return Return String format for obtaining network sswitching information.
     */
    std::string GetRequestHandoverInfo();

    /**
     * Set the request information and print it to the log.
     */
    void SetRequestHandoverInfo(const HttpHandoverInfo &httpHandoverInfo);
#endif

    /**
    * Gets the start and end download position for the HTTP request.
    * @return Returns the string of range. If the position is invallid, the string is empty.
    */
    std::string GetRangeString() const;

    /**
    * convert safamily to AddressFamily
    * @return AddressFamily.
    */
    AddressFamily ConvertSaFamily(int saFamily);

    /**
    * Sets the ssl type and client encryption certificate for the HTTP request.
    * @return Returns true if the set options are set successfully, false otherwise.
    */
    bool SetSslTypeAndClientEncCert(CURL *handle);

    /**
     * Sets the tls option for the HTTP request.
     * @return Returns true if the tls option are set successfully, false otherwise.
     */
    bool SetTlsOption(CURL *handle);

    /**
    * Determine whether the given HTTP method belongs to the GET class method.
    * @return Returns true if it is a GET class method.
    */
    bool MethodForGet(const std::string &method);

    /**
    * Determine whether the given HTTP method belongs to the POST class method.
    * @return Returns true if it is a POST class method.
    */
    bool MethodForPost(const std::string &method);

    /**
     * Sets the multipart/form-data for the HTTP request.
     * @return Returns true if the set options are set successfully, false otherwise.
     */
    bool SetMultiPartOption(CURL *handle);
    bool SetFormDataOption(const HttpMultiFormData &multiFormData, curl_mimepart *part, CURL *curl);

    bool ReadResopnseFromCache();
    void WriteResopnseToCache(const HttpClientResponse &response);

    bool IsUnReserved(unsigned char in);
    bool EncodeUrlParam(std::string &str);
    std::string MakeUrl(const std::string &url, std::string param, const std::string &extraParam);
    std::string GetJsonFieldValue(const cJSON* item);
    void TraverseJson(const cJSON* item, std::string &output);
    std::string ParseJsonValueToExtraParam(const std::string &jsonStr);
    void BuildUrlWithQueryParams();
    std::string ParseJsonValueToQueryParams(const std::string &jsonStr);
    void ProcessQueryParamValue(const std::string &name, bool encodeName, cJSON *value, std::string &queryParams);
#if HAS_NETMANAGER_BASE
    bool SetInterface(CURL *curl);
    bool GetInterfaceName(CURL *curl, std::string &interfaceName, int32_t &netId);
    bool GetPrimaryCellularInterface(CURL *curl,
        std::list<sptr<NetManagerStandard::NetHandle>> netList, std::string &interfaceName, int32_t &netId);
    bool GetSecondaryCellularInterface(CURL *curl,
        std::list<sptr<NetManagerStandard::NetHandle>> netList, std::string &interfaceName, int32_t &netId);
    bool GetNetStatus(std::list<sptr<NetManagerStandard::NetHandle>> netList,
        std::list<sptr<NetManagerStandard::NetHandle>> &cellularNetworks, uint8_t &cellCount, uint8_t &wifiCount);
#endif
    void HandleMethodForGet();
    bool GetRequestBody();
    void ProcessResponseExpectType();

    bool SetCallbackFunctions();
    bool SetHttpHeaders();
    bool SetCurlMethod();
    bool SetCertPinnerOption(CURL *handle);
    void LogResponseInfo(CURLcode code);
    bool HandleCancelCallback(CURLcode code);
    bool HandleErrorCallback(CURLcode code);
    bool ProcessResponseCoreLogic();
    void HandleResultCallback(bool isResponseOk);
    void HandleNetworkProfiling();
#if ENABLE_HTTP_GLOBAL_INTERCEPT
    bool ConvertRequestContextToInterceptorReq(std::shared_ptr<OH_Http_Interceptor_Request> &req);
    bool ConvertInterceptorReqToRequestContext(std::shared_ptr<OH_Http_Interceptor_Request> &req);
    bool GlobalRequestInterceptorCheck();
    bool ConvertResponseContextToInterceptorResp(std::shared_ptr<OH_Http_Interceptor_Response> &resp);
    bool ConvertInterceptorRespToResponseContext(std::shared_ptr<OH_Http_Interceptor_Response> &resp);
    bool GlobalResponseInterceptorCheck();
#endif

    std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> onSucceeded_;
    std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> onCanceled_;
    std::function<void(const HttpClientRequest &request, const HttpClientResponse &response,
                       const HttpClientError &error)>
        onFailed_;
    std::function<void(const HttpClientRequest &request, const uint8_t *data, size_t length)> onDataReceive_;
    std::function<void(const HttpClientRequest &request, u_long dlTotal, u_long dlNow, u_long ulTotal, u_long ulNow)>
        onProgress_;
    std::function<void(const HttpClientRequest &request, std::map<std::string, std::string> headerWithSetCookie)>
        onHeadersReceive_;
    std::function<void(const HttpClientRequest &request, const std::string &header)> onHeaderReceive_;
    bool isHeaderOnce_;
    bool isHeadersOnce_;
#ifdef HTTP_ONLY_VERIFY_ROOT_CA_ENABLE
    bool isRootCaVerified_ = false;
    bool isRootCaVerifiedOk_ = false;
#endif
    bool isRequestInStream_;
    HttpClientRequest request_;
    HttpClientResponse response_;
    HttpClientError error_;
#ifdef HTTP_HANDOVER_FEATURE
    bool isSuccess_ = false;
    std::string httpHandoverInfoStr_ = "no handover";
#endif

    TaskType type_;
    TaskStatus status_;
    unsigned int taskId_;
    curl_slist *curlHeaderList_;
    bool canceled_;

    std::mutex mutex_;
    CURL *curlHandle_;
    std::shared_ptr<CookieShareHandle> cookieShareHandle_;
    static std::atomic<unsigned int> nextTaskId_;
    std::string filePath_;
    FILE *file_ = nullptr;
#if HAS_NETMANAGER_BASE
    std::unique_ptr<NetworkProfilerUtils> networkProfilerUtils_;
#endif
    std::unique_ptr<RequestTracer::Trace> trace_;
};

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_TASK_H