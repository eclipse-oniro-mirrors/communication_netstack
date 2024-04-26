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
#include <memory>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <string>

#include "http_client_error.h"
#include "http_client_request.h"
#include "http_client_response.h"

namespace OHOS {
namespace NetStack {
namespace HttpClient {
enum TaskStatus {
    IDLE,
    RUNNING,
};

enum TaskType {
    DEFAULT,
    UPLOAD,
};

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
     * Sets the response received from the server for this HTTP request.
     * @param response The HttpClientResponse object representing the response from the server.
     */
    void SetResponse(const HttpClientResponse &response);

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
     * Sets other Curl options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the Curl options are set successfully, false otherwise.
     */
    bool SetOtherCurlOption(CURL *handle);

    /**
     * Sets the server ssl cert options for the HTTP request.
     * @param handle The Curl handle.
     * @return Returns true if the set options are set successfully, false otherwise.
     */
    bool SetServerSSLCertOption(CURL *curl);

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
     * Retrieves the HttpProxyInfo including host, port, exclusions, and tunnel flag.
     * @param host The output string to store the proxy host.
     * @param port The output integer to store the proxy port.
     * @param exclusions The output string to store the proxy exclusions.
     * @param tunnel The output bool to indicate if the proxy uses tunneling.
     */
    void GetHttpProxyInfo(std::string &host, int32_t &port, std::string &exclusions,
                          bool &tunnel);

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
    void DumpHttpPerformance() const;

    std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> onSucceeded_;
    std::function<void(const HttpClientRequest &request, const HttpClientResponse &response)> onCanceled_;
    std::function<void(const HttpClientRequest &request, const HttpClientResponse &response,
                       const HttpClientError &error)>
        onFailed_;
    std::function<void(const HttpClientRequest &request, const uint8_t *data, size_t length)> onDataReceive_;
    std::function<void(const HttpClientRequest &request, u_long dlTotal, u_long dlNow, u_long ulTotal, u_long ulNow)>
        onProgress_;

    HttpClientRequest request_;
    HttpClientResponse response_;
    HttpClientError error_;

    TaskType type_;
    TaskStatus status_;
    unsigned int taskId_;
    struct curl_slist *curlHeaderList_;
    bool canceled_;

    std::mutex mutex_;
    CURL *curlHandle_;
    static std::atomic<unsigned int> nextTaskId_;
    std::string filePath_;
    FILE *file_ = nullptr;
};

} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_TASK_H