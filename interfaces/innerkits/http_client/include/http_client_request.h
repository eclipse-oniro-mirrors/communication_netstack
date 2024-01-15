/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_REQUEST_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_REQUEST_H

#include <string>
#include <map>
#include <vector>

namespace OHOS {
namespace NetStack {
namespace HttpClient {
enum HttpProxyType {
    NOT_USE,
    USE_SPECIFIED,
    PROXY_TYPE_MAX,
};

enum HttpProtocol {
    HTTP_NONE, // default choose by curl
    HTTP1_1,
    HTTP2,
    HTTP3,
    HTTP_PROTOCOL_MAX,
};

struct HttpProxy {
    std::string host;
    int32_t port;
    std::string exclusions;
    bool tunnel;

    HttpProxy() : host(""), port(0), exclusions(""), tunnel(false) {}
};

class HttpClientRequest {
public:
    /**
     * Default constructor for HttpClientRequest.
     */
    HttpClientRequest();

    /**
     * Set the URL for the HTTP request.
     * @param url The URL to be set.
     */
    void SetURL(const std::string &url);

    /**
     * Set the method for the HTTP request.
     * @param method The method to be set.
     */
    void SetMethod(const std::string &method);

    /**
     * Set the body data for the HTTP request.
     * @param data Pointer to the data.
     * @param length Length of the data.
     */
    void SetBody(const void *data, size_t length);

    /**
     * Set a header field for the HTTP request.
     * @param key The header field key.
     * @param val The header field value.
     */
    void SetHeader(const std::string &key, const std::string &val);

    /**
     * Set the timeout for the HTTP request.
     * @param timeout The timeout value in seconds.
     */
    void SetTimeout(unsigned int timeout);

    /**
     * Set the connect timeout for the HTTP request.
     * @param timeout The connect timeout value in seconds.
     */
    void SetConnectTimeout(unsigned int timeout);

    /**
     * Set the HTTP protocol for the request.
     * @param protocol The HTTP protocol to be set.
     */
    void SetHttpProtocol(HttpProtocol protocol);

    /**
     * Set the HTTP proxy for the request.
     * @param proxy The HTTP proxy to be set.
     */
    void SetHttpProxy(const HttpProxy &proxy);

    /**
     * Set the HTTP proxy type for the request.
     * @param type The HTTP proxy type to be set.
     */
    void SetHttpProxyType(HttpProxyType type);

    /**
     * Set the CA certificate path for the HTTPS request.
     * @param path The CA certificate path to be set.
     */
    void SetCaPath(const std::string &path);

    /**
     * Set the priority for the HTTP request.
     * @param priority The priority value to be set.
     */
    void SetPriority(unsigned int priority);

    /**
     * Get the URL of the HTTP request.
     * @return The URL of the request.
     */
    [[nodiscard]] const std::string &GetURL() const;

    /**
     * Get the method of the HTTP request.
     * @return The method of the request.
     */
    [[nodiscard]] const std::string &GetMethod() const;

    /**
     * Get the body data of the HTTP request.
     * @return The body data of the request.
     */
    [[nodiscard]] const std::string &GetBody() const;

    /**
     * Get the header fields of the HTTP request.
     * @return A map of header field key-value pairs.
     */
    [[nodiscard]] const std::map<std::string, std::string> &GetHeaders() const;

    /**
     * Get the timeout of the HTTP request.
     * @return The timeout value in seconds.
     */
    [[nodiscard]] unsigned int GetTimeout();

    /**
     * Get the connect timeout of the HTTP request.
     * @return The connect timeout value in seconds.
     */
    [[nodiscard]] unsigned int GetConnectTimeout();

    /**
     * Get the HTTP protocol of the request.
     * @return The HTTP protocol of the request.
     */
    [[nodiscard]] HttpProtocol GetHttpProtocol();

    /**
     * Get the HTTP proxy of the request.
     * @return The HTTP proxy of the request.
     */
    [[nodiscard]] const HttpProxy &GetHttpProxy() const;

    /**
     * Get the HTTP proxy type of the request.
     * @return The HTTP proxy type of the request.
     */
    [[nodiscard]] HttpProxyType GetHttpProxyType();

    /**
     * Get the CA certificate path of the HTTPS request.
     * @return The CA certificate path of the request.
     */
    [[nodiscard]] const std::string &GetCaPath();

    /**
     * Get the priority of the HTTP request.
     * @return The priority value of the request.
     */
    [[nodiscard]] uint32_t GetPriority() const;

    /**
     * Check if the specified method is suitable for a GET request.
     * @param method The method to check.
     * @return True if the method is suitable for a GET request, false otherwise.
     */
    bool MethodForGet(const std::string &method);

    /**
     * Check if the specified method is suitable for a POST request.
     * @param method The method to check.
     * @return True if the method is suitable for a POST request, false otherwise.
     */
    bool MethodForPost(const std::string &method);

    /**
     * Sets the request time for the object.
     * @param time The request time to be set.
     */
    void SetRequestTime(const std::string &time);

    /**
     * Retrieves the request time from the object.
     * @return The request time.
     */
    const std::string &GetRequestTime() const;

private:
    std::string url_;
    std::string method_;
    std::string body_;
    std::map<std::string, std::string> headers_;
    unsigned int timeout_;
    unsigned int connectTimeout_;
    HttpProtocol protocol_;
    HttpProxy proxy_;
    HttpProxyType proxyType_;
    std::string caPath_;
    unsigned int priority_;
    std::string requestTime_;
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_REQUEST_H
