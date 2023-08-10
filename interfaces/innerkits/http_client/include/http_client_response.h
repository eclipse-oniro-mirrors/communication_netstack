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

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_RESPONSE_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_RESPONSE_H

#include <map>
#include <string>

namespace OHOS {
namespace NetStack {
namespace HttpClient {
static constexpr const char *WARNING = "Warning";

enum ResponseCode {
    NONE = 0,
    OK = 200,
    CREATED,
    ACCEPTED,
    NOT_AUTHORITATIVE,
    NO_CONTENT,
    RESET,
    PARTIAL,
    MULT_CHOICE = 300,
    MOVED_PERM,
    MOVED_TEMP,
    SEE_OTHER,
    NOT_MODIFIED,
    USE_PROXY,
    BAD_REQUEST = 400,
    UNAUTHORIZED,
    PAYMENT_REQUIRED,
    FORBIDDEN,
    NOT_FOUND,
    BAD_METHOD,
    NOT_ACCEPTABLE,
    PROXY_AUTH,
    CLIENT_TIMEOUT,
    CONFLICT,
    GONE,
    LENGTH_REQUIRED,
    PRECON_FAILED,
    ENTITY_TOO_LARGE,
    REQ_TOO_LONG,
    UNSUPPORTED_TYPE,
    INTERNAL_ERROR = 500,
    NOT_IMPLEMENTED,
    BAD_GATEWAY,
    UNAVAILABLE,
    GATEWAY_TIMEOUT,
    VERSION,
};

class HttpClientResponse {
public:
    /**
     * Default constructor for HttpClientResponse.
     */
    HttpClientResponse() : responseCode_(NONE), result_(""){};

    /**
     * Get the response code of the HTTP response.
     * @return The response code.
     */
    [[nodiscard]] ResponseCode GetResponseCode() const;

    /**
     * Get the header of the HTTP response.
     * @return The header of the response.
     */
    [[nodiscard]] const std::string &GetHeader() const;

    /**
     * Get the cookies of the HTTP response.
     * @return The cookies of the response.
     */
    [[nodiscard]] const std::string &GetCookies() const;

    /**
     * Get the request time of the HTTP response.
     * @return The request time of the response.
     */
    [[nodiscard]] const std::string &GetRequestTime() const;

    /**
     * Get the response time of the HTTP response.
     * @return The response time of the response.
     */
    [[nodiscard]] const std::string &GetResponseTime() const;

    /**
     * Set the request time of the HTTP response.
     * @param time The request time to be set.
     */
    void SetRequestTime(const std::string &time);

    /**
     * @brief Set the response time of the HTTP response.
     * @param time The response time to be set.
     */
    void SetResponseTime(const std::string &time);

    /**
     * Set the response code of the HTTP response.
     * @param code The response code to be set.
     */
    void SetResponseCode(ResponseCode code);

    /**
     * Parses the headers of the HTTP response.
     */
    void ParseHeaders();

    /**
     * Retrieves the headers of the HTTP response.
     * @return A constant reference to a map of header key-value pairs.
     */
    [[nodiscard]] const std::map<std::string, std::string> &GetHeaders() const;

    /**
     * Sets a warning message for the HTTP response.
     * @param val The warning message.
     */
    void SetWarning(const std::string &val);

    /**
     * Sets a raw header for the HTTP response.
     * @param header The raw header string.
     */
    void SetRawHeader(const std::string &header);

    /**
     * Sets the cookies for the HTTP response.
     * @param cookies The cookie string.
     */
    void SetCookies(const std::string &cookies);

    /**
     * Sets the result of the HTTP response.
     * @param res The result string.
     */
    void SetResult(const std::string &res);

    /**
     * Retrieves the result of the HTTP response.
     * @return A constant reference to the result string.
     */
    [[nodiscard]] const std::string &GetResult() const;

private:
    friend class HttpClientTask;

    /**
     * @brief Append data to the header of the HTTP response.
     * @param data Pointer to the data.
     * @param length Length of the data.
     */
    void AppendHeader(const char *data, size_t length);

    /**
     * Append data to the cookies of the HTTP response.
     * @param data Pointer to the data.
     * @param length Length of the data.
     */
    void AppendCookies(const char *data, size_t length);
    void AppendResult(const void *data, size_t length);

    ResponseCode responseCode_;
    std::string rawHeader_;
    std::map<std::string, std::string> headers_;
    std::string cookies_;
    std::string responseTime_;
    std::string requestTime_;
    std::string result_;
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_RESPONSE_H
