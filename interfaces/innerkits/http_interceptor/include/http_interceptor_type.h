/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef HTTP_INTERCEPTOR_TYPE_H
#define HTTP_INTERCEPTOR_TYPE_H
#include <cstdlib>
#include <curl/curl.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines http error code.
 */
typedef enum Http_ErrCode {
    /** Operation success. */
    OH_HTTP_RESULT_OK = 0,
    /** @brief Parameter error. */
    OH_HTTP_PARAMETER_ERROR = 401,
    /** @brief Permission denied. */
    OH_HTTP_PERMISSION_DENIED = 201
} Http_ErrCode;

/**
 * @brief Defines http response code.
 */
typedef enum Http_ResponseCode {
    /** @brief The request was successful. */
    OH_HTTP_OK = 200,
    /** @brief Successfully requested and created a new resource. */
    OH_HTTP_CREATED = 201,
    /** @brief The request has been accepted but has not been processed completely. */
    OH_HTTP_ACCEPTED = 202,
    /** @brief Unauthorized information. The request was successful. */
    OH_HTTP_NON_AUTHORITATIVE_INFO = 203,
    /** @brief No content. The server successfully processed, but did not return content. */
    OH_HTTP_NO_CONTENT = 204,
    /** @brief Reset the content. */
    OH_HTTP_RESET = 205,
    /** @brief Partial content. The server successfully processed some GET requests. */
    OH_HTTP_PARTIAL = 206,
    /** @brief Multiple options. */
    OH_HTTP_MULTI_CHOICE = 300,
    /**
     * @brief Permanently move. The requested resource has been permanently moved to a new URI,
     * and the returned information will include the new URI. The browser will automatically redirect to the new URI.
     */
    OH_HTTP_MOVED_PERM = 301,
    /** @brief Temporary movement. */
    OH_HTTP_MOVED_TEMP = 302,
    /** @brief View other addresses. */
    OH_HTTP_SEE_OTHER = 303,
    /** @brief Not modified. */
    OH_HTTP_NOT_MODIFIED = 304,
    /** @brief Using proxies. */
    OH_HTTP_USE_PROXY = 305,
    /** @brief The server cannot understand the syntax error error requested by the client. */
    OH_HTTP_BAD_REQUEST = 400,
    /** @brief Request for user authentication. */
    OH_HTTP_UNAUTHORIZED = 401,
    /** @brief Reserved for future use. */
    OH_HTTP_PAYMENT_REQUIRED = 402,
    /** @brief The server understands the request from the requesting client, but refuses to execute it. */
    OH_HTTP_FORBIDDEN = 403,
    /** @brief The server was unable to find resources (web pages) based on the client's request. */
    OH_HTTP_NOT_FOUND = 404,
    /** @brief The method in the client request is prohibited. */
    OH_HTTP_BAD_METHOD = 405,
    /** @brief The server unabled to complete request based on the content characteristics requested by the client. */
    OH_HTTP_NOT_ACCEPTABLE = 406,
    /** @brief Request authentication of the proxy's identity. */
    OH_HTTP_PROXY_AUTH = 407,
    /** @brief The request took too long and timed out. */
    OH_HTTP_CLIENT_TIMEOUT = 408,
    /**
     * @brief The server may have returned this code when completing the client's PUT request,
     * as there was a conflict when the server was processing the request.
     */
    OH_HTTP_CONFLICT = 409,
    /** @brief The resource requested by the client no longer exists. */
    OH_HTTP_GONE = 410,
    /** @brief The server is unable to process request information sent by the client without Content Length. */
    OH_HTTP_LENGTH_REQUIRED = 411,
    /** @brief The prerequisite for requesting information from the client is incorrect. */
    OH_HTTP_PRECON_FAILED = 412,
    /** @brief The request was rejected because the requested entity was too large for the server to process. */
    OH_HTTP_ENTITY_TOO_LARGE = 413,
    /** @brief The requested URI is too long (usually a URL) and the server cannot process it. */
    OH_HTTP_REQUEST_TOO_LONG = 414,
    /** @brief The server is unable to process the requested format. */
    OH_HTTP_UNSUPPORTED_TYPE = 415,
    /** @brief Requested Range not satisfiable. */
    OH_HTTP_RANGE_NOT_MET = 416,
    /** @brief Internal server error, unable to complete the request. */
    OH_HTTP_INTERNAL_ERROR = 500,
    /** @brief The server does not support the requested functionality and cannot complete the request. */
    OH_HTTP_NOT_IMPLEMENTED = 501,
    /** @brief The server acting as a gateway or proxy received an invalid request from the remote server. */
    OH_HTTP_BAD_GATEWAY = 502,
    /** @brief Due to overload or system maintenance, the server is temporarily unable to process client requests. */
    OH_HTTP_UNAVAILABLE = 503,
    /** @brief The server acting as gateway did not obtain requests from the remote server in a timely manner. */
    OH_HTTP_GATEWAY_TIMEOUT = 504,
    /** @brief The version of the HTTP protocol requested by the server. */
    OH_HTTP_VERSION = 505
} Http_ResponseCode;

typedef struct Http_PerformanceTiming {
    /** The total time in milliseconds for the HTTP transfer, including name resolving, TCP connect etc. */
    double dnsTiming;
    /** The time in milliseconds from the start until the remote host name was resolved. */
    double tcpTiming;
    /** The time in milliseconds from the start until the connection to the remote host (or proxy) was completed. */
    double tlsTiming;
    /** The time in milliseconds, it took from the start until the transfer is just about to begin. */
    double firstSendTiming;
    /** The time in milliseconds from last modification time of the remote file. */
    double firstReceiveTiming;
    /** The time in milliseconds, it took from the start until the first byte is received. */
    double totalFinishTiming;
    /** The time in milliseconds it took for all redirection steps including name lookup, connect, etc.*/
    double redirectTiming;
} Http_PerformanceTiming;

/**
 * @brief HTTP header list, alias of libcurl's <tt>curl_slist</tt>.
 */
typedef curl_slist Http_Headers;

/**
 * @brief Buffer.
 */
typedef struct Http_Buffer {
    /** Content. Buffer will not be copied. */
    char *buffer;
    /** Buffer length. */
    uint32_t length;
} Http_Buffer;

/**
 * @brief Defines interceptor request
 */
typedef struct Http_Interceptor_Request {
    /** Request url, see {@link Http_Buffer}. */
    Http_Buffer url;
    /** Request method, see {@link Http_Buffer}. */
    Http_Buffer method;
    /** Header of http Request, see {@link Http_Headers}. */
    Http_Headers *headers;
    /** Request body, see {@link Http_Buffer}. */
    Http_Buffer body;
} Http_Interceptor_Request;

typedef struct Http_Interceptor_Response {
    /** Response body, see {@link Http_Buffer}. */
    Http_Buffer body;
    /** Server status code, see {@link Http_ResponseCode}. */
    Http_ResponseCode responseCode;
    /** Header of http response, see {@link Http_Headers}. */
    Http_Headers *headers;
    /** The time taken of various stages of HTTP request, see {@link Http_PerformanceTiming}. */
    Http_PerformanceTiming performanceTiming;
} Http_Interceptor_Response;

/**
 * @brief Defines interceptor stage
 */
typedef enum Interceptor_Stage {
    /** http request hook */
    STAGE_REQUEST,
    /** http response hook */
    STAGE_RESPONSE
} Interceptor_Stage;

/**
 * @brief Defines interceptor type
 */
typedef enum Interceptor_Type {
    /** interceptor will not modify the packet */
    TYPE_READ_ONLY,
    /** interceptor will modify the packet */
    TYPE_MODIFY
} Interceptor_Type;

/**
 * @brief Defines interceptor process result
 */
typedef enum Interceptor_Result {
    /** interceptor result is continue */
    CONTINUE,
    /** interceptor result is abort this packet */
    ABORT
} Interceptor_Result;

/**
 * @brief Defines interceptor handler
 */
typedef Interceptor_Result (*OH_Http_InterceptorHandler)(
    /** http request packet */
    Http_Interceptor_Request *request,
    /** http response packet */
    Http_Interceptor_Response *response,
    /** interceptor isModified */
    int32_t *isModified);

/**
 * @brief Defines interceptor configuration
 */
typedef struct Http_Interceptor {
    /** group ID of interceptor */
    int32_t groupId;
    /** stage of interceptor */
    Interceptor_Stage stage;
    /** type of interceptor */
    Interceptor_Type type;
    /** handler of interceptor */
    OH_Http_InterceptorHandler handler;
    /** whether this interceptor is enabled */
    int32_t enabled;
} Http_Interceptor;

/**
 * @brief Performs a deep copy of an Http_Buffer.
 *
 * @param dest Pointer to the destination buffer. Must not be NULL.
 *             Its <tt>buffer</tt> field will be overwritten (previous content is NOT freed).
 * @param src  Pointer to the source buffer. Must not be NULL.
 *             If <tt>src->buffer</tt> is NULL, <tt>dest->buffer</tt> will be set to NULL
 *             and <tt>dest->length</tt> to 0.
 */
void DeepCopyBuffer(Http_Buffer *dest, const Http_Buffer *src);

/**
 * @brief Creates a deep copy of an HTTP header list.
 *
 * @param src Pointer to the source header list (<tt>Http_Headers*</tt>).
 *            If NULL, returns NULL.
 *
 * @return A new <tt>Http_Headers*</tt> containing a copy of all headers,
 *         or NULL if out of memory or input is NULL.
 */
Http_Headers *DeepCopyHeaders(Http_Headers *src);

/**
 * @brief Safely destroys an Http_Interceptor_Request and releases all owned resources.
 *
 * After this call, the content of <tt>req</tt> is undefined; do not use it again.
 *
 * @param req Pointer to the request to destroy. Safe to pass NULL (no-op).
 */
void DestroyHttpInterceptorRequest(Http_Interceptor_Request *req);

/**
 * @brief Safely destroys an Http_Interceptor_Response and releases all owned resources.
 *
 * @param resp Pointer to the response to destroy. Safe to pass NULL (no-op).
 */
void DestroyHttpInterceptorResponse(Http_Interceptor_Response *resp);

/**
 * @brief Initializes an Http_Buffer structure to a safe empty state.
 *
 * @param src Pointer to the Http_Buffer to initialize. Must not be NULL.
 */
void InitHttpBuffer(Http_Buffer *src);

#ifdef __cplusplus
}
#endif

#endif // HTTP_INTERCEPTOR_TYPE_H