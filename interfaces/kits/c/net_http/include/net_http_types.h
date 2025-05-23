/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
#ifndef NET_HTTP_TYPE_H
#define NET_HTTP_TYPE_H
/**
 * @addtogroup http
 * @{
 *
 * @brief Provides C APIs for the Http client module.
 *
 * @since 20
 */
/**
 * @file net_http_type.h
 * @brief Defines the data structure for the C APIs of the http module.
 *
 * @kit NetworkKit
 * @syscap SystemCapability.Communication.NetStack
 * @since 20
 */
#ifdef __cplusplus
extern "C" {
#endif
#define OHOS_HTTP_MAX_PATH_LEN 128
#define OHOS_HTTP_MAX_STR_LEN 256
#define OHOS_HTTP_DNS_SERVER_NUM_MAX 3

/**
 * @brief Defines http error code.
 *
 * @since 20
 */
typedef enum Http_ErrCode {
    /**
     * Operation success.
     */
    RESULT_OK = 0,
    /**
     * @brief Parameter error.
     */
    PARAMETER_ERROR = 401,
    /**
     * @brief Permission denied.
     */
    PERMISSION_DENIED = 201,
    /**
     * @brief Error code base.
     */
    NETSTACK_E_BASE = 2300000,
    /**
     * @brief Unsupported protocol.
     */
    UNSUPPORTED_PROTOCOL = (NETSTACK_E_BASE + 1),
    /**
     * @brief Invalid URL format or missing URL.
     */
    INVALID_URL = (NETSTACK_E_BASE + 3),
    /**
     * @brief Failed to resolve the proxy name.
     */
    RESOLVE_PROXY_FAILED = (NETSTACK_E_BASE + 5),
    /**
     * @brief Failed to resolve the host name.
     */
    RESOLVE_HOST_FAILED = (NETSTACK_E_BASE + 6),
    /**
     * @brief Failed to connect to the server.
     */
    CONNECT_SERVER_FAILED = (NETSTACK_E_BASE + 7),
    /**
     * @brief Invalid server response.
     */
    INVALID_SERVER_RESPONSE = (NETSTACK_E_BASE + 8),
    /**
     * @brief Access to the remote resource denied.
     */
    ACCESS_REMOTE_DENIED = (NETSTACK_E_BASE + 9),
    /**
     * @brief Error in the HTTP2 framing layer.
     */
    HTTP2_FRAMING_ERROR = (NETSTACK_E_BASE + 16),
    /**
     * @brief Transferred a partial file.
     */
    TRANSFER_PARTIAL_FILE = (NETSTACK_E_BASE + 18),
    /**
     * @brief Failed to write the received data to the disk or application.
     */
    WRITE_DATA_FAILED = (NETSTACK_E_BASE + 23),
    /**
     * @brief Upload failed.
     */
    UPLOAD_FAILED = (NETSTACK_E_BASE + 25),
    /**
     * @brief Failed to open or read local data from the file or application.
     */
    OPEN_LOCAL_DATA_FAILED = (NETSTACK_E_BASE + 26),
    /**
     * @brief Out of memory.
     */
    OUT_OF_MEMORY = (NETSTACK_E_BASE + 27),
    /**
     * @brief Operation timeout.
     */
    OPERATION_TIMEOUT = (NETSTACK_E_BASE + 28),
    /**
     * @brief The number of redirections reaches the maximum allowed.
     */
    REDIRECTIONS_TOO_LARGE = (NETSTACK_E_BASE + 47),
    /**
     * @brief The server returned nothing (no header or data).
     */
    SERVER_RETURNED_NOTHING = (NETSTACK_E_BASE + 52),
    /**
     * @brief Failed to send data to the peer.
     */
    SEND_DATA_FAILED = (NETSTACK_E_BASE + 55),
    /**
     * @brief Failed to receive data from the peer.
     */
    RECEIVE_DATA_FAILED = (NETSTACK_E_BASE + 56),
    /**
     * @brief Local SSL certificate error.
     */
    SSL_CERTIFICATE_ERROR = (NETSTACK_E_BASE + 58),
    /**
     * @brief The specified SSL cipher cannot be used.
     */
    SSL_CIPHER_USED_ERROR = (NETSTACK_E_BASE + 59),
    /**
     * @brief Invalid SSL peer certificate or SSH remote key.
     */
    INVALID_SSL_PEER_CERT = (NETSTACK_E_BASE + 60),
    /**
     * @brief Invalid HTTP encoding format.
     */
    INVALID_ENCODING_FORMAT = (NETSTACK_E_BASE + 61),
    /**
     * @brief Maximum file size exceeded.
     */
    FILE_TOO_LARGE = (NETSTACK_E_BASE + 63),
    /**
     * @brief Remote disk full.
     */
    REMOTE_DISK_FULL = (NETSTACK_E_BASE + 70),
    /**
     * @brief Remote file already exists.
     */
    REMOTE_FILE_EXISTS = (NETSTACK_E_BASE + 73),
    /**
     * @brief The SSL CA certificate does not exist or is inaccessible.
     */
    SSL_CA_NOT_EXIST = (NETSTACK_E_BASE + 77),
    /**
     * @brief Remote file not found.
     */
    REMOTE_FILE_NOT_FOUND = (NETSTACK_E_BASE + 78),
    /**
     * @brief Authentication error.
     */
    AUTHENTICATION_ERROR = (NETSTACK_E_BASE + 94),
    /**
     * @brief It is not allowed to access this domain.
     */
    ACCESS_DOMAIN_NOT_ALLOWED = (NETSTACK_E_BASE + 998),
    /**
     * @brief Unknown error.
     */
    UNKNOWN_ERROR = (NETSTACK_E_BASE + 999)
} Http_ErrCode;

/**
 * @brief Defines http response code.
 *
 * @since 20
 */
typedef enum Http_ResponseCode {
    /**
     * @brief The request was successful..
     */
    HTTP_OK = 200,
    /**
     * @brief Successfully requested and created a new resource..
     */
    CREATED = 201,
    /**
     * @brief The request has been accepted but has not been processed completely.
     */
    ACCEPTED = 202,
    /**
     * @brief Unauthorized information. The request was successful.
     */
    NOT_AUTHORITATIVE = 203,
    /**
     * @brief No content. The server successfully processed, but did not return content.
     */
    NO_CONTENT = 204,
    /**
     * @brief Reset the content.
     */
    RESET = 205,
    /**
     * @brief Partial content. The server successfully processed some GET requests.
     */
    PARTIAL = 206,
    /**
     * @brief Multiple options.
     */
    MULT_CHOICE = 300,
    /**
     * @brief Permanently move. The requested resource has been permanently moved to a new URI,
     * and the returned information will include the new URI. The browser will automatically redirect to the new URI.
     */
    MOVED_PERM = 301,
    /**
     * @brief Temporary movement.
     */
    MOVED_TEMP = 302,
    /**
     * @brief View other addresses.
     */
    SEE_OTHER = 303,
    /**
     * @brief  Not modified.
     */
    NOT_MODIFIED = 304,
    /**
     * @brief  Using proxies.
     */
    USE_PROXY = 305,
    /**
     * @brief  The server cannot understand the syntax error error requested by the client.
     */
    BAD_REQUEST = 400,
    /**
     * @brief Request for user authentication.
     */
    UNAUTHORIZED = 401,
    /**
     * @brief Reserved for future use.
     */
    PAYMENT_REQUIRED = 402,
    /**
     * @brief The server understands the request from the requesting client, but refuses to execute it.
     */
    FORBIDDEN = 403,
    /**
     * @brief The server was unable to find resources (web pages) based on the client's request.
     */
    NOT_FOUND = 404,
    /**
     * @brief The method in the client request is prohibited.
     */
    BAD_METHOD = 405,
    /**
     * @brief The server is unable to complete the request based on the content characteristics requested by the client.
     */
    NOT_ACCEPTABLE = 406,
    /**
     * @brief Request authentication of the proxy's identity.
     */
    PROXY_AUTH = 407,
    /**
     * @brief The request took too long and timed out.
     */
    CLIENT_TIMEOUT = 408,
    /**
     * @brief The server may have returned this code when completing the client's PUT request,
     * as there was a conflict when the server was processing the request.
     */
    CONFLICT = 409,
    /**
     * @brief The resource requested by the client no longer exists.
     */
    GONE = 410,
    /**
     * @brief  The server is unable to process request information sent by the client without Content Length.
     */
    LENGTH_REQUIRED = 411,
    /**
     * @brief The prerequisite for requesting information from the client is incorrect.
     */
    PRECON_FAILED = 412,
    /**
     * @brief  The request was rejected because the requested entity was too large for the server to process.
     */
    ENTITY_TOO_LARGE = 413,
    /**
     * @brief  The requested URI is too long (usually a URL) and the server cannot process it.
     */
    REQ_TOO_LONG = 414,
    /**
     * @brief The server is unable to process the requested format.
     */
    UNSUPPORTED_TYPE = 415,
    /**
     * @brief Requested Range not satisfiable.
     */
    RANGE_NOT_SATISFIABLE = 416,
    /**
     * @brief Internal server error, unable to complete the request.
     */
    INTERNAL_ERROR = 500,
    /**
     * @brief * The server does not support the requested functionality and cannot complete the request.
     */
    NOT_IMPLEMENTED = 501,
    /**
     * @brief The server acting as a gateway or proxy received an invalid request from the remote server.
     */
    BAD_GATEWAY = 502,
    /**
     * @brief Due to overload or system maintenance, the server is temporarily unable to process client requests.
     */
    UNAVAILABLE = 503,
    /**
     * @brief The server acting as a gateway or proxy did not obtain requests from the remote server in a timely manner.
     */
    GATEWAY_TIMEOUT = 504,
    /**
     * @brief The version of the HTTP protocol requested by the server.
     */
    VERSION = 505
} Http_ResponseCode;

/**
 * @brief Buffer
 * @since 20
 */
typedef struct Http_Buffer {
    /** Content. Buffer will not be copied. */
    const char *buffer;
    /** Buffer length */
    uint32_t length;
} Http_Buffer;

/**
 * @brief Defines the address Family.
 *
 * @since 20
 */
typedef enum Http_AddressFamilyType {
    /** Default, The system automatically selects the IPv4 or IPv6 address of the domain name. */
    DEFAULT = 0,
    /** IPv4, Selects the IPv4 address of the domain name. */
    ONLY_V4 = 1,
    /** IPv6, Selects the IPv4 address of the domain name. */
    ONLY_V6 = 2
} Http_AddressFamilyType;
 
/**
 * @brief HTTP get method
 * @since 20
 */
#define NET_HTTP_METHOD_GET "GET"
/**
 * @brief HTTP head method
 * @since 20
 */
#define NET_HTTPMETHOD_HEAD "HEAD"
/**
 * @brief HTTP options method
 * @since 20
 */
#define NET_HTTPMETHOD_OPTIONS "OPTIONS"
/**
 * @brief HTTP trace method
 * @since 20
 */
#define NET_HTTPMETHOD_TRACE "TRACE"
/**
 * @brief HTTP delete method
 * @since 20
 */
#define NET_HTTPMETHOD_DELETE "DELETE"
/**
 * @brief HTTP post method
 * @since 20
 */
#define NET_HTTP_METHOD_POST "POST"
/**
 * @brief HTTP put method
 * @since 20
 */
#define NET_HTTP_METHOD_PUT "PUT"
/**
 * @brief HTTP patch method
 * @since 20
 */
#define NET_HTTP_METHOD_PATCH "CONNECT"

/**
 * @brief Defines the HTTP version.
 *
 * @since 20
 */
typedef enum Http_HttpProtocol {
    /** default choose by curl */
     HTTP_NONE = 0,
    /** Http 1.1 version */
    HTTP1_1,
    /** Http 2 version */
    HTTP2,
    /** Http 3 version */
    HTTP3
} Http_HttpProtocol;

/**
 * @brief Defines the Cert Type.
 *
 * @since 20
 */
typedef enum Http_CertType {
    /** PEM Cert Type */
    PEM = 0,
    /** DER Cert Type */
    DER = 1,
    /** P12 Cert Type */
    P12 = 2
} Http_CertType;

/**
  * @brief Headers of the request or response.
  * @since 20
  */
typedef struct Http_Headers Http_Headers;

/**
 * @brief The value type of the header map of the request or response.
 * @since 20
 */
typedef struct Http_HeaderValue {
    /** Value */
    char *value;
    /** Point to the next {@link Http_HeaderValue} */
    struct Http_HeaderValue *next;
} Http_HeaderValue;

/**
 * @brief All key-value pairs of the headers of the request or response.
 * @since 20
 */
typedef struct Http_HeaderEntry {
    /** Key */
    char *key;
    /** Value */
    Http_HeaderValue *value;
    /** Points to the next key-value pair {@link Http_HeaderEntry} */
    struct Http_HeaderEntry *next;
} Http_HeaderEntry;

/**
 * @brief Client certificate which is sent to the remote server, the the remote server will use it to verify the
 * client's identification.
 * @since 20
 */
typedef struct Http_ClientCert {
    /** A path to a client certificate. */
    char *certPath;
    /** Client certificate type. */
    Http_CertType type;
    /** File path of your client certificate private key. */
    char *keyPath;
    /** Password for your client certificate private key. */
    char *keyPassword;
} Http_ClientCert;

/**
 * @brief Proxy type. Used to distinguish different proxy configurations.
 * @since 20
 */
typedef enum Http_ProxyType {
    /** System proxy */
    HTTP_PROXY_NOT_USE,
    /** System proxy */
    HTTP_PROXY_SYSTEM,
    /** Use custom proxy */
    HTTP_PROXY_CUSTOM
} Http_ProxyType;

/**
 * @brief Custom proxy configuration.
 * @since 20
 */
typedef struct Http_CustomProxy {
    /** Indicates the URL of the proxy server. If you do not set port explicitly, port will be 1080. */
    const char *host;
    int32_t port;
    const char *exclusionLists;
} Http_CustomProxy;

/**
 * @brief Proxy configuration.
 * @since 20
 */
typedef struct Http_Proxy {
    /** Distinguish the proxy type used by the request */
    Http_ProxyType proxyType;
    /** Custom proxy configuration, see {@link Http_CustomProxy} */
    Http_CustomProxy customProxy;
} Http_Proxy;

/**
 * @brief Response timing information. It will be collected in {@link Http_Response.performanceTiming} and
 * @since 20
 */
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
 * @brief Defines the parameters for http request options.
 *
 * @since 20
 */
typedef struct Http_RequestOptions {
    /** Request method. */
    const char *method;
    /** Priority of http requests. A larger value indicates a higher priority. */
    uint32_t priority;
    /** Header of http requests. */
    Http_Headers *headers;
    /** Read timeout interval. */
    uint32_t readTimeout;
    /** Connection timeout interval. */
    uint32_t connectTimeout;
    /** Use the protocol. The default value is automatically specified by the system. */
    Http_HttpProtocol httpProtocol;
    /** Indicates whether to use the HTTP proxy. The default value is false. */
    Http_Proxy *httpProxy;
    /** CA certificate of the user-specified path. */
    const char *caPath;
    /** Set the download start position. This parameter can be used only in the GET method. */
    int64_t resumeFrom;
    /** Set the download end position. This parameter can be used only in the GET method. */
    int64_t resumeTo;
    /** Client certificates can be transferred. */
    Http_ClientCert *clientCert;
    /** Set the DNS resolution for the https server. */
    const char *dnsOverHttps;
    /** Maximum number of bytes in a response message. */
    uint32_t maxLimit;
    /** The address family can be specified when the target domain name is resolved. */
    Http_AddressFamilyType addressFamily;
} Http_RequestOptions;

/**
 * @brief Defines the parameters for http response.
 *
 * @since 20
 */
typedef struct Http_Response {
    /** Response body */
    Http_Buffer body;
    /** Server status code. */
    Http_ResponseCode responseCode;
    /** Header of http response. */
    Http_Headers *headers;
    /** Cookies returned by the server. */
    char *cookies;
    /** The time taken of various stages of HTTP request. */
    Http_PerformanceTiming *performanceTiming;
    /**
     * @brief Response deletion function
     * @param response Indicates the response to be deleted. It is a pointer that points to {@link Http_Response}.
     * @since 20
     */
    void (*destroyResponse)(struct Http_Response **response);
} Http_Response;

/**
 * @brief Http request.
 * @since 20
 */
typedef struct Http_Request {
    /** The request id for every single request. Generated by system. */
    uint32_t requestId;
    /** Request url */
    char *url;
    /** Request options. */
    Http_RequestOptions *options;
} Http_Request;

/**
 * @brief Callback function that is invoked when response is received.
 * @param response Http response struct.
 * @param errCode Response error code.
 * @since 20
 */
typedef void (*Http_ResponseCallback)(struct Http_Response *response, uint32_t errCode);

/**
 * @brief Callback function that is invoked when a response body is received.
 * @param data Response body.
 * @return size_t the length of response body.
 * @since 20
 */
typedef size_t (*Http_OnDataReceiveCallback)(const char *data);

/**
 * @brief Callback function invoked during request/response data transmission.
 * @param totalSize total size
 * @param transferredSize transferred size
 * @since 20
 */
typedef void (*Http_OnProgressCallback)(uint64_t totalSize, uint64_t transferredSize);

/**
 * @brief Callback called when all requests are received.
 * @param headers Headers of the received requests, which points to the pointer of {@link Rcp_Headers}.
 * @since 20
 */
typedef void (*Http_OnHeaderReceiveCallback)(Http_Headers *headers);

/**
 * @brief Empty callback function for requested DataEnd or Canceled event callback
 * @since 20
 */
typedef void (*Http_OnVoidCallback)(void);

/**
 * @brief Callbacks to watch different events.
 * @since 20
 */
typedef struct Http_EventsHandler {
    /** Callback function when the response body is received */
    Http_OnDataReceiveCallback onDataReceive;
    /** Callback function during uploading */
    Http_OnProgressCallback onUploadProgress;
    /** Callback function during downloading */
    Http_OnProgressCallback onDownloadProgress;
    /** Callback function when a header is received */
    Http_OnHeaderReceiveCallback onHeadersReceive;
    /** Callback function at the end of the transfer */
    Http_OnVoidCallback onDataEnd; // DONE
    /** Callback function when a request is canceled */
    Http_OnVoidCallback onCanceled;  // DONE
} Http_EventsHandler;
#ifdef __cplusplus
}
#endif
#endif // NET_HTTP_TYPE_H