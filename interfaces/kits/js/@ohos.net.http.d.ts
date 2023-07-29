/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

import {AsyncCallback, Callback} from "./basic";
import connection from "./@ohos.net.connection";

/**
 * Provides http related APIs.
 * @namespace http
 * @syscap SystemCapability.Communication.NetStack
 * @since 6
 */
declare namespace http {
  /**
   * @since 10
   */
  type HttpProxy = connection.HttpProxy;

  /**
   * Creates an HTTP request task.
   * @returns { HttpRequest } the HttpRequest of the createHttp.
   * @crossplatform
   * @syscap SystemCapability.Communication.NetStack
   * @since 6
   */
  function createHttp(): HttpRequest;

  /**
   * Specifies the type and value range of the optional parameters in the HTTP request.
   * @interface HttpRequestOptions
   * @syscap SystemCapability.Communication.NetStack
   * @since 6
   */
  export interface HttpRequestOptions {
    /**
     * Request method,default is GET.
     * @type {RequestMethod}
     * @crossplatform
     * @since 6
     */
    method?: RequestMethod;

    /**
     * Additional data of the request.
     * extraData can be a string or an Object (API 6) or an ArrayBuffer(API 8).
     * @type {string | Object | ArrayBuffer}
     * @crossplatform
     * @since 6
     */
    extraData?: string | Object | ArrayBuffer;

    /**
     * Data type to be returned. If this parameter is set, the system preferentially returns the specified type.
     * @type {HttpDataType}
     * @crossplatform
     * @since 9
     */
    expectDataType?: HttpDataType;

    /**
     * default is true
     * @type {boolean}
     * @crossplatform
     * @since 9
     */
    usingCache?: boolean;

    /**
     * [1, 1000], default is 1.
     * @type {number}
     * @crossplatform
     * @since 9
     */
    priority?: number; 

    /**
     * HTTP request header. default is 'content-type': 'application/json'
     * @type {Object}
     * @crossplatform
     * @since 6
     */
    header?: Object;

    /**
     * Read timeout period. The default value is 60,000, in ms.
     * @type {number}
     * @crossplatform
     * @since 6
     */
    readTimeout?: number;

    /**
     * Connection timeout interval. The default value is 60,000, in ms.
     * @type {number}
     * @crossplatform
     * @since 6
     */
    connectTimeout?: number;

    /**
     * default is automatically specified by the system.
     * @type {HttpProtocol}
     * @crossplatform
     * @since 9
     */
    usingProtocol?: HttpProtocol;
    /**
     * If this parameter is set as type of boolean, the system will use default proxy or not use proxy.
     * If this parameter is set as type of HttpProxy, the system will use the specified HttpProxy.
     * @type {boolean | HttpProxy}
     * @since 10
     */
    usingProxy?: boolean | HttpProxy;

    /**
     * If this parameter is set, the system will use ca path specified by user, or else use preset ca by the system. 
     * @type {string}
     * @since 10
     */
    caPath?: string;
  }

  /**
   * <p>Defines an HTTP request task. Before invoking APIs provided by HttpRequest,
   * you must call createHttp() to create an HttpRequestTask object.</p>
   * @interface HttpRequest
   * @syscap SystemCapability.Communication.NetStack
   * @since 6
   */
  export interface HttpRequest {
    /**
     * Initiates an HTTP request to a given URL.
     * @param { string } url URL for initiating an HTTP request.
     * @param { AsyncCallback<HttpResponse> } callback - the callback of request.
     * @permission ohos.permission.INTERNET
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 2300001 - Unsupported protocol.
     * @throws { BusinessError } 2300003 - URL using bad/illegal format or missing URL.
     * @throws { BusinessError } 2300005 - Couldn't resolve proxy name.
     * @throws { BusinessError } 2300006 - Couldn't resolve host name.
     * @throws { BusinessError } 2300007 - Couldn't connect to server.
     * @throws { BusinessError } 2300008 - Weird server reply.
     * @throws { BusinessError } 2300009 - Access denied to remote resource.
     * @throws { BusinessError } 2300016 - Error in the HTTP2 framing layer.
     * @throws { BusinessError } 2300018 - Transferred a partial file.
     * @throws { BusinessError } 2300023 - Failed writing received data to disk/application.
     * @throws { BusinessError } 2300025 - Upload failed.
     * @throws { BusinessError } 2300026 - Failed to open/read local data from file/application.
     * @throws { BusinessError } 2300027 - Out of memory.
     * @throws { BusinessError } 2300028 - Timeout was reached.
     * @throws { BusinessError } 2300047 - Number of redirects hit maximum amount.
     * @throws { BusinessError } 2300052 - Server returned nothing (no headers, no data).
     * @throws { BusinessError } 2300055 - Failed sending data to the peer.
     * @throws { BusinessError } 2300056 - Failure when receiving data from the peer.
     * @throws { BusinessError } 2300058 - Problem with the local SSL certificate.
     * @throws { BusinessError } 2300059 - Couldn't use specified SSL cipher.
     * @throws { BusinessError } 2300060 - SSL peer certificate or SSH remote key was not OK.
     * @throws { BusinessError } 2300061 - Unrecognized or bad HTTP Content or Transfer-Encoding.
     * @throws { BusinessError } 2300063 - Maximum file size exceeded.
     * @throws { BusinessError } 2300070 - Disk full or allocation exceeded.
     * @throws { BusinessError } 2300073 - Remote file already exists.
     * @throws { BusinessError } 2300077 - Problem with the SSL CA cert (path? access rights?).
     * @throws { BusinessError } 2300078 - Remote file not found.
     * @throws { BusinessError } 2300094 - An authentication function returned an error.
     * @throws { BusinessError } 2300999 - Unknown Other Error.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 6
     */
    request(url: string, callback: AsyncCallback<HttpResponse>): void;

    /**
     * Initiates an HTTP request to a given URL.
     * @param { string } url URL for initiating an HTTP request.
     * @param { HttpRequestOptions } options Optional parameters {@link HttpRequestOptions}.
     * @param { AsyncCallback<HttpResponse> } callback callback - the callback of request..
     * @permission ohos.permission.INTERNET
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 2300001 - Unsupported protocol.
     * @throws { BusinessError } 2300003 - URL using bad/illegal format or missing URL.
     * @throws { BusinessError } 2300005 - Couldn't resolve proxy name.
     * @throws { BusinessError } 2300006 - Couldn't resolve host name.
     * @throws { BusinessError } 2300007 - Couldn't connect to server.
     * @throws { BusinessError } 2300008 - Weird server reply.
     * @throws { BusinessError } 2300009 - Access denied to remote resource.
     * @throws { BusinessError } 2300016 - Error in the HTTP2 framing layer.
     * @throws { BusinessError } 2300018 - Transferred a partial file.
     * @throws { BusinessError } 2300023 - Failed writing received data to disk/application.
     * @throws { BusinessError } 2300025 - Upload failed.
     * @throws { BusinessError } 2300026 - Failed to open/read local data from file/application.
     * @throws { BusinessError } 2300027 - Out of memory.
     * @throws { BusinessError } 2300028 - Timeout was reached.
     * @throws { BusinessError } 2300047 - Number of redirects hit maximum amount.
     * @throws { BusinessError } 2300052 - Server returned nothing (no headers, no data).
     * @throws { BusinessError } 2300055 - Failed sending data to the peer.
     * @throws { BusinessError } 2300056 - Failure when receiving data from the peer.
     * @throws { BusinessError } 2300058 - Problem with the local SSL certificate.
     * @throws { BusinessError } 2300059 - Couldn't use specified SSL cipher.
     * @throws { BusinessError } 2300060 - SSL peer certificate or SSH remote key was not OK.
     * @throws { BusinessError } 2300061 - Unrecognized or bad HTTP Content or Transfer-Encoding.
     * @throws { BusinessError } 2300063 - Maximum file size exceeded.
     * @throws { BusinessError } 2300070 - Disk full or allocation exceeded.
     * @throws { BusinessError } 2300073 - Remote file already exists.
     * @throws { BusinessError } 2300077 - Problem with the SSL CA cert (path? access rights?).
     * @throws { BusinessError } 2300078 - Remote file not found.
     * @throws { BusinessError } 2300094 - An authentication function returned an error.
     * @throws { BusinessError } 2300999 - Unknown Other Error.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 6
     */
    request(url: string, options: HttpRequestOptions, callback: AsyncCallback<HttpResponse>): void;

    /**
     * Initiates an HTTP request to a given URL.
     * @param { string } url URL for initiating an HTTP request.
     * @param { HttpRequestOptions } options Optional parameters {@link HttpRequestOptions}.
     * @returns { Promise<HttpResponse> } The promise returned by the function.
     * @permission ohos.permission.INTERNET
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 2300001 - Unsupported protocol.
     * @throws { BusinessError } 2300003 - URL using bad/illegal format or missing URL.
     * @throws { BusinessError } 2300005 - Couldn't resolve proxy name.
     * @throws { BusinessError } 2300006 - Couldn't resolve host name.
     * @throws { BusinessError } 2300007 - Couldn't connect to server.
     * @throws { BusinessError } 2300008 - Weird server reply.
     * @throws { BusinessError } 2300009 - Access denied to remote resource.
     * @throws { BusinessError } 2300016 - Error in the HTTP2 framing layer.
     * @throws { BusinessError } 2300018 - Transferred a partial file.
     * @throws { BusinessError } 2300023 - Failed writing received data to disk/application.
     * @throws { BusinessError } 2300025 - Upload failed.
     * @throws { BusinessError } 2300026 - Failed to open/read local data from file/application.
     * @throws { BusinessError } 2300027 - Out of memory.
     * @throws { BusinessError } 2300028 - Timeout was reached.
     * @throws { BusinessError } 2300047 - Number of redirects hit maximum amount.
     * @throws { BusinessError } 2300052 - Server returned nothing (no headers, no data).
     * @throws { BusinessError } 2300055 - Failed sending data to the peer.
     * @throws { BusinessError } 2300056 - Failure when receiving data from the peer.
     * @throws { BusinessError } 2300058 - Problem with the local SSL certificate.
     * @throws { BusinessError } 2300059 - Couldn't use specified SSL cipher.
     * @throws { BusinessError } 2300060 - SSL peer certificate or SSH remote key was not OK.
     * @throws { BusinessError } 2300061 - Unrecognized or bad HTTP Content or Transfer-Encoding.
     * @throws { BusinessError } 2300063 - Maximum file size exceeded.
     * @throws { BusinessError } 2300070 - Disk full or allocation exceeded.
     * @throws { BusinessError } 2300073 - Remote file already exists.
     * @throws { BusinessError } 2300077 - Problem with the SSL CA cert (path? access rights?).
     * @throws { BusinessError } 2300078 - Remote file not found.
     * @throws { BusinessError } 2300094 - An authentication function returned an error.
     * @throws { BusinessError } 2300999 - Unknown Other Error.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 6
     */
    request(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;

    /**
     * Initiates an HTTP request to a given URL, applicable to scenarios where http response supports streaming.
     * @param { string } url URL for initiating an HTTP request.
     * <p>@param { AsyncCallback<number> } callback Returns the callback of requestInStream {@link ResponseCode},
     * should use on_headersReceive and on_dataReceive to get http response.</p>
     * @permission ohos.permission.INTERNET
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 2300001 - Unsupported protocol.
     * @throws { BusinessError } 2300003 - URL using bad/illegal format or missing URL.
     * @throws { BusinessError } 2300005 - Couldn't resolve proxy name.
     * @throws { BusinessError } 2300006 - Couldn't resolve host name.
     * @throws { BusinessError } 2300007 - Couldn't connect to server.
     * @throws { BusinessError } 2300008 - Weird server reply.
     * @throws { BusinessError } 2300009 - Access denied to remote resource.
     * @throws { BusinessError } 2300016 - Error in the HTTP2 framing layer.
     * @throws { BusinessError } 2300018 - Transferred a partial file.
     * @throws { BusinessError } 2300023 - Failed writing received data to disk/application.
     * @throws { BusinessError } 2300025 - Upload failed.
     * @throws { BusinessError } 2300026 - Failed to open/read local data from file/application.
     * @throws { BusinessError } 2300027 - Out of memory.
     * @throws { BusinessError } 2300028 - Timeout was reached.
     * @throws { BusinessError } 2300047 - Number of redirects hit maximum amount.
     * @throws { BusinessError } 2300052 - Server returned nothing (no headers, no data).
     * @throws { BusinessError } 2300055 - Failed sending data to the peer.
     * @throws { BusinessError } 2300056 - Failure when receiving data from the peer.
     * @throws { BusinessError } 2300058 - Problem with the local SSL certificate.
     * @throws { BusinessError } 2300059 - Couldn't use specified SSL cipher.
     * @throws { BusinessError } 2300060 - SSL peer certificate or SSH remote key was not OK.
     * @throws { BusinessError } 2300061 - Unrecognized or bad HTTP Content or Transfer-Encoding.
     * @throws { BusinessError } 2300063 - Maximum file size exceeded.
     * @throws { BusinessError } 2300070 - Disk full or allocation exceeded.
     * @throws { BusinessError } 2300073 - Remote file already exists.
     * @throws { BusinessError } 2300077 - Problem with the SSL CA cert (path? access rights?).
     * @throws { BusinessError } 2300078 - Remote file not found.
     * @throws { BusinessError } 2300094 - An authentication function returned an error.
     * @throws { BusinessError } 2300999 - Unknown Other Error.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    requestInStream(url: string, callback: AsyncCallback<number>): void;

    /**
     * Initiates an HTTP request to a given URL, applicable to scenarios where http response supports streaming.
     * @param { string } url URL for initiating an HTTP request.
     * @param { HttpRequestOptions } options Optional parameters {@link HttpRequestOptions}.
     * @param { AsyncCallback<number> } callback - the callback of requestInStream.
     * @permission ohos.permission.INTERNET
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 2300001 - Unsupported protocol.
     * @throws { BusinessError } 2300003 - URL using bad/illegal format or missing URL.
     * @throws { BusinessError } 2300005 - Couldn't resolve proxy name.
     * @throws { BusinessError } 2300006 - Couldn't resolve host name.
     * @throws { BusinessError } 2300007 - Couldn't connect to server.
     * @throws { BusinessError } 2300008 - Weird server reply.
     * @throws { BusinessError } 2300009 - Access denied to remote resource.
     * @throws { BusinessError } 2300016 - Error in the HTTP2 framing layer.
     * @throws { BusinessError } 2300018 - Transferred a partial file.
     * @throws { BusinessError } 2300023 - Failed writing received data to disk/application.
     * @throws { BusinessError } 2300025 - Upload failed.
     * @throws { BusinessError } 2300026 - Failed to open/read local data from file/application.
     * @throws { BusinessError } 2300027 - Out of memory.
     * @throws { BusinessError } 2300028 - Timeout was reached.
     * @throws { BusinessError } 2300047 - Number of redirects hit maximum amount.
     * @throws { BusinessError } 2300052 - Server returned nothing (no headers, no data).
     * @throws { BusinessError } 2300055 - Failed sending data to the peer.
     * @throws { BusinessError } 2300056 - Failure when receiving data from the peer.
     * @throws { BusinessError } 2300058 - Problem with the local SSL certificate.
     * @throws { BusinessError } 2300059 - Couldn't use specified SSL cipher.
     * @throws { BusinessError } 2300060 - SSL peer certificate or SSH remote key was not OK.
     * @throws { BusinessError } 2300061 - Unrecognized or bad HTTP Content or Transfer-Encoding.
     * @throws { BusinessError } 2300063 - Maximum file size exceeded.
     * @throws { BusinessError } 2300070 - Disk full or allocation exceeded.
     * @throws { BusinessError } 2300073 - Remote file already exists.
     * @throws { BusinessError } 2300077 - Problem with the SSL CA cert (path? access rights?).
     * @throws { BusinessError } 2300078 - Remote file not found.
     * @throws { BusinessError } 2300094 - An authentication function returned an error.
     * @throws { BusinessError } 2300999 - Unknown Other Error.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    requestInStream(url: string, options: HttpRequestOptions, callback: AsyncCallback<number>): void;

    /**
     * Initiates an HTTP request to a given URL, applicable to scenarios where http response supports streaming.
     * @param { string } url URL for initiating an HTTP request.
     * @param { HttpRequestOptions } options Optional parameters {@link HttpRequestOptions}.
     * @returns { Promise<number> } the promise returned by the function.
     * @permission ohos.permission.INTERNET
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 2300001 - Unsupported protocol.
     * @throws { BusinessError } 2300003 - URL using bad/illegal format or missing URL.
     * @throws { BusinessError } 2300005 - Couldn't resolve proxy name.
     * @throws { BusinessError } 2300006 - Couldn't resolve host name.
     * @throws { BusinessError } 2300007 - Couldn't connect to server.
     * @throws { BusinessError } 2300008 - Weird server reply.
     * @throws { BusinessError } 2300009 - Access denied to remote resource.
     * @throws { BusinessError } 2300016 - Error in the HTTP2 framing layer.
     * @throws { BusinessError } 2300018 - Transferred a partial file.
     * @throws { BusinessError } 2300023 - Failed writing received data to disk/application.
     * @throws { BusinessError } 2300025 - Upload failed.
     * @throws { BusinessError } 2300026 - Failed to open/read local data from file/application.
     * @throws { BusinessError } 2300027 - Out of memory.
     * @throws { BusinessError } 2300028 - Timeout was reached.
     * @throws { BusinessError } 2300047 - Number of redirects hit maximum amount.
     * @throws { BusinessError } 2300052 - Server returned nothing (no headers, no data).
     * @throws { BusinessError } 2300055 - Failed sending data to the peer.
     * @throws { BusinessError } 2300056 - Failure when receiving data from the peer.
     * @throws { BusinessError } 2300058 - Problem with the local SSL certificate.
     * @throws { BusinessError } 2300059 - Couldn't use specified SSL cipher.
     * @throws { BusinessError } 2300060 - SSL peer certificate or SSH remote key was not OK.
     * @throws { BusinessError } 2300061 - Unrecognized or bad HTTP Content or Transfer-Encoding.
     * @throws { BusinessError } 2300063 - Maximum file size exceeded.
     * @throws { BusinessError } 2300070 - Disk full or allocation exceeded.
     * @throws { BusinessError } 2300073 - Remote file already exists.
     * @throws { BusinessError } 2300077 - Problem with the SSL CA cert (path? access rights?).
     * @throws { BusinessError } 2300078 - Remote file not found.
     * @throws { BusinessError } 2300094 - An authentication function returned an error.
     * @throws { BusinessError } 2300999 - Unknown Other Error.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    requestInStream(url: string, options?: HttpRequestOptions): Promise<number>;

    /**
     * Destroys an HTTP request.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     */
    destroy(): void;

    /**
     * Registers an observer for HTTP Response Header events.
     * @param { string } type Indicates Event name.
     * @param { AsyncCallback<Object> } callback - the callback of on.
     * @syscap SystemCapability.Communication.NetStack
     * @deprecated since 8
     * @useinstead on_headersReceive
     */
    on(type: 'headerReceive', callback: AsyncCallback<Object>): void;

    /**
     * Unregisters the observer for HTTP Response Header events.
     * @param { string } type Indicates Event name.
     * @param { AsyncCallback<Object> } callback - the callback of off.
     * @syscap SystemCapability.Communication.NetStack
     * @deprecated since 8
     * @useinstead off_headersReceive
     */
    off(type: 'headerReceive', callback?: AsyncCallback<Object>): void;

    /**
     * Registers an observer for HTTP Response Header events.
     * @param { string } type Indicates Event name.
     * @param { Callback<Object> } callback - the callback of on.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 8
     */
    on(type: 'headersReceive', callback: Callback<Object>): void;

    /**
     * Unregisters the observer for HTTP Response Header events.
     * @param { string } type Indicates Event name.
     * @param { Callback<Object> } callback - the callback of off.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 8
     */
    off(type: 'headersReceive', callback?: Callback<Object>): void;

    /**
     * Registers a one-time observer for HTTP Response Header events.
     * @param { string } type Indicates Event name.
     * @param { Callback<Object> } callback - the callback of once.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 8
     */
    once(type: 'headersReceive', callback: Callback<Object>): void;

    /**
     * Registers an observer for receiving HTTP Response data events continuously.
     * @param { string } type Indicates Event name.
     * @param { Callback<ArrayBuffer> } callback - the callback of on.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    on(type: 'dataReceive', callback: Callback<ArrayBuffer>): void;

    /**
     * Unregisters an observer for receiving HTTP Response data events continuously.
     * @param { string } type Indicates Event name.
     * @param { Callback<ArrayBuffer> } callback - the callback of off.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    off(type: 'dataReceive', callback?: Callback<ArrayBuffer>): void;

    /**
     * Registers an observer for receiving HTTP Response data ends events.
     * @param { string } type Indicates Event name.
     * @param { Callback<void> } callback - the callback of on.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    on(type: 'dataEnd', callback: Callback<void>): void;

    /**
     * Unregisters an observer for receiving HTTP Response data ends events.
     * @param { string } type Indicates Event name.
     * @param { Callback<void> } callback - the callback of off.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    off(type: 'dataEnd', callback?: Callback<void>): void;

    /**
     * Registers an observer for progress of receiving HTTP Response data events.
     * @param { string } type Indicates Event name.
     * @param { Callback<{ receiveSize: number, totalSize: number }> } callback - the callback of on.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    on(type: 'dataReceiveProgress', callback: Callback<{ receiveSize: number, totalSize: number }>): void;

    /**
     * Unregisters an observer for progress of receiving HTTP Response data events.
     * @param { string } type Indicates Event name.
     * @param { Callback<{ receiveSize: number, totalSize: number }> } callback - the callback of off.
     * @syscap SystemCapability.Communication.NetStack
     * @since 10
     */
    off(type: 'dataReceiveProgress', callback?: Callback<{ receiveSize: number, totalSize: number }>): void;
  }

  /**
   * Defines an HTTP request method.
   * @enum {string}
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 6
   */
  export enum RequestMethod {
    /**
     * OPTIONS method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    OPTIONS = "OPTIONS",

    /**
     * GET method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    GET = "GET",

    /**
     * HEAD method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    HEAD = "HEAD",

    /**
     * POST method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    POST = "POST",

    /**
     * PUT method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    PUT = "PUT",

    /**
     * DELETE method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    DELETE = "DELETE",

    /**
     * TRACE method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    TRACE = "TRACE",

    /**
     * CONNECT method.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    CONNECT = "CONNECT"
  }

  /**
   * Enumerates the response codes for an HTTP request.
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 6
   */
  export enum ResponseCode {
    /**
     * The request was successful. Typically used for GET and POST requests.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    OK = 200,

    /**
     * Successfully requested and created a new resource.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */

    CREATED,

    /**
     * The request has been accepted but has not been processed completely.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    ACCEPTED,

    /**
     * Unauthorized information. The request was successful.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    NOT_AUTHORITATIVE,

    /**
     * No content. The server successfully processed, but did not return content.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    NO_CONTENT,

    /**
     * Reset the content.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    RESET,

    /**
     * Partial content. The server successfully processed some GET requests.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    PARTIAL,

    /**
     * Multiple options.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    MULT_CHOICE = 300,

    /**
     * <p>Permanently move. The requested resource has been permanently moved to a new URI,
     * and the returned information will include the new URI. The browser will automatically redirect to the new URI.</p>
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    MOVED_PERM,

    /**
     * Temporary movement.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    MOVED_TEMP,

    /**
     * View other addresses.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    SEE_OTHER,

    /**
     * Not modified.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    NOT_MODIFIED,

    /**
     * Using proxies.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    USE_PROXY,

    /**
     * The server cannot understand the syntax error error requested by the client.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    BAD_REQUEST = 400,

    /**
     * Request for user authentication.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    UNAUTHORIZED,

    /**
     * Reserved for future use.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    PAYMENT_REQUIRED,

    /**
     * The server understands the request from the requesting client, but refuses to execute it.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    FORBIDDEN,

    /**
     * The server was unable to find resources (web pages) based on the client's request.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    NOT_FOUND,

    /**
     * The method in the client request is prohibited.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    BAD_METHOD,

    /**
     * The server is unable to complete the request based on the content characteristics requested by the client.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    NOT_ACCEPTABLE,

    /**
     * Request authentication of the proxy's identity.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    PROXY_AUTH,

    /**
     * The request took too long and timed out.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    CLIENT_TIMEOUT,
    /**
     * <p>The server may have returned this code when completing the client's PUT request,
     * as there was a conflict when the server was processing the request.</p>
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    CONFLICT,

    /**
     * The resource requested by the client no longer exists.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    GONE,

    /**
     * The server is unable to process request information sent by the client without Content Length.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    LENGTH_REQUIRED,

    /**
     * The prerequisite for requesting information from the client is incorrect.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    PRECON_FAILED,

    /**
     * The request was rejected because the requested entity was too large for the server to process.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    ENTITY_TOO_LARGE,

    /**
     * The requested URI is too long (usually a URL) and the server cannot process it.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    REQ_TOO_LONG,

    /**
     * The server is unable to process the requested format.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    UNSUPPORTED_TYPE,

    /**
     * Internal server error, unable to complete the request.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    INTERNAL_ERROR = 500,

    /**
     * The server does not support the requested functionality and cannot complete the request.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    NOT_IMPLEMENTED,

    /**
     * The server acting as a gateway or proxy received an invalid request from the remote server.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    BAD_GATEWAY,

    /**
     * Due to overload or system maintenance, the server is temporarily unable to process client requests.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    UNAVAILABLE,

    /**
     * The server acting as a gateway or proxy did not obtain requests from the remote server in a timely manner.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    GATEWAY_TIMEOUT,

    /**
     * The version of the HTTP protocol requested by the server.
     * @syscap SystemCapability.Communication.NetStack
     * @since 6
     */
    VERSION
  }

  /**
   * Supported protocols.
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 9
   */
  export enum HttpProtocol {
    /**
     * Protocol http1.1
     * @syscap SystemCapability.Communication.NetStack
     * @since 9
     */
    HTTP1_1,

    /**
     * Protocol http2
     * @syscap SystemCapability.Communication.NetStack
     * @since 9
     */
    HTTP2,
  }

  /**
   * Indicates the type of the returned data.
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 9
   */
  export enum HttpDataType {
    /**
     * The returned type is string.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 6
     */
    STRING,
    /**
     * The returned type is Object.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 6
     */
    OBJECT = 1,
    /**
     * The returned type is ArrayBuffer.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 6
     */
    ARRAY_BUFFER = 2,
  }

  /**
   * Defines the response to an HTTP request.
   * @interface HttpResponse
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 6
   */
  export interface HttpResponse {
    /**
     * result can be a string (API 6) or an ArrayBuffer(API 8). Object is deprecated from API 8.
     * If {@link HttpRequestOptions#expectDataType} is set, the system preferentially returns this parameter.
     * @type {string | Object | ArrayBuffer}
     * @crossplatform
     * @since 6
     */
    result: string | Object | ArrayBuffer;

    /**
     * If the resultType is string, you can get result directly.
     * If the resultType is Object, you can get result such as this: result['key'].
     * If the resultType is ArrayBuffer, you can use ArrayBuffer to create the binary objects.
     * @type {HttpDataType}
     * @crossplatform
     * @since 9
     */
    resultType: HttpDataType;

    /**
     * Server status code.
     * @type {ResponseCode | number}
     * @crossplatform
     * @since 6
     */
    responseCode: ResponseCode | number;

    /**
     * All headers in the response from the server.
     * @type {Object}
     * @crossplatform
     * @since 6
     */
    header: Object;

    /**
     * Cookies returned by the server.
     * @type {string}
     * @crossplatform
     * @since 8
     */
    cookies: string;
  }

  /**
   * Creates a default {@code HttpResponseCache} object to store the responses of HTTP access requests.
   * @param { number } cacheSize the size of cache(max value is 10MB), default is 10*1024*1024(10MB).
   * @returns { HttpResponseCache } the HttpResponseCache of the createHttpResponseCache.
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 9
   */
  function createHttpResponseCache(cacheSize?: number): HttpResponseCache;

  /**
   * Defines an object that stores the response to an HTTP request.
   * @interface HttpResponseCache
   * @syscap SystemCapability.Communication.NetStack
   * @crossplatform
   * @since 9
   */
  export interface HttpResponseCache {
    /**
     * Writes data in the cache to the file system so that all the cached data can be accessed in the next HTTP request.
     * @param { AsyncCallback<void> } callback Returns the callback of flush.
     * @systemapi Hide this for inner system use.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 9
     */
    flush(callback: AsyncCallback<void>): void;

    /**
     * Writes data in the cache to the file system so that all the cached data can be accessed in the next HTTP request.
     * @returns { Promise<void> } The promise returned by the flush.
     * @systemapi Hide this for inner system use.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 9
     */
    flush(): Promise<void>;

    /**
     * Disables a cache and deletes the data in it.
     * @param { AsyncCallback<void> } callback Returns the callback of delete.
     * @systemapi Hide this for inner system use.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 9
     */
    delete(callback: AsyncCallback<void>): void;

    /**
     * Disables a cache and deletes the data in it.
     * @returns { Promise<void> } The promise returned by the delete.
     * @systemapi Hide this for inner system use.
     * @syscap SystemCapability.Communication.NetStack
     * @crossplatform
     * @since 9
     */
    delete(): Promise<void>;
  }
}

export default http;