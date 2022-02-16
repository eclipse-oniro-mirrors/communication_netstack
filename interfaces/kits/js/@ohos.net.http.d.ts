/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

/**
 * Provides http related APIs.
 *
 * @since 6
 * @sysCap SystemCapability.Communication.NetStack
 */
declare namespace http {
  function createHttp(): HttpRequest;

  export interface HttpRequestOptions {
    method?: RequestMethod; // default is GET
    /**
     * extraData can be a string or an Object (API 6) or an ArrayBuffer(API 8).
     */
    extraData?: string | Object | ArrayBuffer;
    header?: Object; // default is 'content-type': 'application/json'
    readTimeout?: number; // default is 60s
    connectTimeout?: number; // default is 60s.
    /**
     * @since 8
     */
    ifModifiedSince?: number; // "If-Modified-Since", default is 0.
    /**
     * @since 8
     */
    fixedLengthStreamingMode?: number; // default is -1 means disabled.
  }

  export interface HttpRequest {
    request(url: string, callback: AsyncCallback<HttpResponse>): void;
    request(url: string, options: HttpRequestOptions, callback: AsyncCallback<HttpResponse>): void;
    request(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;

    destroy(): void;

    /**
     * @deprecated use once() instead since 8.
     */
    on(type: "headerReceive", callback: AsyncCallback<Object>): void;
    /**
     * @since 8
     */
    once(type: "headerReceive", callback: Callback<Object>): void;
    /**
     * @deprecated use once() instead since 8.
     */
    off(type: "headerReceive", callback?: AsyncCallback<Object>): void;
  }

  export enum RequestMethod {
    OPTIONS = "OPTIONS",
    GET = "GET",
    HEAD = "HEAD",
    POST = "POST",
    PUT = "PUT",
    DELETE = "DELETE",
    TRACE = "TRACE",
    CONNECT = "CONNECT"
  }

  export enum ResponseCode {
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
    VERSION
  }

  export interface HttpResponse {
    /**
     * result can be a string or an Object (API 6) or an ArrayBuffer(API 8).
     */
    result: string | Object | ArrayBuffer;
    responseCode: ResponseCode | number;
    header: Object;
    /**
     * @since 8
     */
    cookies: string;
  }

  /**
   * Creates a default {@code HttpResponseCache} object to store the responses of HTTP access requests.
   *
   * @param options {@code HttpResponseCacheOptions}
   * @param callback the newly-installed cache
   * @since 8
   */
  function createHttpResponseCache(options: HttpResponseCacheOptions, callback: AsyncCallback<HttpResponseCache>): void;
  function createHttpResponseCache(options: HttpResponseCacheOptions): Promise<HttpResponseCache>;

  /**
   * Obtains the {@code HttpResponseCache} object.
   *
   * @param callback Returns the {@code HttpResponseCache} object.
   * @since 8
   */
  function getInstalledHttpResponseCache(callback: AsyncCallback<HttpResponseCache>): void;
  function getInstalledHttpResponseCache(): Promise<HttpResponseCache>;

  /**
   * @since 8
   */
  export interface HttpResponseCacheOptions {
    /**
     * Indicates the full directory for storing the cached data.
     */
    filePath: string;
    /**
     * Indicates the child directory for storing the cached data. It is an optional parameter.
     */
    fileChildPath?: string;
    /**
     * Indicates the maximum size of the cached data.
     */
    cacheSize: number;
  }

  /**
   * @since 8
   */
  export interface HttpResponseCache {
    /**
     * Writes data in the cache to the file system so that all the cached data can be accessed in the next HTTP request.
     */
    flush(callback: AsyncCallback<void>): void;
    flush(): Promise<void>;

    /**
     * Disables a cache without changing the data in it.
     */
    close(callback: AsyncCallback<void>): void;
    close(): Promise<void>;

    /**
     * Disables a cache and deletes the data in it.
     */
    delete(callback: AsyncCallback<void>): void;
    delete(): Promise<void>;
  }
}

export default http;