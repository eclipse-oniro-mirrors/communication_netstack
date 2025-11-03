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


import type { AsyncCallback, Callback } from '@ohos.base';
import type connection from '@ohos.net.connection';
import { BusinessError, RecordData }  from '@ohos.base';

export default namespace http {
  loadLibrary("http_ani")
  export type HttpProxy = connection.HttpProxy;

  class Cleaner {
    private nativePtr: long = 0
    constructor(nativePtr:long) {
        this.nativePtr = nativePtr
    }
    native cleanHttp(): void
    native cleanCache(): void
  }

  let httpRequestDestroyRegister = new FinalizationRegistry<Cleaner>((cleaner: Cleaner) => {cleaner.cleanHttp()})
  let httpResponseCacheDestroyRegister = new FinalizationRegistry<Cleaner>((cleaner: Cleaner) => {cleaner.cleanCache()})

  let unregisterToken = new object()

  export native function createHttpPtr(): long;

  export function createHttp(): HttpRequest {
    let ptr = createHttpPtr();
    return new HttpRequestInner(ptr);
  }

  export enum AddressFamily {
    DEFAULT = 'CURL_IPRESOLVE_WHATEVER',

    ONLY_V4 = 'CURL_IPRESOLVE_V4',

    ONLY_V6 = 'CURL_IPRESOLVE_V6'
  }

  export interface HttpRequestOptions {
    method?: RequestMethod;

    extraData?: string | Object | ArrayBuffer;

    expectDataType?: HttpDataType;

    usingCache?: boolean;

    priority?: int;

    header?: Object;

    readTimeout?: int;

    connectTimeout?: int;

    usingProtocol?: HttpProtocol;

    usingProxy?: boolean | HttpProxy;

    caPath?: string;

    resumeFrom?: long;

    resumeTo?: long;

    clientCert?: ClientCert;

    dnsOverHttps?: string;

    dnsServers?: Array<string>;

    maxLimit?: int;

    multiFormDataList?: Array<MultiFormData>;

    certificatePinning?: CertificatePinning | CertificatePinning[];

    remoteValidation?: RemoteValidation;

    tlsOptions?: TlsOptions;

    serverAuthentication?: ServerAuthentication;

    addressFamily?: AddressFamily;
  }

  export interface ServerAuthentication {
    credential: Credential;

    authenticationType?: AuthenticationType;
  }

  class ServerAuthenticationInner implements ServerAuthentication {
    credential: Credential;

    authenticationType?: AuthenticationType;
  }

  export type TlsOptions = 'system' | TlsConfig;

  export type RemoteValidation = 'system' | 'skip';

  export type AuthenticationType = 'basic' | 'ntlm' | 'digest';

  export interface Credential {
    username: string;

    password: string;
  }

  class CredentialInner implements Credential {
    username: string;

    password: string;
  }

  export interface TlsConfig {
    tlsVersionMin: TlsVersion;

    tlsVersionMax: TlsVersion;

    cipherSuites?: CipherSuite[];
  }

  export class TlsConfigInner implements TlsConfig {
    tlsVersionMin: TlsVersion;

    tlsVersionMax: TlsVersion;

    cipherSuites?: CipherSuite[];
  }

  export type TlsV13SpecificCipherSuite = 'TLS_AES_128_GCM_SHA256' | 'TLS_AES_256_GCM_SHA384' | 'TLS_CHACHA20_POLY1305_SHA256';

  export type TlsV12SpecificCipherSuite = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' | 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' | 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384' | 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' | 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256' | 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256' | 'TLS_RSA_WITH_AES_128_GCM_SHA256' | 'TLS_RSA_WITH_AES_256_GCM_SHA384';

  export type TlsV10SpecificCipherSuite = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA' | 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA' | 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA' | 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA' | 'TLS_RSA_WITH_AES_128_CBC_SHA' | 'TLS_RSA_WITH_AES_256_CBC_SHA' | 'TLS_RSA_WITH_3DES_EDE_CBC_SHA';

  export type CipherSuite = TlsV13CipherSuite;

  export type TlsV13CipherSuite = TlsV12CipherSuite | TlsV13SpecificCipherSuite;

  export type TlsV12CipherSuite = TlsV11CipherSuite | TlsV12SpecificCipherSuite;

  export type TlsV11CipherSuite = TlsV10CipherSuite;

  export type TlsV10CipherSuite = TlsV10SpecificCipherSuite;

  export enum TlsVersion {
    TLS_V_1_0 = 4,

    TLS_V_1_1 = 5,

    TLS_V_1_2 = 6,

    TLS_V_1_3 = 7
  }

  export interface MultiFormData {
    name: string;

    contentType: string;

    remoteFileName?: string;

    data?: string | Object | ArrayBuffer;

    filePath?: string;
  }

  class MultiFormDataInner implements MultiFormData {
    name: string;

    contentType: string;

    remoteFileName?: string;

    data?: string | Object | ArrayBuffer;

    filePath?: string;
  }

  export enum CertType {
    PEM = 'PEM',

    DER = 'DER',

    P12 = 'P12'
  }

  export interface ClientCert {
    certPath: string;

    certType?: CertType;

    keyPath: string;

    keyPassword?: string;
  }

  class ClientCertInner implements ClientCert {
    certPath: string;

    certType?: CertType;

    keyPath: string;

    keyPassword?: string;
  }

  interface CertificatePinning {
    publicKeyHash: string;
    hashAlgorithm: 'SHA-256';
  }

  export interface HttpRequest {
    request(url: string, callback: AsyncCallback<HttpResponse>): void;

    request(url: string, options: HttpRequestOptions, callback: AsyncCallback<HttpResponse>): void;

    request(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;

    requestInStream(url: string, callback: AsyncCallback<int>): void;

    requestInStream(url: string, options: HttpRequestOptions, callback: AsyncCallback<int>): void;

    requestInStream(url: string, options?: HttpRequestOptions): Promise<int>;

    destroy(): void;

    on(type: "headerReceive" | "headersReceive" | "dataReceive" | "dataEnd" | 'dataReceiveProgress' | 'dataSendProgress', callback: Object): void ;

    off(type: "headerReceive" | "headersReceive" | "dataReceive" | "dataEnd" | 'dataReceiveProgress' | 'dataSendProgress', callback?: Object): void;

    once(type: "headersReceive", callback: Callback<Object>): void;
  }

  export class HttpRequestInner implements HttpRequest {
    private  nativePtr:long = 0;
    private cleaner: Cleaner | null = null;

    constructor(context:long) {
        if(this.nativePtr == 0){
             this.nativePtr = context;
        }
        this.registerCleaner(this.nativePtr)
    }

    registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
      httpRequestDestroyRegister.register(this, this.cleaner!, unregisterToken);
    }
    unregisterCleaner(): void {
        httpRequestDestroyRegister.unregister(unregisterToken);
    }

    native requestInner(url: string, callback: AsyncCallback<HttpResponse>, options?: HttpRequestOptions): void;

    request(url: string, callback: AsyncCallback<HttpResponse>): void {
      this.requestInner(url, callback);
    }

    request(url: string, options: HttpRequestOptions, callback: AsyncCallback<HttpResponse>): void {
      this.requestInner(url, callback,  options);
    }

    request(url: string, options?: HttpRequestOptions): Promise<HttpResponse> {
      return new Promise<HttpResponse>((resolve, reject) => {
        this.requestInner(url,  (err: BusinessError | null, data: HttpResponse| undefined) => {
          if (err?.code != 0) {
            reject(err as BusinessError);
          } else {
            resolve(data as HttpResponse);
          }
        }, options);
      });
    }

    native requestInStreamInner(url: string, callback: AsyncCallback<int>, options?: HttpRequestOptions): void;

    requestInStream(url: string, callback: AsyncCallback<int>): void {
      this.requestInStreamInner(url, callback);
    }

    requestInStream(url: string, options: HttpRequestOptions, callback: AsyncCallback<int>): void {
      this.requestInStreamInner(url, callback, options);
    }

    requestInStream(url: string, options?: HttpRequestOptions): Promise<int> {
      return new Promise<int>((resolve, reject) => {
        this.requestInStreamInner(url, (err: BusinessError | null, data: int | undefined) => {
          if (err?.code != 0) {
            reject(err as BusinessError);
          } else {
            resolve(data as int);
          }
        }, options);
      });
    }

    native destroy(): void;

    native onHeaderReceive(callback: AsyncCallback<String>): void;
    native onHeadersReceive(callback:  Callback<Record<String, String>>): void;
    native onDataReceive(callback: Callback<ArrayBuffer>): void;
    native onDataEnd(callback: Callback<void>): void;
    native onDataReceiveProgress(callback: Callback<DataReceiveProgressInfo>): void;
    native onDataSendProgress(callback: Callback<DataSendProgressInfo>): void;

    native offHeaderReceive(callback?: AsyncCallback<Record<String, String>>): void;
    native offHeadersReceive(callback?:  Callback<Record<String, String>>): void;
    native offDataReceive(callback?: Callback<ArrayBuffer>): void;
    native offDataEnd(callback?: Callback<void>): void;
    native offDataReceiveProgress(callback?: Callback<DataReceiveProgressInfo>): void;
    native offDataSendProgress(callback?: Callback<DataSendProgressInfo>): void;

    on(type: 'headerReceive' | 'headersReceive' | 'dataReceive' | 'dataEnd' | 'dataReceiveProgress' | 'dataSendProgress', callback: Object): void {
      if (type == 'headerReceive') {
        this.onHeaderReceive(callback as AsyncCallback<String>)
      } else if (type == 'headersReceive') {
        this.onHeadersReceive(callback as Callback<Record<String, String>>)
      } else if (type == 'dataReceive') {
        this.onDataReceive(callback as Callback<ArrayBuffer>)
      } else if (type == 'dataEnd') {
        this.onDataEnd(callback as Callback<void>)
      } else if (type == 'dataReceiveProgress') {
        this.onDataReceiveProgress(callback as Callback<DataReceiveProgressInfo>)
      } else if (type == 'dataSendProgress') {
        this.onDataSendProgress(callback as Callback<DataSendProgressInfo>)
      }
    }

    off(type: "headerReceive" | "headersReceive" | "dataReceive" | "dataEnd" | 'dataReceiveProgress' | 'dataSendProgress', callback?: Object): void {
      if (type == 'headerReceive') {
        if (callback === undefined) {
          this.offHeaderReceive()
        } else {
          this.offHeaderReceive(callback as AsyncCallback<Record<String, String>>)
        }
      } else if (type == 'headersReceive') {
        if (callback === undefined) {
          this.offHeadersReceive()
        } else {
          this.offHeadersReceive(callback as Callback<Record<String, String>>)
        }
      } else if (type == 'dataReceive') {
        if (callback === undefined) {
          this.offDataReceive()
        } else {
          this.offDataReceive(callback as Callback<ArrayBuffer>)
        }
      } else if (type == 'dataEnd') {
        if (callback === undefined) {
          this.offDataEnd()
        } else {
          this.offDataEnd(callback as Callback<void>)
        }
      } else if (type == 'dataReceiveProgress') {
        if (callback === undefined) {
          this.offDataReceiveProgress()
        } else {
          this.offDataReceiveProgress(callback as Callback<DataReceiveProgressInfo>)
        }
      } else if (type == 'dataSendProgress') {
        if (callback === undefined) {
          this.offDataSendProgress()
        } else {
          this.offDataSendProgress(callback as Callback<DataSendProgressInfo>)
        }
      }
    }

    native once(type: "headersReceive", callback: Callback<Object>): void;
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

    RANGE_NOT_SATISFIABLE,

    INTERNAL_ERROR = 500,

    NOT_IMPLEMENTED,

    BAD_GATEWAY,

    UNAVAILABLE,

    GATEWAY_TIMEOUT,

    VERSION
  }


  export enum HttpProtocol {
    HTTP1_1,

    HTTP2,

    HTTP3
  }

  export enum HttpDataType {
    STRING,

    OBJECT = 1,

    ARRAY_BUFFER = 2
  }

  export interface HttpResponse {
    result: string | Object | ArrayBuffer;

    resultType: HttpDataType;

    responseCode: ResponseCode | int;

    header: Object;

    cookies: string;

    performanceTiming: PerformanceTiming;
  }

  class HttpResponseInner implements HttpResponse {
    result: string | Object | ArrayBuffer;

    resultType: HttpDataType;

    responseCode: ResponseCode | int;

    header: Object;

    cookies: string;

    performanceTiming: PerformanceTiming;
  }

  export interface PerformanceTiming {
    dnsTiming: double;

    tcpTiming: double;

    tlsTiming: double;

    firstSendTiming: double;

    firstReceiveTiming: double;

    totalFinishTiming: double;

    redirectTiming: double;

    responseHeaderTiming: double;

    responseBodyTiming: double;

    totalTiming: double;
  }

  class PerformanceTimingInner implements PerformanceTiming {
    dnsTiming: double;

    tcpTiming: double;

    tlsTiming: double;

    firstSendTiming: double;

    firstReceiveTiming: double;

    totalFinishTiming: double;

    redirectTiming: double;

    responseHeaderTiming: double;

    responseBodyTiming: double;

    totalTiming: double;
  }

  export interface DataReceiveProgressInfo {
    receiveSize: int;

    totalSize: int;
  }

  class DataReceiveProgressInfoInner implements DataReceiveProgressInfo {
    receiveSize: int;

    totalSize: int;
  }

  export interface DataSendProgressInfo {
    sendSize: int;

    totalSize: int;
  }

  class DataSendProgressInfoInner implements DataSendProgressInfo {
    sendSize: int;

    totalSize: int;
  }

  export native function createHttpResponseCache(cacheSize?: int): HttpResponseCache;

  export interface HttpResponseCache {
    flush(callback: AsyncCallback<void>): void;

    flush(): Promise<void>;

    delete(callback: AsyncCallback<void>): void;

    delete(): Promise<void>;
  }

  export class HttpResponseCacheInner implements HttpResponseCache {
    private  nativePtr:long = 0;
    private cleaner: Cleaner | null = null;

    constructor(context:long) {
        if(this.nativePtr == 0){
             this.nativePtr = context;
        }
        this.registerCleaner(this.nativePtr)
    }

    registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
      httpResponseCacheDestroyRegister.register(this, this.cleaner!, unregisterToken);
    }
    unregisterCleaner(): void {
        httpResponseCacheDestroyRegister.unregister(unregisterToken);
    }
    native flushSync(): void;

    flush(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(() => {
          this.flushSync();
      })
      p1.then(() => {
          callback(new BusinessError(), undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      });
    }

    flush(): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        taskpool.execute(() => {
            this.flushSync();
        }).then(() => {
            resolve(undefined);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native deleteSync():void;

    delete(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(() => {
          this.deleteSync();
      })
      p1.then(() => {
          callback(new BusinessError(), undefined);
      }, (err: Error): void => {
          callback(err as BusinessError, undefined);
      });
    }

    delete(): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        taskpool.execute(() => {
            this.deleteSync();
        }).then(() => {
            resolve(undefined);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }
  }
}
