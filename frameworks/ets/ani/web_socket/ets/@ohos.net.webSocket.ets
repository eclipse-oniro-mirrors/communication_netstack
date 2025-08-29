/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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


import type { AsyncCallback, ErrorCallback, Callback } from '@ohos.base';
import type connection from '@ohos.net.connection';
import { BusinessError }  from '@ohos.base';

export default namespace webSocket {
  type HttpProxy = connection.HttpProxy;

  loadLibrary("websocket_ani");

  class Cleaner {
    private nativePtr: long = 0
    constructor(nativePtr:long) {
        this.nativePtr = nativePtr
    }
    native clean(): void
  }

  export native function createWebSocket(): WebSocket;

  let destroyRegister = new FinalizationRegistry<Cleaner>((cleaner: Cleaner) => {cleaner.clean()})
  let unregisterToken = new object()

  export interface WebSocketRequestOptions {
    header?: Record<string, string>;

    caPath?: string;

    clientCert?: ClientCert;

    proxy?: ProxyConfiguration;

    protocol?: string;
  }

  export class WebSocketRequestOptionsInner implements WebSocketRequestOptions {
    header?: Record<string, string>;

    caPath?: string;

    clientCert?: ClientCert;

    proxy?: ProxyConfiguration;

    protocol?: string;
  }

  export type ProxyConfiguration = 'system' | 'no-proxy' | HttpProxy;

  export interface ClientCert {
    certPath: string;

    keyPath: string;

    keyPassword?: string;
  }

  export class ClientCertInner implements ClientCert {
    certPath: string;

    keyPath: string;

    keyPassword?: string;
  }

  export interface WebSocketCloseOptions {
    code?: int;
    reason?: string;
  }

  export class WebSocketCloseOptionsInner implements WebSocketCloseOptions {
    code?: int;
    reason?: string;
  }

  export interface CloseResult {
    code: int;
    reason: string;
  }

  export class CloseResultInner implements CloseResult {
    code: int;
    reason: string;
  }

  export interface OpenResult {
    status: int;
    message: string;
  }

  export class OpenResultInner implements OpenResult {
    status: int;
    message: string;
  }
  
  export type ResponseHeaders = Record<string, string | string[] | undefined>;

  export interface WebSocket {
    connect(url: string, callback: AsyncCallback<boolean>): void;

    connect(url: string, options: WebSocketRequestOptions, callback: AsyncCallback<boolean>): void;

    connect(url: string, options?: WebSocketRequestOptions): Promise<boolean>;

    send(data: string | ArrayBuffer, callback: AsyncCallback<boolean>): void;

    send(data: string | ArrayBuffer): Promise<boolean>;

    close(callback: AsyncCallback<boolean>): void;

    close(options: WebSocketCloseOptions, callback: AsyncCallback<boolean>): void;

    close(options?: WebSocketCloseOptions): Promise<boolean>;

    on(type: 'open' | 'message' | 'close' | 'error' | 'dataEnd' | 'headerReceive',
    callback: Object): void;

    off(type: 'open' | 'message' | 'close' | 'error' | 'dataEnd' | 'headerReceive',
    callback?: Object): void;
  }

  export class WebSocketInner implements WebSocket {
    private  nativePtr:long = 0;
    private cleaner: Cleaner | null = null;

    constructor(context:long) {
        if(this.nativePtr == 0){
             this.nativePtr = context;
        }
        this.registerCleaner(this.nativePtr)
    }

    registerCleaner(nativePtr: long): void {
      this.cleaner = new Cleaner(nativePtr)
      destroyRegister.register(this, this.cleaner!, unregisterToken);
    }

    unregisterCleaner(): void {
        destroyRegister.unregister(unregisterToken);
    }

    native connectSync(url: string, options?: WebSocketRequestOptions): boolean;

    connect(url: string, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.connectSync(url);
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    connect(url: string, options: WebSocketRequestOptions, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.connectSync(url, options);
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    connect(url: string, options?: WebSocketRequestOptions): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.connectSync(url, options);
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native sendSync(data: string | ArrayBuffer): boolean;

    send(data: string | ArrayBuffer, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.sendSync(data);
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    send(data: string | ArrayBuffer): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.sendSync(data);
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native closeSync(options?: WebSocketCloseOptions): boolean;

    close(callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.closeSync();
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    close(options: WebSocketCloseOptions, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.closeSync(options);
      })
      p1.then((content: NullishType) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    close(options?: WebSocketCloseOptions): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.closeSync(options);
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native onOpen(callback: AsyncCallback<OpenResult>): void;
    native onMessage(callback: AsyncCallback<string | ArrayBuffer>): void;
    native onClose(callback: AsyncCallback<CloseResult>): void;
    native onError(callback: ErrorCallback): void;
    native onDataEnd(callback: Callback<void>): void;
    native onHeaderReceive(callback: Callback<ResponseHeaders>): void;

    on(type: 'open' | 'message' | 'close' | 'error' | 'dataEnd' | 'headerReceive',
    callback: Object): void {
      if (type == 'open') {
        this.onOpen(callback as AsyncCallback<OpenResult>)
      } else if (type == 'message') {
        this.onMessage(callback as AsyncCallback<string | ArrayBuffer>)
      } else if (type == 'close') {
        this.onClose(callback as AsyncCallback<CloseResult>)
      } else if (type == 'error') {
        this.onError(callback as ErrorCallback)
      } else if (type == 'dataEnd') {
        this.onDataEnd(callback as Callback<void>)
      } else if (type == 'headerReceive') {
        this.onHeaderReceive(callback as Callback<ResponseHeaders>)
      }
    }

    native offOpen(callback?: AsyncCallback<Object>): void;
    native offMessage(callback?: AsyncCallback<string | ArrayBuffer>): void;
    native offClose(callback?: AsyncCallback<CloseResult>): void;
    native offError(callback?: ErrorCallback): void;
    native offDataEnd(callback?: Callback<void>): void;
    native offHeaderReceive(callback?: Callback<ResponseHeaders>): void;

    off(type: 'open' | 'message' | 'close' | 'error' | 'dataEnd' | 'headerReceive',
    callback?: Object): void {
      if (type == 'open') {
        if (callback === undefined) {
          this.offOpen()
        } else {
          this.offOpen(callback as AsyncCallback<Object>)
        }        
      } else if (type == 'message') {
        if (callback === undefined) {
          this.offMessage()
        } else {
          this.offMessage(callback as AsyncCallback<string | ArrayBuffer>)
        }
      } else if (type == 'close') {
        if (callback === undefined) {
          this.offClose()
        } else {
          this.offClose(callback as AsyncCallback<CloseResult>)
        }
      } else if (type == 'error') {
        if (callback === undefined) {
          this.offError()
        } else {
          this.offError(callback as ErrorCallback)
        }
      } else if (type == 'dataEnd') {
        if (callback === undefined) {
          this.offDataEnd()
        } else {
          this.offDataEnd(callback as Callback<void>)
        }
      } else if (type == 'headerReceive') {
        if (callback === undefined) {
          this.offHeaderReceive()
        } else {
          this.offHeaderReceive(callback as Callback<ResponseHeaders>)
        }
      }
    }
  }

  class CleanerServer {
    private nativePtr: long = 0
    constructor(nativePtr:long) {
        this.nativePtr = nativePtr
    }
    native clean(): void
  }

  let destroyRegisterServer = new FinalizationRegistry<CleanerServer>((cleaner: CleanerServer) => {cleaner.clean()})
  let unregisterTokenServer = new object()

  export native function createWebSocketServer(): WebSocketServer;

  export interface WebSocketServerConfig {
    serverIP?: string;

    serverPort: int;

    serverCert?: ServerCert;

    maxConcurrentClientsNumber: int;

    protocol?: string;

    maxConnectionsForOneClient: int;
  }

  export class WebSocketServerConfigInner implements WebSocketServerConfig {
    serverIP?: string;

    serverPort: int;

    serverCert?: ServerCert;

    maxConcurrentClientsNumber: int;

    protocol?: string;

    maxConnectionsForOneClient: int;
  }

  export interface ServerCert {
    certPath: string;

    keyPath: string;
  }

  export class ServerCertInner implements ServerCert {
    certPath: string;

    keyPath: string;
  }

  export interface WebSocketConnection {
    clientIP: string;

    clientPort: int;
  }

  export class WebSocketConnectionInner implements WebSocketConnection {
    clientIP: string;

    clientPort: int;
  }

  export type ClientConnectionCloseCallback = (clientConnection: WebSocketConnection, closeReason: CloseResult) => void;

  export interface WebSocketMessage {
    data: string | ArrayBuffer;

    clientConnection: WebSocketConnection;
  }

  export class WebSocketMessageInner implements WebSocketMessage {
    data: string | ArrayBuffer;

    clientConnection: WebSocketConnection;
  }

  export interface WebSocketServer {
    start(config: WebSocketServerConfig): Promise<boolean>;

    listAllConnections(): WebSocketConnection[];

    close(connection: WebSocketConnection, options?: WebSocketCloseOptions): Promise<boolean>;

    send(data: string | ArrayBuffer, connection: WebSocketConnection): Promise<boolean>;

    stop(): Promise<boolean>;

    on(type: 'error' | 'connect' | 'close' | 'messageReceive', callback: Object): void;

    off(type: 'error' | 'connect' | 'close' | 'messageReceive', callback?: Object): void;
  }

  export class WebSocketServerInner implements WebSocketServer {
    private nativePtr: long = 0;
    private cleaner: CleanerServer | null = null;

    constructor(context: long) {
      if (this.nativePtr == 0) {
        this.nativePtr = context;
      }
      this.registerCleaner(this.nativePtr);
    }

    registerCleaner(nativePtr: long): void {
      this.cleaner = new CleanerServer(nativePtr);
      destroyRegisterServer.register(this, this.cleaner!, unregisterTokenServer);
    }

    unregisterCleaner(): void {
      destroyRegisterServer.unregister(unregisterTokenServer);
    }

    native startSync(config: WebSocketServerConfig): boolean;

    start(config: WebSocketServerConfig): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.startSync(config);
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native closeSync(connection: WebSocketConnection, options?: webSocket.WebSocketCloseOptions): boolean;

    close(connection: WebSocketConnection, options?: webSocket.WebSocketCloseOptions): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.closeSync(connection, options);
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native listAllConnectionsSync(): WebSocketConnection[];

    listAllConnections(): WebSocketConnection[] {
      return this.listAllConnectionsSync();
    }

    native sendSync(data: string | ArrayBuffer, connection: WebSocketConnection): boolean;

    send(data: string | ArrayBuffer, connection: WebSocketConnection): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.sendSync(data, connection);
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native stopSync(): boolean;

    stop(): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.stopSync();
        }).then((content: NullishType) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native onError(callback: ErrorCallback): void;
    native onConnect(callback: Callback<WebSocketConnection>): void;
    native onClose(callback: ClientConnectionCloseCallback): void;
    native onMessageReceive(callback: Callback<WebSocketMessage>): void;

    on(type: 'error' | 'connect' | 'close' | 'messageReceive', callback: Object): void {
      if (type == 'error') {
        this.onError(callback as ErrorCallback);
      } else if (type == 'connect') {
        this.onConnect(callback as Callback<WebSocketConnection>);
      } else if (type == 'close') {
        this.onClose(callback as ClientConnectionCloseCallback);
      } else if (type == 'messageReceive') {
        this.onMessageReceive(callback as Callback<WebSocketMessage>);
      }
    }

    native offError(callback?: ErrorCallback): void;
    native offConnect(callback?: Callback<WebSocketConnection>): void;
    native offClose(callback?: ClientConnectionCloseCallback): void;
    native offMessageReceive(callback?: Callback<WebSocketMessage>): void;

    off(type: 'error' | 'connect' | 'close' | 'messageReceive', callback?: Object): void {
      if (type == 'error') {
        if (callback === undefined) {
          this.offError();
        } else {
          this.offError(callback as ErrorCallback);
        }
      } else if (type == 'connect') {
        if (callback === undefined) {
          this.offConnect();
        } else {
          this.offConnect(callback as Callback<WebSocketConnection>);
        }
      } else if (type == 'close') {
        if (callback === undefined) {
          this.offClose();
        } else {
          this.offClose(callback as ClientConnectionCloseCallback);
        }
      } else if (type == 'messageReceive') {
        if (callback === undefined) {
          this.offMessageReceive();
        } else {
          this.offMessageReceive(callback as Callback<WebSocketMessage>);
        }
      }
    }
  }
}
