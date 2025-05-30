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
// import type connection from '@ohos.net.connection';
import { BusinessError }  from '@ohos.base';

export default namespace webSocket {
  // type HttpProxy = connection.HttpProxy;

  loadLibrary("websocket_ani");

  class Cleaner {
    private ptr: long = 0
    constructor(ptr:long) {
        this.ptr = ptr
    }
    native clean(): void
  }

  export native function createWebSocket(): WebSocket;

  let destroyRegister = new FinalizationRegistry<Cleaner>((cleaner: Cleaner) => {cleaner.clean()})
  let unregisterToken = new object()

  export interface WebSocketRequestOptions {
    header?: Record<String, String>;

    caPath?: string;

    clientCert?: ClientCert;

    proxy?: ProxyConfiguration;

    protocol?: string;
  }

  export type ProxyConfiguration = 'system' | 'no-proxy' // | HttpProxy;

  export interface ClientCert {
    certPath: string;

    keyPath: string;

    keyPassword?: string;
  }

  export interface WebSocketCloseOptions {
    code?: int;
    reason?: string;
  }

  export interface CloseResult {
    code: int;
    reason: string;
  }

  // export type ResponseHeaders = {
  //   [k: string]: string | string[] | undefined;
  // }

  export interface WebSocket {
    connect(url: string, callback: AsyncCallback<boolean>): void;

    connect(url: string, options: WebSocketRequestOptions, callback: AsyncCallback<boolean>): void;

    connect(url: string, options?: WebSocketRequestOptions): Promise<boolean>;

    send(data: string | ArrayBuffer, callback: AsyncCallback<boolean>): void;

    send(data: string | ArrayBuffer): Promise<boolean>;

    close(callback: AsyncCallback<boolean>): void;

    close(options: WebSocketCloseOptions, callback: AsyncCallback<boolean>): void;

    close(options?: WebSocketCloseOptions): Promise<boolean>;

    // on(type: 'open', callback: AsyncCallback<Object>): void;

    // off(type: 'open', callback?: AsyncCallback<Object>): void;

    // on(type: 'message', callback: AsyncCallback<string | ArrayBuffer>): void;

    // off(type: 'message', callback?: AsyncCallback<string | ArrayBuffer>): void;

    // on(type: 'close', callback: AsyncCallback<CloseResult>): void;

    // off(type: 'close', callback?: AsyncCallback<CloseResult>): void;

    // on(type: 'error', callback: ErrorCallback): void;

    // off(type: 'error', callback?: ErrorCallback): void;

    // on(type: 'dataEnd', callback: Callback<void>): void;

    // off(type: 'dataEnd', callback?: Callback<void>): void;

    // on(type: 'headerReceive', callback: Callback<ResponseHeaders>): void;

    // off(type: 'headerReceive', callback?: Callback<ResponseHeaders>): void;
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

    registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
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
  }
}

function main() {
  try {
    let options: webSocket.WebSocketRequestOptions = {

    }
    let w = webSocket.createWebSocket();
    await w.connect("https://baidu.com", {
      caPath: "niaaani",
    });
    w.close();
  } catch (e:BusinessError) {
    console.log(e);
  }
}
