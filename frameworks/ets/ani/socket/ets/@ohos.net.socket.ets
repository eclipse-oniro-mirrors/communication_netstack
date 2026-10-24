/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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
import type cert from '@ohos.security.cert';
import { BusinessError }  from '@ohos.base';

export default namespace socket {
    export type NetAddress = connection.NetAddress;
    export type X509CertRawData = cert.EncodingBlob

    loadLibrary("socket_ani");

    export native function constructUDPSocketInstance(): UDPSocket;
    export native function constructMulticastSocketInstance(): MulticastSocket;
    export native function constructLocalSocketInstance(): LocalSocket;
    export native function constructLocalSocketServerInstance(): LocalSocketServer;
    export native function constructTCPSocketInstance(): TCPSocket;
    export native function constructTCPSocketServerInstance(): TCPSocketServer;
    export native function constructTLSSocketInstanceSync(tcpSocket?: TCPSocket): TLSSocket;
    export function constructTLSSocketInstance(): TLSSocket {
        return constructTLSSocketInstanceSync(undefined);
    }
    export function constructTLSSocketInstance(tcpSocket: TCPSocket): TLSSocket {
        return constructTLSSocketInstanceSync(tcpSocket);
    }

    export native function constructTLSSocketServerInstance(): TLSSocketServer;
    export native function destroyUDPSocketInstance(ptr: long): void;
    export native function destroyLocalSocketInstance(ptr: long): void;
    export native function destroyLocalSocketServerInstance(ptr: long): void;
    export native function destroyLocalSocketConnectionInstance(ptr: long): void;
    export native function destroyTCPSocketInstance(ptr: long): void;
    export native function destroyTCPSocketServerInstance(ptr: long): void;
    export native function destroyTCPSocketConnectionInstance(ptr: long): void;
    export native function destroyTLSSocketInstance(ptr: long): void;
    export native function destroyTLSSocketServerInstance(ptr: long): void;
    export native function destroyTLSSocketConnectionInstance(ptr: long): void;

    export enum ProxyTypes {
        NONE = 0,
        SOCKS5 = 1,
    }
    
    export enum Protocol {
        TLSv12 = "TLSv1.2",
        TLSv13 = "TLSv1.3",
    }
    
    export interface LocalAddress {
        address: string;
    }
    
    export interface SocketLingerOptions {
        on?: boolean;
        linger?: int;
    }
    
    export interface ProxyOptions {
        type: ProxyTypes;
        address: NetAddress;
        username?: string;
        password?: string;
    }
    
    export interface SocketStateBase {
        isBound: boolean;
        isClose: boolean;
        isConnected: boolean;
    }

    export interface SocketRemoteInfo {
        address: string;
        family: 'IPv4' | 'IPv6';
        port: int;
        size: int;
    }

    export interface TLSSecureOptions {
        ca?: string | Array<string>;
        cert?: string | Array<string>;
        key?: string;
        password?: string;
        protocols?: Protocol | Array<Protocol>;
        useRemoteCipherPrefer?: boolean;
        signatureAlgorithms?: string;
        cipherSuite?: string;
        isBidirectionalAuthentication?: boolean;
    }    
    
    export interface SocketMessageInfo {
        message: ArrayBuffer;
        remoteInfo: SocketRemoteInfo;
    }
    
    export interface LocalSocketMessageInfo {
        message: ArrayBuffer;
        address: string;
        size: int;
    }

    export interface ExtraOptionsBase {
        receiveBufferSize?: int;
        sendBufferSize?: int;
        reuseAddress?: boolean;
        socketTimeout?: int;
    }

    export interface UDPExtraOptions extends ExtraOptionsBase {
        broadcast?: boolean;
    }
    
    export interface TCPExtraOptions extends ExtraOptionsBase {
        keepAlive?: boolean;
        OOBInline?: boolean;
        TCPNoDelay?: boolean;
        socketLinger?: SocketLingerOptions;
        tcpFastOpen?: boolean;
    }

    export interface UDPSendOptions {
        data: string | ArrayBuffer;
        address: NetAddress;
        proxy?: ProxyOptions;
    }
    
    export interface LocalSendOptions {
        data: string | ArrayBuffer;
        encoding?: string;
    }

    export interface TCPSendOptions {
        data: string | ArrayBuffer;
        encoding?: string;
    }

    export interface LocalConnectOptions {
        address: LocalAddress;
        timeout?: int;
    }

    export interface TCPConnectOptions {
        address: NetAddress;
        timeout?: int;
        proxy?: ProxyOptions;
    }
    
    export interface TLSConnectOptions {    
        address: NetAddress;
        secureOptions: TLSSecureOptions;
        ALPNProtocols?: Array<string>;
        skipRemoteValidation?: boolean;
        proxy?: ProxyOptions;
        timeout?: int;
    }

    export interface UDPSocket {    
        bind(address: NetAddress, callback: AsyncCallback<void>): void;
        bind(address: NetAddress): Promise<void>;
        send(options: UDPSendOptions, callback: AsyncCallback<void>): void;
        send(options: UDPSendOptions): Promise<void>;
        close(callback: AsyncCallback<void>): void;
        close(): Promise<void>;
        getLocalAddress(): Promise<NetAddress>;
        getState(callback: AsyncCallback<SocketStateBase>): void;
        getState(): Promise<SocketStateBase>;
        getSocketFd(): Promise<int>;
        setExtraOptions(options: UDPExtraOptions, callback: AsyncCallback<void>): void;
        setExtraOptions(options: UDPExtraOptions): Promise<void>;
        onUdpMessage(callback: Callback<SocketMessageInfo>): void;
        offUdpMessage(callback?: Callback<SocketMessageInfo>): void;
        onListening(callback: Callback<void>): void;
        offListening(callback?: Callback<void>): void;
        onClose(callback: Callback<void>): void;
        offClose(callback?: Callback<void>): void;
        onUdpError(callback: ErrorCallback): void;
        offUdpError(callback?: ErrorCallback): void;
    }

    export interface MulticastSocket extends UDPSocket {
        addMembership(multicastAddress: NetAddress, callback: AsyncCallback<void>): void;
        addMembership(multicastAddress: NetAddress): Promise<void>;
        dropMembership(multicastAddress: NetAddress, callback: AsyncCallback<void>): void;
        dropMembership(multicastAddress: NetAddress): Promise<void>;
        setMulticastTTL(ttl: int, callback: AsyncCallback<void>): void;
        setMulticastTTL(ttl: int): Promise<void>;
        getMulticastTTL(callback: AsyncCallback<int>): void;
        getMulticastTTL(): Promise<int>;
        setLoopbackMode(flag: boolean, callback: AsyncCallback<void>): void;
        setLoopbackMode(flag: boolean): Promise<void>;
        getLoopbackMode(callback: AsyncCallback<boolean>): void;
        getLoopbackMode(): Promise<boolean>;
        getSocketFd(): Promise<int>;
        setReuseAddress(reuse: boolean): void;
    }

    export interface LocalSocket {
        bind(address: LocalAddress): Promise<void>;
        connect(options: LocalConnectOptions): Promise<void>;
        send(options: LocalSendOptions): Promise<void>;
        close(): Promise<void>;
        getState(): Promise<SocketStateBase>;
        getSocketFd(): Promise<int>;
        setExtraOptions(options: ExtraOptionsBase): Promise<void>;
        getExtraOptions(): Promise<ExtraOptionsBase>;
        getLocalAddress(): Promise<string>;
        onLocalSocketMessage(callback: Callback<LocalSocketMessageInfo>): void;
        offLocalSocketMessage(callback?: Callback<LocalSocketMessageInfo>): void;
        onConnect(callback: Callback<void>): void;
        offConnect(callback?: Callback<void>): void;
        onLocalSocketClose(callback: Callback<void>): void;
        offLocalSocketClose(callback?: Callback<void>): void;
        onLocalSocketError(callback: ErrorCallback): void;
        offLocalSocketError(callback?: ErrorCallback): void;
    }

    export interface LocalSocketServer {
        listen(address: LocalAddress): Promise<void>;
        close(): Promise<void>;
        getState(): Promise<SocketStateBase>;
        setExtraOptions(options: ExtraOptionsBase): Promise<void>;
        getExtraOptions(): Promise<ExtraOptionsBase>;
        getLocalAddress(): Promise<string>;
        getSocketFd(): Promise<int>;
        onConnect(callback: Callback<LocalSocketConnection>): void;
        offConnect(callback?: Callback<LocalSocketConnection>): void;
        onLocalServerError(callback: ErrorCallback): void;
        offLocalServerError(callback?: ErrorCallback): void;
    }

    export interface LocalSocketConnection {
        clientId: int;
        send(options: LocalSendOptions): Promise<void>;
        close(): Promise<void>;
        getLocalAddress(): Promise<string>;
        getSocketFd(): Promise<int>;
        onLocalConnMessage(callback: Callback<LocalSocketMessageInfo>): void;
        offLocalConnMessage(callback?: Callback<LocalSocketMessageInfo>): void;
        onLocalConnClose(callback: Callback<void>): void;
        offLocalConnClose(callback?: Callback<void>): void;
        onLocalConnError(callback: ErrorCallback): void;
        offLocalConnError(callback?: ErrorCallback): void;
    }

    export interface TCPSocket {
        bind(address: NetAddress, callback: AsyncCallback<void>): void;
        bind(address: NetAddress): Promise<void>;
        connect(options: TCPConnectOptions, callback: AsyncCallback<void>): void;
        connect(options: TCPConnectOptions): Promise<void>;
        send(options: TCPSendOptions, callback: AsyncCallback<void>): void;
        send(options: TCPSendOptions): Promise<void>;
        close(callback: AsyncCallback<void>): void;
        close(): Promise<void>;
        getRemoteAddress(callback: AsyncCallback<NetAddress>): void;
        getRemoteAddress(): Promise<NetAddress>;
        getState(callback: AsyncCallback<SocketStateBase>): void;
        getState(): Promise<SocketStateBase>;
        getSocketFd(callback: AsyncCallback<int>): void;
        getSocketFd(): Promise<int>;
        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void;
        setExtraOptions(options: TCPExtraOptions): Promise<void>;
        getLocalAddress(): Promise<NetAddress>;
        onTcpMessage(callback: Callback<SocketMessageInfo>): void;
        offTcpMessage(callback?: Callback<SocketMessageInfo>): void;
        onTcpConnect(callback: Callback<void>): void;
        offTcpConnect(callback?: Callback<void>): void;
        onTcpClose(callback: Callback<void>): void;
        offTcpClose(callback?: Callback<void>): void;
        onTcpError(callback: ErrorCallback): void;
        offTcpError(callback?: ErrorCallback): void;
    }
    
    export interface TCPSocketServer {    
        listen(address: NetAddress, callback: AsyncCallback<void>): void;
        listen(address: NetAddress): Promise<void>;
        close(): Promise<void>;
        getState(callback: AsyncCallback<SocketStateBase>): void;
        getState(): Promise<SocketStateBase>;
        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void;
        setExtraOptions(options: TCPExtraOptions): Promise<void>;
        getLocalAddress(): Promise<NetAddress>;
        getSocketFd(): Promise<int>;
        onTcpServerConnect(callback: Callback<TCPSocketConnection>): void;
        offTcpServerConnect(callback?: Callback<TCPSocketConnection>): void;
        onTcpServerError(callback: ErrorCallback): void;
        offTcpServerError(callback?: ErrorCallback): void;
    }

    export interface TCPSocketConnection {
        clientId: int;
        send(options: TCPSendOptions, callback: AsyncCallback<void>): void;
        send(options: TCPSendOptions): Promise<void>;
        close(callback: AsyncCallback<void>): void;
        close(): Promise<void>;
        getRemoteAddress(callback: AsyncCallback<NetAddress>): void;
        getRemoteAddress(): Promise<NetAddress>;
        getLocalAddress(): Promise<NetAddress>;
        getSocketFd(): Promise<int>;
        onTcpConnMessage(callback: Callback<SocketMessageInfo>): void;
        offTcpConnMessage(callback?: Callback<SocketMessageInfo>): void;
        onTcpConnClose(callback: Callback<void>): void;
        offTcpConnClose(callback?: Callback<void>): void;
        onTcpConnError(callback: ErrorCallback): void;
        offTcpConnError(callback?: ErrorCallback): void;
    }

    export interface TLSSocket {
        bind(address: NetAddress, callback: AsyncCallback<void>): void;
        bind(address: NetAddress): Promise<void>;
        connect(options: TLSConnectOptions, callback: AsyncCallback<void>): void;
        connect(options: TLSConnectOptions): Promise<void>;
        send(data: string | ArrayBuffer, callback: AsyncCallback<void>): void;
        send(data: string | ArrayBuffer): Promise<void>;
        close(callback: AsyncCallback<void>): void;
        close(): Promise<void>;
        getRemoteAddress(callback: AsyncCallback<NetAddress>): void;
        getRemoteAddress(): Promise<NetAddress>;
        getState(callback: AsyncCallback<SocketStateBase>): void;
        getState(): Promise<SocketStateBase>;
        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void;
        setExtraOptions(options: TCPExtraOptions): Promise<void>;
        getLocalAddress(): Promise<NetAddress>;
        getCertificate(callback: AsyncCallback<X509CertRawData>): void;
        getCertificate(): Promise<X509CertRawData>;
        getRemoteCertificate(callback: AsyncCallback<X509CertRawData>): void;
        getRemoteCertificate(): Promise<X509CertRawData>;
        getProtocol(callback: AsyncCallback<string>): void;
        getProtocol(): Promise<string>;
        getCipherSuite(callback: AsyncCallback<Array<string>>): void;
        getCipherSuite(): Promise<Array<string>>;
        getSignatureAlgorithms(callback: AsyncCallback<Array<string>>): void;
        getSignatureAlgorithms(): Promise<Array<string>>;
        getSocketFd(): Promise<int>;
        onTlsMessage(callback: Callback<SocketMessageInfo>): void;
        offTlsMessage(callback?: Callback<SocketMessageInfo>): void;
        onTlsConnect(callback: Callback<void>): void;
        offTlsConnect(callback?: Callback<void>): void;
        onTlsClose(callback: Callback<void>): void;
        offTlsClose(callback?: Callback<void>): void;
        onTlsError(callback: ErrorCallback): void;
        offTlsError(callback?: ErrorCallback): void;
    }
    
    export interface TLSSocketServer {
        listen(options: TLSConnectOptions, callback: AsyncCallback<void>): void;
        listen(options: TLSConnectOptions): Promise<void>;
        close(): Promise<void>;
        getState(callback: AsyncCallback<SocketStateBase>): void;
        getState(): Promise<SocketStateBase>;
        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void;
        setExtraOptions(options: TCPExtraOptions): Promise<void>;
        getCertificate(callback: AsyncCallback<X509CertRawData>): void;
        getCertificate(): Promise<X509CertRawData>;
        getProtocol(callback: AsyncCallback<string>): void;
        getProtocol(): Promise<string>;
        getLocalAddress(): Promise<NetAddress>;
        getSocketFd(): Promise<int>;
        onTlsServerConnect(callback: Callback<TLSSocketConnection>): void;
        offTlsServerConnect(callback?: Callback<TLSSocketConnection>): void;
        onTlsServerError(callback: ErrorCallback): void;
        offTlsServerError(callback?: ErrorCallback): void;
    }

    export interface TLSSocketConnection {
        clientId: int;
        send(data: string | ArrayBuffer, callback: AsyncCallback<void>): void;
        send(data: string | ArrayBuffer): Promise<void>;
        close(callback: AsyncCallback<void>): void;
        close(): Promise<void>;
        getRemoteAddress(callback: AsyncCallback<NetAddress>): void;
        getRemoteAddress(): Promise<NetAddress>;
        getRemoteCertificate(callback: AsyncCallback<X509CertRawData>): void;
        getRemoteCertificate(): Promise<X509CertRawData>;
        getCipherSuite(callback: AsyncCallback<Array<string>>): void;
        getCipherSuite(): Promise<Array<string>>;
        getSignatureAlgorithms(callback: AsyncCallback<Array<string>>): void;
        getSignatureAlgorithms(): Promise<Array<string>>;
        getLocalAddress(): Promise<NetAddress>;
        getSocketFd(): Promise<int>;
        onTlsConnMessage(callback: Callback<SocketMessageInfo>): void;
        offTlsConnMessage(callback?: Callback<SocketMessageInfo>): void;
        onTlsConnClose(callback: Callback<void>): void;
        offTlsConnClose(callback?: Callback<void>): void;
        onTlsConnError(callback: ErrorCallback): void;
        offTlsConnError(callback?: ErrorCallback): void;
    }
    
    class Cleaner {
        ptr: long;
        cleanFn: (ptr: long) => void;
        
        constructor(ptr: long, cleanFn: (ptr: long) => void) {
            this.ptr = ptr;
            this.cleanFn = cleanFn;
        }
    }
    let destroyRegister: FinalizationRegistry<Cleaner> = new FinalizationRegistry<Cleaner>((holder: Cleaner) => {holder.cleanFn(holder.ptr);});
    
    export class X509CertRawDataInner implements X509CertRawData {
        data: Uint8Array;
        encodingFormat: cert.EncodingFormat;
    }

    export class LocalAddressInner implements LocalAddress {
        address: string;
    }

    export class SocketLingerOptionsInner implements SocketLingerOptions {
        on?: boolean;
        linger?: int;
    }

    export class ProxyOptionsInner implements ProxyOptions {
        type: ProxyTypes;
        address: NetAddress;
        username?: string;
        password?: string;
    }

    export class SocketStateBaseInner implements SocketStateBase {
        isBound: boolean;
        isClose: boolean;
        isConnected: boolean;
    }

    export class SocketRemoteInfoInner implements SocketRemoteInfo {
        address: string;
        family: 'IPv4' | 'IPv6';
        port: int;
        size: int;
    }

    export class TLSSecureOptionsInner implements TLSSecureOptions {
        ca?: string | Array<string>;
        cert?: string | Array<string>;
        key?: string;
        password?: string;
        protocols?: Protocol | Array<Protocol>;
        useRemoteCipherPrefer?: boolean;
        signatureAlgorithms?: string;
        cipherSuite?: string;
        isBidirectionalAuthentication?: boolean;
    }

    export class SocketMessageInfoInner implements SocketMessageInfo {
        message: ArrayBuffer;
        remoteInfo: SocketRemoteInfo;
    }
    
    export class LocalSocketMessageInfoInner implements LocalSocketMessageInfo {
        message: ArrayBuffer;
        address: string;
        size: int;
    }

    export class ExtraOptionsBaseInner implements ExtraOptionsBase {
        receiveBufferSize?: int;
        sendBufferSize?: int;
        reuseAddress?: boolean;
        socketTimeout?: int;
    }

    export class UDPExtraOptionsInner extends ExtraOptionsBaseInner implements UDPExtraOptions {
        broadcast?: boolean;
    }

    export class TCPExtraOptionsInner extends ExtraOptionsBaseInner implements TCPExtraOptions {
        keepAlive?: boolean;
        OOBInline?: boolean;
        TCPNoDelay?: boolean;
        socketLinger?: SocketLingerOptionsInner;
        tcpFastOpen?: boolean;
    }

    export class UDPSendOptionsInner implements UDPSendOptions {
        data: string | ArrayBuffer;
        address: NetAddress;
        proxy?: ProxyOptions;
    }

    export class LocalSendOptionsInner implements LocalSendOptions {
        data: string | ArrayBuffer;
        encoding?: string;
    }

    export class TCPSendOptionsInner implements TCPSendOptions {
        data: string | ArrayBuffer;
        encoding?: string;
    }

    export class LocalConnectOptionsInner implements LocalConnectOptions {
        address: LocalAddress;
        timeout?: int;
    }

    export class TCPConnectOptionsInner implements TCPConnectOptions {
        address: NetAddress;
        timeout?: int;
        proxy?: ProxyOptions;
    }

    export class TLSConnectOptionsInner implements TLSConnectOptions {
        address: NetAddress;
        secureOptions: TLSSecureOptions;
        ALPNProtocols?: Array<string>;
        skipRemoteValidation?: boolean;
        proxy?: ProxyOptions;
        timeout?: int;
    }

    class UDPSocketInner implements UDPSocket {
        private nativePtr: long = 0;
        private token: object = new object();
        socketFd: int = -1;

        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyUDPSocketInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        bind(address: NetAddress, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.bindSync(address);
            });
            p1.then(() => {
                this.socketFd = this.getSocketFdSync();
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        bind(address: NetAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.bindSync(address);
                }).then(() => {
                    this.socketFd = this.getSocketFdSync();
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        send(options: UDPSendOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.sendSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        send(options: UDPSendOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.closeSync();
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }
        
        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(callback: AsyncCallback<SocketStateBase>): void {
            let p1 = taskpool.execute((): SocketStateBase => {
                return this.getStateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as SocketStateBase);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: UDPExtraOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setExtraOptionsSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setExtraOptions(options: UDPExtraOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }
        
        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onUdpMessage(callback: Callback<SocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offUdpMessage(callback?: Callback<SocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onListening(callback: Callback<void>): void {
            this.onListeningInner(callback);
        }

        offListening(callback?: Callback<void>): void {
            this.offListeningInner(callback);
        }

        onClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onUdpError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offUdpError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native bindSync(address: NetAddress): void;
        native getLocalAddressSync(): NetAddress;
        native sendSync(options: UDPSendOptions): void;
        native closeSync(): void;
        native getStateSync(): SocketStateBase;
        native setExtraOptionsSync(options: UDPExtraOptions): void;
        native getSocketFdSync(): int;

        native onMessageInner(callback: Callback<SocketMessageInfo>): void;
        native offMessageInner(callback?: Callback<SocketMessageInfo>): void;
        native onListeningInner(callback: Callback<void>): void;
        native offListeningInner(callback?: Callback<void>): void;
        native onCloseInner(callback: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class MulticastSocketInner extends UDPSocketInner implements MulticastSocket {
        constructor(context: long) {
            super(context);
        }

        addMembership(multicastAddress: NetAddress, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.addMembershipSync(multicastAddress);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        addMembership(multicastAddress: NetAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.addMembershipSync(multicastAddress);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        dropMembership(multicastAddress: NetAddress, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.dropMembershipSync(multicastAddress);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        dropMembership(multicastAddress: NetAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.dropMembershipSync(multicastAddress);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setMulticastTTL(ttl: int, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setMulticastTTLSync(ttl);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setMulticastTTL(ttl: int): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setMulticastTTLSync(ttl);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getMulticastTTL(callback: AsyncCallback<int>): void {
            let p1 = taskpool.execute((): int => {
                return this.getMulticastTTLSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as int);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getMulticastTTL(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getMulticastTTLSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setLoopbackMode(flag: boolean, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setLoopbackModeSync(flag);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setLoopbackMode(flag: boolean): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setLoopbackModeSync(flag);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLoopbackMode(callback: AsyncCallback<boolean>): void {
            let p1 = taskpool.execute((): boolean => {
                return this.getLoopbackModeSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as boolean);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getLoopbackMode(): Promise<boolean> {
            return new Promise<boolean>((resolve, reject) => {
                taskpool.execute((): boolean => {
                    return this.getLoopbackModeSync();
                }).then((content: Any) => {
                    resolve(content as boolean);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setReuseAddress(reuse: boolean): void {
            this.setReuseAddressSync(reuse);
        }

        native addMembershipSync(multicastAddress: NetAddress): void;
        native dropMembershipSync(multicastAddress: NetAddress): void;
        native setMulticastTTLSync(ttl: int): void;
        native getMulticastTTLSync(): int;
        native setLoopbackModeSync(flag: boolean): void;
        native getLoopbackModeSync(): boolean;
        native setReuseAddressSync(reuse: boolean): void;
    }

    class LocalSocketInner implements LocalSocket {
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyLocalSocketInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        bind(address: LocalAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.bindSync(address);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        connect(options: LocalConnectOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.connectSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        send(options: LocalSendOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: ExtraOptionsBase): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getExtraOptions(): Promise<ExtraOptionsBase> {
            return new Promise<ExtraOptionsBase>((resolve, reject) => {
                taskpool.execute((): ExtraOptionsBase => {
                    return this.getExtraOptionsSync();
                }).then((content: Any) => {
                    resolve(content as ExtraOptionsBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<string> {
            return new Promise<string>((resolve, reject) => {
                taskpool.execute((): string => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as string);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onLocalSocketMessage(callback: Callback<LocalSocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offLocalSocketMessage(callback?: Callback<LocalSocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onConnect(callback: Callback<void>): void {
            this.onConnectInner(callback);
        }

        offConnect(callback?: Callback<void>): void {
            this.offConnectInner(callback);
        }

        onLocalSocketClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offLocalSocketClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onLocalSocketError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offLocalSocketError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native bindSync(address: LocalAddress): void;
        native connectSync(options: LocalConnectOptions): void;
        native sendSync(options: LocalSendOptions): void;
        native closeSync(): void;
        native getStateSync(): SocketStateBase;
        native getSocketFdSync(): int;
        native setExtraOptionsSync(options: ExtraOptionsBase): void;
        native getExtraOptionsSync(): ExtraOptionsBase;
        native getLocalAddressSync(): string;

        native onMessageInner(callback: Callback<LocalSocketMessageInfo>): void;
        native offMessageInner(callback?: Callback<LocalSocketMessageInfo>): void;
        native onConnectInner(callback: Callback<void>): void;
        native offConnectInner(callback?: Callback<void>): void;
        native onCloseInner(callback: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }
    
    class LocalSocketServerInner implements LocalSocketServer {
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyLocalSocketServerInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        listen(address: LocalAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.listenSync(address);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: ExtraOptionsBase): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getExtraOptions(): Promise<ExtraOptionsBase> {
            return new Promise<ExtraOptionsBase>((resolve, reject) => {
                taskpool.execute((): ExtraOptionsBase => {
                    return this.getExtraOptionsSync();
                }).then((content: Any) => {
                    resolve(content as ExtraOptionsBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<string> {
            return new Promise<string>((resolve, reject) => {
                taskpool.execute((): string => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as string);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onConnect(callback: Callback<LocalSocketConnection>): void {
            this.onConnectInner(callback);
        }

        offConnect(callback?: Callback<LocalSocketConnection>): void {
            this.offConnectInner(callback);
        }

        onLocalServerError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offLocalServerError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native listenSync(address: LocalAddress): void;
        native getStateSync(): SocketStateBase;
        native setExtraOptionsSync(options: ExtraOptionsBase): void;
        native getExtraOptionsSync(): ExtraOptionsBase;
        native getLocalAddressSync(): string;
        native closeSync(): void;
        native getSocketFdSync(): int;

        native onConnectInner(callback: Callback<LocalSocketConnection>): void;
        native offConnectInner(callback?: Callback<LocalSocketConnection>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class LocalSocketConnectionInner implements LocalSocketConnection {
        clientId: int;
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long, clientId: int) {
            this.clientId = clientId;
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyLocalSocketConnectionInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        send(options: LocalSendOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<string> {
            return new Promise<string>((resolve, reject) => {
                taskpool.execute((): string => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as string);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onLocalConnMessage(callback: Callback<LocalSocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offLocalConnMessage(callback?: Callback<LocalSocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onLocalConnClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offLocalConnClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onLocalConnError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offLocalConnError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native sendSync(options: LocalSendOptions): void;
        native closeSync(): void;
        native getLocalAddressSync(): string;
        native getSocketFdSync(): int;

        native onMessageInner(callback: Callback<LocalSocketMessageInfo>): void;
        native offMessageInner(callback?: Callback<LocalSocketMessageInfo>): void;
        native onCloseInner(callback: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class TCPSocketInner implements TCPSocket {
        private nativePtr: long = 0;
        private token: object = new object();
        socketFd: int = -1;
        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyTCPSocketInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        bind(address: NetAddress, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.bindSync(address);
            });
            p1.then(() => {
                this.socketFd = this.getSocketFdSync();
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        bind(address: NetAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.bindSync(address);
                }).then(() => {
                    this.socketFd = this.getSocketFdSync();
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        connect(options: TCPConnectOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.connectSync(options);
            });
            p1.then(() => {
                this.socketFd = this.getSocketFdSync();
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        connect(options: TCPConnectOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.connectSync(options);
                }).then(() => {
                    this.socketFd = this.getSocketFdSync();
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        send(options: TCPSendOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.sendSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        send(options: TCPSendOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.closeSync();
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getRemoteAddress(callback: AsyncCallback<NetAddress>): void {
            let p1 = taskpool.execute((): NetAddress => {
                return this.getRemoteAddressSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as NetAddress);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getRemoteAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getRemoteAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(callback: AsyncCallback<SocketStateBase>): void {
            let p1 = taskpool.execute((): SocketStateBase => {
                return this.getStateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as SocketStateBase);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(callback: AsyncCallback<int>): void {
            let p1 = taskpool.execute((): int => {
                return this.getSocketFdSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as int);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setExtraOptionsSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setExtraOptions(options: TCPExtraOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onTcpMessage(callback: Callback<SocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offTcpMessage(callback?: Callback<SocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onTcpConnect(callback: Callback<void>): void {
            this.onConnectInner(callback);
        }

        offTcpConnect(callback?: Callback<void>): void {
            this.offConnectInner(callback);
        }

        onTcpClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offTcpClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onTcpError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offTcpError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native bindSync(address: NetAddress): void;
        native connectSync(options: TCPConnectOptions): void;
        native sendSync(options: TCPSendOptions): void;
        native closeSync(): void;
        native getRemoteAddressSync(): NetAddress;
        native getStateSync(): SocketStateBase;
        native getSocketFdSync(): int;
        native setExtraOptionsSync(options: TCPExtraOptions): void;
        native getLocalAddressSync(): NetAddress;

        native onMessageInner(callback: Callback<SocketMessageInfo>): void;
        native offMessageInner(callback?: Callback<SocketMessageInfo>): void;
        native onConnectInner(callback: Callback<void>): void;
        native offConnectInner(callback?: Callback<void>): void;
        native onCloseInner(callback: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class TCPSocketServerInner implements TCPSocketServer {
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyTCPSocketServerInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        listen(address: NetAddress, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.listenSync(address);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        listen(address: NetAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.listenSync(address);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(callback: AsyncCallback<SocketStateBase>): void {
            let p1 = taskpool.execute((): SocketStateBase => {
                return this.getStateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as SocketStateBase);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setExtraOptionsSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setExtraOptions(options: TCPExtraOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }
        
        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onTcpServerConnect(callback: Callback<TCPSocketConnection>): void {
            this.onConnectInner(callback);
        }

        offTcpServerConnect(callback?: Callback<TCPSocketConnection>): void {
            this.offConnectInner(callback);
        }

        onTcpServerError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offTcpServerError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native listenSync(address: NetAddress): void;
        native closeSync(): void;
        native getStateSync(): SocketStateBase;
        native setExtraOptionsSync(options: TCPExtraOptions): void;
        native getLocalAddressSync(): NetAddress;
        native getSocketFdSync(): int;

        native onConnectInner(callback: Callback<TCPSocketConnection>): void;
        native offConnectInner(callback?: Callback<TCPSocketConnection>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class TCPSocketConnectionInner implements TCPSocketConnection {
        clientId: int;
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long, clientId: int) {
            this.clientId = clientId;
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyTCPSocketConnectionInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        send(options: TCPSendOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.sendSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        send(options: TCPSendOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.closeSync();
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getRemoteAddress(callback: AsyncCallback<NetAddress>): void {
            let p1 = taskpool.execute((): NetAddress => {
                return this.getRemoteAddressSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as NetAddress);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getRemoteAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getRemoteAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onTcpConnMessage(callback: Callback<SocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offTcpConnMessage(callback?: Callback<SocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onTcpConnClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offTcpConnClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onTcpConnError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offTcpConnError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native sendSync(options: TCPSendOptions): void;
        native closeSync(): void;
        native getRemoteAddressSync(): NetAddress;
        native getLocalAddressSync(): NetAddress;
        native getSocketFdSync(): int;

        native onMessageInner(callback: Callback<SocketMessageInfo>): void;
        native offMessageInner(callback?: Callback<SocketMessageInfo>): void;
        native onCloseInner(callback: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    export class TLSSocketInner implements TLSSocket {
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyTLSSocketInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        bind(address: NetAddress, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.bindSync(address);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        bind(address: NetAddress): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.bindSync(address);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }
        
        connect(options: TLSConnectOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.connectSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        connect(options: TLSConnectOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.connectSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        send(data: string | ArrayBuffer, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.sendSync(data);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        send(data: string | ArrayBuffer): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(data);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.closeSync();
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getRemoteAddress(callback: AsyncCallback<NetAddress>): void {
            let p1 = taskpool.execute((): NetAddress => {
                return this.getRemoteAddressSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as NetAddress);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getRemoteAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getRemoteAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(callback: AsyncCallback<SocketStateBase>): void {
            let p1 = taskpool.execute((): SocketStateBase => {
                return this.getStateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as SocketStateBase);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setExtraOptionsSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setExtraOptions(options: TCPExtraOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getCertificate(callback: AsyncCallback<X509CertRawData>): void {
            let p1 = taskpool.execute((): X509CertRawData => {
                return this.getCertificateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as X509CertRawData);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getCertificate(): Promise<X509CertRawData> {
            return new Promise<X509CertRawData>((resolve, reject) => {
                taskpool.execute((): X509CertRawData => {
                    return this.getCertificateSync();
                }).then((content: Any) => {
                    resolve(content as X509CertRawData);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getRemoteCertificate(callback: AsyncCallback<X509CertRawData>): void {
            let p1 = taskpool.execute((): X509CertRawData => {
                return this.getRemoteCertificateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as X509CertRawData);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getRemoteCertificate(): Promise<X509CertRawData> {
            return new Promise<X509CertRawData>((resolve, reject) => {
                taskpool.execute((): X509CertRawData => {
                    return this.getRemoteCertificateSync();
                }).then((content: Any) => {
                    resolve(content as X509CertRawData);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getProtocol(callback: AsyncCallback<string>): void {
            let p1 = taskpool.execute((): string => {
                return this.getProtocolSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as string);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getProtocol(): Promise<string> {
            return new Promise<string>((resolve, reject) => {
                taskpool.execute((): string => {
                    return this.getProtocolSync();
                }).then((content: Any) => {
                    resolve(content as string);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getCipherSuite(callback: AsyncCallback<Array<string>>): void {
            let p1 = taskpool.execute((): Array<string> => {
                return this.getCipherSuiteSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as Array<string>);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getCipherSuite(): Promise<Array<string>> {
            return new Promise<Array<string>>((resolve, reject) => {
                taskpool.execute((): Array<string> => {
                    return this.getCipherSuiteSync();
                }).then((content: Any) => {
                    resolve(content as Array<string>);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSignatureAlgorithms(callback: AsyncCallback<Array<string>>): void {
            let p1 = taskpool.execute((): Array<string> => {
                return this.getSignatureAlgorithmsSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as Array<string>);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getSignatureAlgorithms(): Promise<Array<string>> {
            return new Promise<Array<string>>((resolve, reject) => {
                taskpool.execute((): Array<string> => {
                    return this.getSignatureAlgorithmsSync();
                }).then((content: Any) => {
                    resolve(content as Array<string>);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }
        
        onTlsMessage(callback: Callback<SocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offTlsMessage(callback?: Callback<SocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onTlsConnect(callback: Callback<void>): void {
            this.onConnectInner(callback);
        }

        offTlsConnect(callback?: Callback<void>): void {
            this.offConnectInner(callback);
        }

        onTlsClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offTlsClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onTlsError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offTlsError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native bindSync(address: NetAddress): void;
        native getRemoteAddressSync(): NetAddress;
        native getStateSync(): SocketStateBase;
        native setExtraOptionsSync(options: TCPExtraOptions): void;
        native getLocalAddressSync(): NetAddress;
        native getCertificateSync(): X509CertRawData;
        native getRemoteCertificateSync(): X509CertRawData;
        native getProtocolSync(): string;
        native getCipherSuiteSync(): Array<string>;
        native getSignatureAlgorithmsSync(): Array<string>;
        native getSocketFdSync(): int;
        native connectSync(options: TLSConnectOptions): void;
        native sendSync(data: string | ArrayBuffer): void;
        native closeSync(): void;

        native onMessageInner(callback: Callback<SocketMessageInfo>): void;
        native onConnectInner(callback: Callback<void>): void;
        native onCloseInner(callback: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offMessageInner(callback?: Callback<SocketMessageInfo>): void;
        native offConnectInner(callback?: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class TLSSocketServerInner implements TLSSocketServer {
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long) {
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyTLSSocketServerInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        listen(options: TLSConnectOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.listenSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        listen(options: TLSConnectOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.listenSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getState(callback: AsyncCallback<SocketStateBase>): void {
            let p1 = taskpool.execute((): SocketStateBase => {
                return this.getStateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as SocketStateBase);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getState(): Promise<SocketStateBase> {
            return new Promise<SocketStateBase>((resolve, reject) => {
                taskpool.execute((): SocketStateBase => {
                    return this.getStateSync();
                }).then((content: Any) => {
                    resolve(content as SocketStateBase);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        setExtraOptions(options: TCPExtraOptions, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.setExtraOptionsSync(options);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        setExtraOptions(options: TCPExtraOptions): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.setExtraOptionsSync(options);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getCertificate(callback: AsyncCallback<X509CertRawData>): void {
            let p1 = taskpool.execute((): X509CertRawData => {
                return this.getCertificateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as X509CertRawData);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getCertificate(): Promise<X509CertRawData> {
            return new Promise<X509CertRawData>((resolve, reject) => {
                taskpool.execute((): X509CertRawData => {
                    return this.getCertificateSync();
                }).then((content: Any) => {
                    resolve(content as X509CertRawData);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getProtocol(callback: AsyncCallback<string>): void {
            let p1 = taskpool.execute((): string => {
                return this.getProtocolSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as string);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getProtocol(): Promise<string> {
            return new Promise<string>((resolve, reject) => {
                taskpool.execute((): string => {
                    return this.getProtocolSync();
                }).then((content: Any) => {
                    resolve(content as string);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onTlsServerConnect(callback: Callback<TLSSocketConnection>): void {
            this.onConnectInner(callback);
        }

        offTlsServerConnect(callback?: Callback<TLSSocketConnection>): void {
            this.offConnectInner(callback);
        }

        onTlsServerError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offTlsServerError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native listenSync(options: TLSConnectOptions): void;
        native closeSync(): void;
        native getStateSync(): SocketStateBase;
        native setExtraOptionsSync(options: TCPExtraOptions): void;
        native getCertificateSync(): X509CertRawData;
        native getProtocolSync(): string;
        native getLocalAddressSync(): NetAddress;
        native getSocketFdSync(): int;

        native onConnectInner(callback: Callback<TLSSocketConnection>): void;
        native offConnectInner(callback?: Callback<TLSSocketConnection>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }

    class TLSSocketConnectionInner implements TLSSocketConnection {
        clientId: int;
        private nativePtr: long = 0;
        private token: object = new object();

        constructor(context: long, clientId: int) {
            this.clientId = clientId;
            if (this.nativePtr == 0) {
                this.nativePtr = context;
            }
            let cleaner = new Cleaner(this.nativePtr, destroyTLSSocketConnectionInstance);
            destroyRegister.register(this, cleaner!, this.token);
        }

        unregisterCleaner(): void {
            destroyRegister.unregister(this.token);
            this.nativePtr = 0;
        }

        send(data: string | ArrayBuffer, callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.sendSync(data);
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        send(data: string | ArrayBuffer): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.sendSync(data);
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        close(callback: AsyncCallback<void>): void {
            let p1 = taskpool.execute(() => {
                this.closeSync();
            });
            p1.then(() => {
                callback(new BusinessError(), undefined);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        close(): Promise<void> {
            return new Promise<void>((resolve, reject) => {
                taskpool.execute(() => {
                    this.closeSync();
                }).then(() => {
                    resolve(undefined);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getRemoteAddress(callback: AsyncCallback<NetAddress>): void {
            let p1 = taskpool.execute((): NetAddress => {
                return this.getRemoteAddressSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as NetAddress);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getRemoteAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getRemoteAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getRemoteCertificate(callback: AsyncCallback<X509CertRawData>): void {
            let p1 = taskpool.execute((): X509CertRawData => {
                return this.getRemoteCertificateSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as X509CertRawData);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getRemoteCertificate(): Promise<X509CertRawData> {
            return new Promise<X509CertRawData>((resolve, reject) => {
                taskpool.execute((): X509CertRawData => {
                    return this.getRemoteCertificateSync();
                }).then((content: Any) => {
                    resolve(content as X509CertRawData);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getCipherSuite(callback: AsyncCallback<Array<string>>): void {
            let p1 = taskpool.execute((): Array<string> => {
                return this.getCipherSuiteSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as Array<string>);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getCipherSuite(): Promise<Array<string>> {
            return new Promise<Array<string>>((resolve, reject) => {
                taskpool.execute((): Array<string> => {
                    return this.getCipherSuiteSync();
                }).then((content: Any) => {
                    resolve(content as Array<string>);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSignatureAlgorithms(callback: AsyncCallback<Array<string>>): void {
            let p1 = taskpool.execute((): Array<string> => {
                return this.getSignatureAlgorithmsSync();
            });
            p1.then((content: Any) => {
                callback(new BusinessError(), content as Array<string>);
            }, (err: Error): void => {
                callback(err as BusinessError, undefined);
            });
        }

        getSignatureAlgorithms(): Promise<Array<string>> {
            return new Promise<Array<string>>((resolve, reject) => {
                taskpool.execute((): Array<string> => {
                    return this.getSignatureAlgorithmsSync();
                }).then((content: Any) => {
                    resolve(content as Array<string>);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getLocalAddress(): Promise<NetAddress> {
            return new Promise<NetAddress>((resolve, reject) => {
                taskpool.execute((): NetAddress => {
                    return this.getLocalAddressSync();
                }).then((content: Any) => {
                    resolve(content as NetAddress);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        getSocketFd(): Promise<int> {
            return new Promise<int>((resolve, reject) => {
                taskpool.execute((): int => {
                    return this.getSocketFdSync();
                }).then((content: Any) => {
                    resolve(content as int);
                }, (err: Error): void => {
                    reject(err as BusinessError);
                });
            });
        }

        onTlsConnMessage(callback: Callback<SocketMessageInfo>): void {
            this.onMessageInner(callback);
        }

        offTlsConnMessage(callback?: Callback<SocketMessageInfo>): void {
            this.offMessageInner(callback);
        }

        onTlsConnClose(callback: Callback<void>): void {
            this.onCloseInner(callback);
        }

        offTlsConnClose(callback?: Callback<void>): void {
            this.offCloseInner(callback);
        }

        onTlsConnError(callback: ErrorCallback): void {
            this.onErrorInner(callback);
        }

        offTlsConnError(callback?: ErrorCallback): void {
            this.offErrorInner(callback);
        }

        native sendSync(data: string | ArrayBuffer): void;
        native closeSync(): void;
        native getRemoteAddressSync(): NetAddress;
        native getRemoteCertificateSync(): X509CertRawData;
        native getCipherSuiteSync(): Array<string>;
        native getSignatureAlgorithmsSync(): Array<string>;
        native getLocalAddressSync(): NetAddress;
        native getSocketFdSync(): int;

        native onMessageInner(callback: Callback<SocketMessageInfo>): void;
        native offMessageInner(callback?: Callback<SocketMessageInfo>): void;
        native onCloseInner(callback: Callback<void>): void;
        native offCloseInner(callback?: Callback<void>): void;
        native onErrorInner(callback: ErrorCallback): void;
        native offErrorInner(callback?: ErrorCallback): void;
    }
}