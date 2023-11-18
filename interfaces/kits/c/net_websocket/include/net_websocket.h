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

#ifndef NET_WEBSOCKET_H
#define NET_WEBSOCKET_H

#include <signal.h>
#include <stdint.h>
#include <string.h>

/**
 * @addtogroup netstack
 * @{
 *
 * @brief 为websocket客户端模块提供C接口

 * @since 11
 * @version 1.0
 */

/**
 * @file net_websocket.h
 *
 * @brief 为websocket客户端模块定义C接口
 *
 * @library libnet_websocket.so
 * @syscap SystemCapability.Communication.Netstack
 * @since 11
 * @version 1.0
 */

#include "net_websocket_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  OH_NetStack_WebsocketClient客户端的构造函数
 *
 * @param onMessage 客户端定义的接收消息的回调函数
 * @param onClose   客户端定义的关闭消息的回调函数
 * @param onError   客户端定义的错误消息的回调函数
 * @param onOpen    客户端定义的建立连接消息的回调函数
 * @return 成功返回客户端指针，失败返回为NULL
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient *OH_NetStack_WebsocketClient_Construct(
    OH_NetStack_WebsocketClient_OnOpenCallback OnOpen, OH_NetStack_WebsocketClient_OnMessageCallback onMessage,
    OH_NetStack_WebsocketClient_OnErrorCallback OnError, OH_NetStack_WebsocketClient_OnCloseCallback onclose);

/**
 * @brief  将header头信息添加到client客户端request中
 *
 * @param client 客户端指针
 * @param header header头信息
 * @return 返回值为0表示执行成功。返回错细信息可以查看{@link OH_Websocket_ErrCode}。
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
int OH_NetStack_WebSocketClient_AddHeader(struct OH_NetStack_WebsocketClient *client,
                                          struct OH_NetStack_WebsocketClient_Slist header);

/**
 * @brief 客户端连接服务端
 *
 * @param client 客户端指针
 * @param url 客户端要连接到服务端的地址
 * @param options 发起连接的可选参数
 * @return 返回值为0表示执行成功。返回错细信息可以查看{@link OH_Websocket_ErrCode}。
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
int OH_NetStack_WebSocketClient_Connect(struct OH_NetStack_WebsocketClient *client, const char *url,
                                        struct OH_NetStack_WebsocketClient_RequestOptions options);

/**
 * @brief 客户端向服务端发送数据
 *
 * @param client 客户端
 * @param data   客户端发送的数据
 * @param length 客户端发送的数据长度
 * @return 0 - 成功.
 * @return 返回值为0表示执行成功。返回错细信息可以查看{@link OH_Websocket_ErrCode}。
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
int OH_NetStack_WebSocketClient_Send(struct OH_NetStack_WebsocketClient *client, char *data, size_t length);

/**
 * @brief 客户端主动关闭websocket连接
 *
 * @param client 客户端
 * @param url 客户端要连接到服务端的地址
 * @param options 发起关闭连接的可选参数
 * @return 返回值为0表示执行成功。返回错细信息可以查看{@link OH_Websocket_ErrCode}。
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
int OH_NetStack_WebSocketClient_Close(struct OH_NetStack_WebsocketClient *client,
                                      struct OH_NetStack_WebsocketClient_CloseOption options);

/**
 * @brief  释放websocket连接上下文和资源
 *
 * @param client 客户端
 * @return 返回值为0表示执行成功。返回错细信息可以查看{@link OH_Websocket_ErrCode}。
 * @permission ohos.permission.INTERNET
 * @syscap SystemCapability.Communication.NetStack
 * @since 11
 * @version 1.0
 */
int OH_NetStack_WebsocketClient_Destroy(struct OH_NetStack_WebsocketClient *client);

#ifdef __cplusplus
}
#endif

#endif // NET_WEBSOCKET_H
