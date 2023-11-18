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

#ifndef NET_WEBSOCKET_TYPE_H
#define NET_WEBSOCKET_TYPE_H

/**
 * @addtogroup netstack
 * @{
 *
 * @brief  为websocket客户端模块提供C接口
 *
 * @since 11
 * @version 1.0
 */

/**
 * @file net_websocket_type.h
 *
 * @brief 定义websocket客户端模块的C接口需要的数据结构
 *
 * @library libnet_websocket.so
 * @syscap SystemCapability.Communication.Netstack
 * @since 11
 * @version 1.0
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief websocket客户端来自服务端关闭的参数
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient_CloseResult {
    /** 关闭的错误码 */
    uint32_t code;
    /** 关闭的错误原因 */
    const char *reason;
};

/**
 * @brief websocket客户端主动关闭的参数
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient_CloseOption {
    /** 关闭的错误码 */
    uint32_t code;
    /** 关闭的错误原因 */
    const char *reason;
};

/**
 * @brief websocket客户端来自服务端连接错误的参数
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient_ErrorResult {
    /** 错误码 */
    uint32_t errorCode;
    /** 错误的消息 */
    const char *errorMessage;
};

/**
 * @brief websocket客户端来自服务端连接成功的参数
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient_OpenResult {
    /** websocket客户端连接成功码 */
    uint32_t code;
    /** websocket客户端连接原因 */
    const char *reason;
};

/**
 * @brief  websocket客户端接收open消息的回调函数定义
 *
 * @param client websocket客户端
 * @param openResult   websocket客户端接收建立连接消息的内容
 * @since 11
 * @version 1.0
 */
typedef void (*OH_NetStack_WebsocketClient_OnOpenCallback)(struct OH_NetStack_WebsocketClient *client,
                                                           OH_NetStack_WebsocketClient_OpenResult openResult);

/**
 * @brief  websocket客户端接收数据的回调函数定义
 *
 * @param client websocket客户端
 * @param data   websocket客户端接收的数据
 * @param length websocket客户端接收的数据长度
 * @since 11
 * @version 1.0
 */
typedef void (*OH_NetStack_WebsocketClient_OnMessageCallback)(struct OH_NetStack_WebsocketClient *client, char *data,
                                                              uint32_t length);

/**
 * @brief  websocket客户端接收error错误消息的回调函数定义
 *
 * @param client websocket客户端
 * @param errorResult   websocket客户端接收连接错误消息的内容
 * @since 11
 * @version 1.0
 */
typedef void (*OH_NetStack_WebsocketClient_OnErrorCallback)(struct OH_NetStack_WebsocketClient *client,
                                                            OH_NetStack_WebsocketClient_ErrorResult errorResult);

/**
 * @brief  websocket客户端接收close消息的回调函数定义
 *
 * @param client websocket客户端
 * @param closeResult   websocket客户端接收关闭消息的内容
 * @since 11
 * @version 1.0
 */
typedef void (*OH_NetStack_WebsocketClient_OnCloseCallback)(struct OH_NetStack_WebsocketClient *client,
                                                            OH_NetStack_WebsocketClient_CloseResult closeResult);

/**
 * @brief  websocket客户端增加header头的链表节点
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient_Slist {
    /** header头的字段名 */
    const char *FieldName;
    /**header头的字段内容 */
    const char *FieldValue;
    /** header头链表的next指针 */
    struct OH_NetStack_WebsocketClient_Slist *next;
};

/**
 * @brief  websocket客户端和服务端建立连接的参数
 *
 * @param headers header头信息
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient_RequestOptions {
    struct OH_NetStack_WebsocketClient_Slist *headers;
};

/**
 * @brief  websocket客户端结构体
 *
 * @since 11
 * @version 1.0
 */
struct OH_NetStack_WebsocketClient {
    /** 客户端接收连接消息的回调指针 */
    OH_NetStack_WebsocketClient_OnOpenCallback onOpen;
    /**客户端接收消息的回调指针 */
    OH_NetStack_WebsocketClient_OnMessageCallback onMessage;
    /** 客户端接收错误消息的回调指针 */
    OH_NetStack_WebsocketClient_OnErrorCallback onError;
    /** 客户端接收关闭消息的回调指针 */
    OH_NetStack_WebsocketClient_OnCloseCallback onClose;
    /** 客户端建立连接请求内容 */
    OH_NetStack_WebsocketClient_RequestOptions RequestOptions;
};

typedef enum OH_Websocket_ErrCode {
    /**
     * 执行成功
     */
    Websocket_OK = 0,

    /**
     * @brief 异常错误代码的基础
     */
    E_BASE = 1000,

    /**
     * @brief websocket为空
     */
    WEBSOCKET_CLIENT_IS_NULL = (E_BASE + 1),

    /**
     * @brief websocket未创建
     */
    WEBSOCKET_CLIENT_IS_NOT_CREAT = (E_BASE + 2),

    /**
     * @brief websocket客户端连接错误
     */
    WEBSOCKET_CONNECTION_ERROR = (E_BASE + 3),

    /**
     * @brief websocket客户端连接参数解析错误
     */
    WEBSOCKET_CONNECTION_PARSEURL_ERROR = (E_BASE + 5),

    /**
     * @brief websocket客户端连接时创建上下文无内存
     */
    WEBSOCKET_CONNECTION_NO_MEMOERY = (E_BASE + 6),

    /**
     * @brief 初始化时候关闭
     */
    WEBSOCKET_PEER_INITIATED_CLOSE = (E_BASE + 7),

    /**
     * @brief websocket连接被销毁
     */
    WEBSOCKET_DESTROY = (E_BASE + 8),

    /**
     * @brief websocket客户端连接时候协议错误
     */
    WEBSOCKET_PROTOCOL_ERROR = (E_BASE + 9),

    /**
     * @brief websocket客户端发送数据时候没有足够内存
     */
    WEBSOCKET_SEND_NO_MEMOERY_ERROR = (E_BASE + 10),

    /**
     * @brief websocket客户端发送数据为空
     */
    WEBSOCKET_SEND_DATA_NULL = (E_BASE + 11),

    /**
     * @brief websocket客户端发送数据长度超限制
     */
    WEBSOCKET_DATA_LENGTH_EXCEEDS = (E_BASE + 12),

    /**
     * @brief websocket客户端发送数据队列长度超限制
     */
    WEBSOCKET_QUEUE_LENGTH_EXCEEDS = (E_BASE + 13),

    /**
     * @brief websocket客户端上下文为空
     */
    WEBSOCKET_ERROR_NO_CLIENTCONTEX = (E_BASE + 14),

    /**
     * @brief websocket客户端header头异常
     */
    WEBSOCKET_ERROR_NO_HEADR_CONTEXT = (E_BASE + 15),

    /**
     * @brief websocket客户端header头超过限制
     */
    WEBSOCKET_ERROR_NO_HEADR_EXCEEDS = (E_BASE + 16),

    /**
     * @brief websocket客户端没有连接
     */
    WEBSOCKET_ERROR_HAVE_NO_CONNECT = (E_BASE + 17),

    /**
     * @brief websocket客户端没有连接上下文
     */
    WEBSOCKET_ERROR_HAVE_NO_CONNECT_CONTEXT = (E_BASE + 18),

} OH_Websocket_ErrCode;

#ifdef __cplusplus
}
#endif

#endif // NET_WEBSOCKET_TYPE_H
