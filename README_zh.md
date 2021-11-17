# 电话子系统网络协议栈组件<a name="ZH-CN_TOPIC_0000001125689015"></a>

-   [简介](#section11660541593)
-   [目录](#section1464106163817)
-   [接口](#section1096322014288)
-   [相关仓](#section11683135113011)

## 简介<a name="section11660541593"></a>

**电话子系统网络协议栈组件**，是OpenHarmony为开发者提供的一套开发OpenHarmony应用的Http、Socket、WebSocket等网络协议栈的API的适配层框架。目前主要由以下两部分组成:

1、标准系统上基于NAPI的JS适配层。

2、轻量级系统和小型系统上基于JSI的JS适配层。

## 目录<a name="section1464106163817"></a>

电话子系统网络协议栈组件源代码在 **/foundation/communication/netstack**，目录结构如下所示：

```
/foundation/communication/netstack
├── frameworks         # 框架代码目录
│   ├── js             # JS适配层
│       ├── builtin    # 轻量级系统和小型系统上基于JSI的JS适配层
│       └── napi       # 标准系统上基于NAPI的JS适配层
├── interfaces         # 对外暴露的API
│   └── kits           # OpenHarmony SDK API, 包括Java、Js、Native, 目前只有JS
│       └── js         # JS API
├── utils              # 公共工具
│   └── log            # 日志工具
```

## 接口<a name="section1096322014288"></a>

```
export interface FetchResponse {
  /**
   * Server status code.
   * @since 3
   */
  code: number;

  /**
   * Data returned by the success function.
   * @since 3
   */
  data: string | object;

  /**
   * All headers in the response from the server.
   * @since 3
   */
  headers: Object;
}

/**
 * @Syscap SysCap.ACE.UIEngine
 */
export default class Fetch {
  /**
   * Obtains data through the network.
   * @param options
   */
  static fetch(options: {
    /**
     * Resource URL.
     * @since 3
     */
    url: string;

    /**
     * Request parameter, which can be of the string type or a JSON object.
     * @since 3
     */
    data?: string | object;

    /**
     * Request header, which accommodates all attributes of the request.
     * @since 3
     */
    header?: Object;

    /**
     * Request methods available: OPTIONS, GET, HEAD, POST, PUT, DELETE and TRACE. The default value is GET.
     * @since 3
     */
    method?: string;

    /**
     * The return type can be text, or JSON. By default, the return type is determined based on Content-Type in the header returned by the server.
     * @since 3
     */
    responseType?: string;

    /**
     * Called when the network data is obtained successfully.
     * @since 3
     */
    success?: (data: FetchResponse) => void;

    /**
     * Called when the network data fails to be obtained.
     * @since 3
     */
    fail?: (data: any, code: number) => void;

    /**
     * Called when the execution is completed.
     * @since 3
     */
    complete?: () => void;
  }): void;
}
```

## 相关仓<a name="section11683135113011"></a>

[ ace_engine_lite ](https://gitee.com/openharmony/ace_engine_lite)

[ third_party_curl ](https://gitee.com/openharmony/third_party_curl)

[ third_party_mbedtls ](https://gitee.com/openharmony/third_party_mbedtls)
