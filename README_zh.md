# 电话子系统网络协议栈组件<a name="ZH-CN_TOPIC_0000001125689015"></a>

-   [简介](#section11660541593)
-   [目录](#section1464106163817)
-   [接口](#section1096322014288)
-   [相关仓](#section11683135113011)

## 简介<a name="section11660541593"></a>

**电话子系统网络协议栈组件**，是OpenHarmony为开发者提供的一套开发OpenHarmony应用的Http、Socket、WebSocket等网络协议栈的API的适配层框架。目前主要由以下两部分组成:

1、L2上基于NAPI的JS适配层。

2、L0、L1上基于JSI的JS适配层。

## 目录<a name="section1464106163817"></a>

电话子系统网络协议栈组件源代码在 **/foundation/communication/netstack**，目录结构如下图所示：

```
/foundation/communication/netstack
├── frameworks         # 框架代码目录
│   ├── js             # JS适配层
│       ├── builtin    # L0、L1上基于JSI的JS适配层
│       └── napi       # L2上基于NAPI的JS适配层
├── interfaces         # 对外暴露的API
│   └── kits           # Huawei SDK API, 包括Java、Js、Native, 目前只有JS
│       └── js         # JS API
├── utils              # 公共工具
│   └── log            # 日志工具
```

## 接口<a name="section1096322014288"></a>

API介绍请参考[《OpenHarmony Device开发API参考》](https://device.harmonyos.com/cn/docs/develop/apiref/js-framework-file-0000000000611396)

## 相关仓<a name="section11683135113011"></a>

[ ace_engine_lite ](https://gitee.com/openharmony/ace_engine_lite)

[ third_party_curl ](https://gitee.com/openharmony/third_party_curl)

[ third_party_mbedtls ](https://gitee.com/openharmony/third_party_mbedtls)
