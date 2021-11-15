# Network Stack Component<a name="EN-US_TOPIC_0000001125689015"></a>

-   [Introduction](#section11660541593)
-   [Directory Structure](#section1464106163817)
-   [Available APIs](#section1096322014288)
-   [Repositories Involved](#section11683135113011)

## Introduction<a name="section11660541593"></a>

The **network stack component** is an adaptation layer framework for developers to develop network protocol stacks such as HTTP, socket and websocket for OpenHarmony applications. At present, it mainly consists of the following two parts:

1. NAPI based JS adaptation layer on L2.


2. JSI based JS adaptation layer on L0 and L1

## Directory Structure<a name="section1464106163817"></a>

The source code of the network stack component is stored in **/foundation/communication/netstack**. The directory structure is as follows:

```
/foundation/communication/netstack
├── frameworks         # Framework code
│   ├── js             # JS adaptation
│       ├── builtin    # JSI based JS adaptation layer on L0 and L1
│       └── napi       # NAPI based JS adaptation layer on L2.
├── interfaces         # APIs exposed externally
│   └── kits           # Huawei SDK API, including Java, JS and native. At present, there is only JS
│       └── js         # JS API
├── utils              # Common tools
│   └── log            # Log tool
```

## Available APIs<a name="section1096322014288"></a>

For details about the APIs, see the  [JS Application Development](https://device.harmonyos.com/en/docs/apiref/js-framework-file-0000000000616658).

## Repositories Involved<a name="section11683135113011"></a>

[ ace_engine_lite ](https://gitee.com/openharmony/ace_engine_lite)

[ third_party_curl ](https://gitee.com/openharmony/third_party_curl)

[ third_party_mbedtls ](https://gitee.com/openharmony/third_party_mbedtls)
