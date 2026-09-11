# netstack 总体代码地图

> 本文是 netstack 仓的全局导航图：给出五层架构、每个二级目录的职责、任务到路径的映射表与高风险文件 Top10。任何任务动手前先在此定位"代码在哪一层、先读哪篇专题文档"。

## 1. 组件定位与形态

- 职责：为应用与系统提供 HTTP(S)/HTTP3、TCP/UDP Socket、TLS Socket、WebSocket 的多语言客户端网络协议栈。
- 形态：**无 SA 进程的设备侧客户端协议栈库**——所有能力以库形态运行在调用方进程内，不存在独立网络服务进程。
- 与 netmanager_base 的关系：运行时通过 `NetConnClient` 获取代理与网络信息；编译期由宏 `HAS_NETMANAGER_BASE` 决定是否接入，改代理逻辑必须两种宏配置都考虑。
- 特性开关：`netstack_feature_http3`（bundle.json）、`netstack_http_boringssl`（netstack_config.gni，默认 `false`）、`ENABLE_HTTP_INTERCEPT`（拦截器）、`HTTP_DEADFLOWRESET_FEATURE`（死流复位）。
- 观测面：hilog domain `0xD0015B0`（utils/log）、`EventReport`（netstack_hisysevent）、HiAppEvent、CHR。

## 2. 分层架构（自上而下，禁止跨层耦合）

```
JS API 声明        interfaces/kits/js/*.d.ts
   ↓
NAPI/exec 层       frameworks/js/napi/{http,socket,tls,websocket,fetch,net_ssl,proxy}
   ↓
原生层             frameworks/native/* + inner API interfaces/innerkits/*
   ↓
执行引擎           utils/http_over_curl（epoll + curl_multi）
   ↓
三方依赖           curl / openssl / libwebsockets
```

- 多语言绑定与主链路平行存在：`frameworks/cj`（仓颉 FFI）、`frameworks/ets/ani`（ArkTS Rust ANI）、`interfaces/kits/c`（NDK）、`interfaces/innerkits/rust`（Rust inner API）。
- 架构不变量：NAPI exec 层不得直接耦合底层 curl API，必须经 `utils/http_over_curl` 封装；所有 JS 回调必须经 `utils/napi_utils/src/event_manager.cpp` 的 `EmitByUv` 切回 JS 线程。

## 3. 二级目录职责表

| 路径 | 职责 |
|---|---|
| `bundle.json` | 组件清单与部件级 feature 声明（如 `netstack_feature_http3`） |
| `netstack_config.gni` | GN 编译参数，`declare_args` 含 `netstack_http_boringssl`（默认 `false`） |
| `Cargo.toml` | Rust 工作区：members 含 `frameworks/ets/ani/*` 与 `interfaces/innerkits/rust/{netstack_rs,ffrt_rs}` |
| `frameworks/js/napi/http` | HTTP NAPI exec：`http_module`（注册）/`http_exec`（执行核心）/`async_context`/`async_work`/`cache`/`http_interceptor`/`options`/`constant` |
| `frameworks/js/napi/socket` | TCP/UDP/LocalSocket NAPI exec：`socket_exec`/`task_queue`/`options`/`async_context`/`async_work` |
| `frameworks/js/napi/tls` | TLS Socket NAPI exec：`tls_socket.cpp`/`tls_socket_server.cpp`/`monitor.cpp`/`tlssocket_exec.cpp` 等 |
| `frameworks/js/napi/websocket` | WebSocket NAPI exec：`websocket_exec`/`websocket_server_exec` |
| `frameworks/js/napi/fetch` | 旧 `@system.fetch` API 的 exec（fetch_exec/fetch_module） |
| `frameworks/js/napi/net_ssl` | 证书 API NAPI exec（net_ssl_exec/net_ssl_module） |
| `frameworks/js/napi/proxy` | SOCKS5 代理实现（include/socks5.h 状态机） |
| `frameworks/cj` | 仓颉 FFI 绑定：`http`/`socket`/`websocket`/`network_security` |
| `frameworks/ets/ani` | ArkTS↔Rust ANI 绑定：`http`/`net_ssl`/`web_socket`/`common` |
| `frameworks/native/http/http_client` | innerkits HTTP 客户端：`http_client_task.cpp`（HttpClientTask）、`http_client.cpp`（HttpSession） |
| `frameworks/native/http/http_curl` | curl C API 封装头 `http_curl.h` |
| `frameworks/native/http/http_rust` | Rust 后端封装头 `http_rust.h` |
| `frameworks/native/http_interceptor` | 拦截器 native 实现（http_interceptor_mgr.cpp） |
| `frameworks/native/tls_socket` | TLS 原生层：tls_context/tls_context_server/tls_certificate/tls_key/secure_data 等 |
| `frameworks/native/websocket_native` | WebSocket 原生层（websocket_client.cpp/websocket_server.cpp，基于 libwebsockets） |
| `frameworks/native/net_ssl` | 证书校验原生层（net_ssl.cpp/net_ssl_verify_cert.cpp） |
| `interfaces/kits/js` | 公共 JS API 声明：`@ohos.net.http.d.ts`/`@ohos.net.socket.d.ts`/`@ohos.net.webSocket.d.ts`/`@system.fetch.d.ts` |
| `interfaces/kits/c` | NDK：`net_http`/`net_websocket`/`net_ssl`/`http_interceptor`/`common`（netstack_hash_map） |
| `interfaces/innerkits/http_client` | HTTP inner API：include/（http_client_task.h 等）+ `cache/`（双层缓存的 innerkits 侧） |
| `interfaces/innerkits/{tls_socket,websocket_native,net_ssl,http_interceptor}` | 各模块 inner API 头文件与 .map 版本约束 |
| `interfaces/innerkits/rust` | Rust inner API：`netstack_rs`（cxx 桥）、`ffrt_rs`、`ylong_http_client` |
| `utils/napi_utils` | NAPI 公共设施：EventManager/EventListener、BaseContext、BaseAsyncWork、module_template.h、SecureChar、hi_app_event_report.h |
| `utils/http_over_curl` | 执行引擎：epoll+curl_multi 驱动、handover/deadflow、TransferCallbacks |
| `utils/common_utils` | 公共工具：netstack_common_utils、EventReport（netstack_hisysevent.h）、apipolicy、bundle_utils、socket_statistics |
| `utils/log` | 日志封装（domain `0xD0015B0`，NETSTACK_LOGx） |
| `utils/netstack_chr_client` | CHR 维测上报客户端 |
| `utils/profiler_utils` | 网络 profiler 消息封装 |
| `utils/tlv_utils` | TLV 序列化工具 |
| `test` | `test/unittest`（模块级单测）与 `test/fuzztest` |

## 4. 任务到路径映射

| 任务类型 | 先看这里 | 原因 |
|---|---|---|
| 公共 JS API 变更 | `interfaces/kits/js/` | 接口稳定性基线 |
| NDK API 变更 | `interfaces/kits/c/` | NDK 头文件与实现同目录 |
| HTTP 执行链修改 | `frameworks/js/napi/http/` + `utils/http_over_curl/` | 链路最长，见 [http-pipeline-map.md](http-pipeline-map.md) |
| HTTP 缓存逻辑 | `frameworks/js/napi/http/cache/` + `interfaces/innerkits/http_client/cache/` | 双层缓存，策略集中在 cache_strategy |
| 拦截器 | `frameworks/js/napi/http/http_interceptor/` + `frameworks/native/http_interceptor/` | exec 侧切点 + native 管理 |
| TCP/UDP Socket | `frameworks/js/napi/socket/` | `socket_exec.cpp` 为大文件 |
| TLS Socket | `frameworks/js/napi/tls/` + `frameworks/native/tls_socket/` | UAF/double-close 历史第一高发区 |
| WebSocket | `frameworks/js/napi/websocket/` + `frameworks/native/websocket_native/` | 基于 libwebsockets |
| SOCKS5 代理 | `frameworks/js/napi/proxy/` | 状态机集中在 socks5.h，依赖 `HAS_NETMANAGER_BASE` 宏 |
| 证书 API | `frameworks/js/napi/net_ssl/` + `interfaces/innerkits/net_ssl/` | 证书校验横跨三层 |
| 多网切换 handover | `utils/http_over_curl/src/http_handover_handler.cpp` | 死流复位与 handover 事件 |
| Rust/ANI 变更 | `interfaces/innerkits/rust/` + `frameworks/ets/ani/` | Cargo members |
| 仓颉绑定 | `frameworks/cj/` | FFI 与 NAPI 行为需对齐 |
| 事件分发/线程切换 | `utils/napi_utils/src/event_manager.cpp` | 所有回调回 JS 线程的咽喉 |
| 日志/维测 | `utils/log/` + `utils/netstack_chr_client/` + `utils/common_utils/` | hilog/hisysevent/CHR |
| 新增测试用例 | `test/unittest` + `test/fuzztest` | 按模块目录对号入座 |

## 5. 高风险文件 Top10（按行数）

| 文件 | 行数 | 风险点 |
|---|---|---|
| `frameworks/js/napi/http/http_exec/src/http_exec.cpp` | 3741 | 执行核心，改动必须绑定回归测试 |
| `frameworks/js/napi/socket/socket_exec/src/socket_exec.cpp` | 3296 | close 路径与 fd 生命周期 |
| `frameworks/js/napi/tls/src/tls_socket.cpp` | 1982 | UAF/double-close 第一热点 |
| `frameworks/native/http/http_client/http_client_task.cpp` | 1867 | NDK 请求任务，直接持有 `CURL*` |
| `frameworks/js/napi/http/async_context/src/request_context.cpp` | 1794 | 持有 napi_ref，生命周期敏感 |
| `frameworks/js/napi/tls/src/tls_socket_server.cpp` | 1744 | 服务端 close 并发 |
| `frameworks/js/napi/http/http_interceptor/src/http_interceptor.cpp` | 1510 | 五类切点插桩 |
| `frameworks/js/napi/websocket/websocket_exec/src/websocket_server_exec.cpp` | 1464 | 服务端连接管理 |
| `frameworks/js/napi/socket/socket_exec/src/local_socket_exec.cpp` | 1463 | 本地 socket 特有路径 |
| `frameworks/js/napi/socket/socket_module/src/socket_module.cpp` | 1419 | 模块注册与接口聚合 |

以上大文件改动必须配套回归用例，详见 [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)。

## 关联知识

- [http-pipeline-map.md](http-pipeline-map.md)：HTTP 请求全链路逐步拆解
- [socket-tls-websocket-map.md](socket-tls-websocket-map.md)：Socket/TLS/WebSocket 模块结构
- [napi-multilanguage-map.md](napi-multilanguage-map.md)：NAPI 基础设施与四套语言绑定
- [../routing/task-routing.md](../routing/task-routing.md)：场景路由总表
- [../routing/crash-routing.md](../routing/crash-routing.md)：崩溃/内存问题按特征定位
- [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)：生命周期/napi_ref/UAF 高发区

## 适用场景

- 第一次进入本仓，需要建立全局认知
- 不确定某任务属于哪个模块、该读哪篇文档
- 评估改动影响面（跨目录/跨语言/跨层）
