# Socket/TLS/WebSocket 模块地图

> 本文给出 Socket、TLS、WebSocket 三大模块与 SOCKS5 代理、证书 API 的目录结构、关键文件与风险点。TLS 系是本仓 UAF/double-close 历史第一高发区，改动前必读对应约束。

## 1. Socket（TCP/UDP/LocalSocket）

| 路径 | 内容 |
|---|---|
| `frameworks/js/napi/socket/socket_exec/src/socket_exec.cpp` | TCP/UDP exec 核心（3296 行），fd 生命周期与 close 路径集中地 |
| `frameworks/js/napi/socket/socket_exec/src/local_socket_exec.cpp` | LocalSocket exec（1463 行），本地 socket 特有路径 |
| `frameworks/js/napi/socket/socket_exec/src/socket_extra_exec.cpp` | 扩展接口 exec |
| `frameworks/js/napi/socket/socket_exec/src/connect_monitor.cpp` | 连接状态监测 |
| `frameworks/js/napi/socket/task_queue/` | 优先级任务队列：`TaskPriority` 分级排队，避免多异步任务乱序 |
| `frameworks/js/napi/socket/{async_context,async_work,options,constant,socket_module}` | 上下文/异步工作/参数解析/常量/注册，与 http 模块同构 |

- 队列入口：`task_queue/include` 中 `PushTask(TaskPriority priority, ...)` 按优先级入队。
- 执行链与 HTTP 同构：`async_work` 经 `utils/napi_utils/src/base_context.cpp` 的 `napi_create_async_work`，回调经 `utils/napi_utils/src/event_manager.cpp` 的 `EmitByUv` 回 JS 线程。

## 2. TLS Socket（UAF/double-close 第一高发区）

| 路径 | 内容 |
|---|---|
| `frameworks/js/napi/tls/src/tls_socket.cpp` | 客户端 exec（1982 行），握手/证书/close 核心 |
| `frameworks/js/napi/tls/src/tls_socket_server.cpp` | 服务端 exec（1744 行） |
| `frameworks/js/napi/tls/src/monitor.cpp` | 客户端连接监测器（close 并发/UAF 热点） |
| `frameworks/js/napi/tls/src/monitor_server.cpp` | 服务端连接监测器 |
| `frameworks/js/napi/tls/src/tlssocket_exec.cpp` | exec 公共实现 |
| `frameworks/js/napi/tls/src/tlssocket_module.cpp` 等 | 模块注册与 async_work（与 http 同构） |
| `frameworks/native/tls_socket/src/` | 原生实现：`tls_context.cpp`/`tls_context_server.cpp`/`tls_certificate.cpp`/`tls_key.cpp`/`tls_configuration.cpp`/`tls_config_enhanced.cpp`/`secure_data.cpp`/`socket_error.cpp`/`tls_utils.cpp` |
| `interfaces/innerkits/tls_socket/include/tls_socket.h`、`interfaces/innerkits/tls_socket/include/tls_socket_server.h` | inner API 基线 |

## 3. WebSocket（基于 libwebsockets）

| 路径 | 内容 |
|---|---|
| `frameworks/js/napi/websocket/` | NAPI exec：`websocket_exec/src/websocket_exec.cpp`（客户端，1258 行）、`websocket_exec/src/websocket_server_exec.cpp`（服务端，1464 行）+ async_context/async_work/constant |
| `frameworks/native/websocket_native/src/websocket_client.cpp` | 客户端原生实现 |
| `frameworks/native/websocket_native/src/websocket_server.cpp` | 服务端原生实现 |
| `interfaces/innerkits/websocket_native/include/websocket_client_innerapi.h` | 客户端 inner API |
| `interfaces/innerkits/websocket_native/include/websocket_server_innerapi.h` | 服务端 inner API（另有 client_context.h/server_context.h 承载上下文） |

- 事件（open/message/close/error）同样必须经 `utils/napi_utils/src/event_manager.cpp` 的 `EmitByUv` 回 JS 线程。

## 4. SOCKS5 代理

| 路径 | 内容 |
|---|---|
| `frameworks/js/napi/proxy/include/socks5.h` | 状态机核心：`Socks5AuthState`（:50 认证状态）、`Socks5Status`（:56 协议状态） |
| `frameworks/js/napi/proxy/include/socks5_instance.h` | 连接实例 |
| `frameworks/js/napi/proxy/include/socks5_method.h` | 认证方法接口 |
| `frameworks/js/napi/proxy/include/socks5_none_method.h` / `socks5_passwd_method.h` | 无认证/用户名密码两种方法 |
| `frameworks/js/napi/proxy/include/socks5_package.h` / `socks5_utils.h` | 报文封包与工具 |

- 代理来源依赖 `NetConnClient`（netmanager_base），编译期由 `HAS_NETMANAGER_BASE` 宏分叉；改动必须两种宏配置都验证。

## 5. 证书 API（net_ssl）

| 路径 | 内容 |
|---|---|
| `interfaces/innerkits/net_ssl/include/net_ssl.h`、`interfaces/innerkits/net_ssl/include/net_ssl_type.h` | inner API 与类型基线 |
| `frameworks/js/napi/net_ssl/` | NAPI exec：`net_ssl_exec`/`net_ssl_module`/async_context/async_work |
| `frameworks/native/net_ssl/net_ssl.cpp` | 原生实现 |
| `frameworks/native/net_ssl/net_ssl_verify_cert.cpp` | 证书校验实现 |

## 6. 风险点与必跑测试

- TLS close 并发是第一失效模式：`tls_socket.cpp`/`tlssocket_exec.cpp`/`monitor.cpp` 改动需确认 close 并发场景用例通过（约束见 [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md)）。
- 历史失效模式与热点剖析见 [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md) 与 [../routing/crash-routing.md](../routing/crash-routing.md)。
- `socket_exec.cpp` 与 `local_socket_exec.cpp` 均为大文件（3296/1463 行），改动必须绑定回归测试。

## 关联知识

- [netstack-code-map.md](netstack-code-map.md)：全局目录与分层
- [http-pipeline-map.md](http-pipeline-map.md)：exec 层同构的 HTTP 链路参考
- [napi-multilanguage-map.md](napi-multilanguage-map.md)：回调回 JS 线程的公共设施
- [../routing/crash-routing.md](../routing/crash-routing.md)：TLS 崩溃按现象定位
- [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)：UAF/double-close 陷阱清单
- [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md)：线程与回调规则

## 适用场景

- 修改 Socket/TLS/WebSocket/SOCKS5/证书任一模块前定位文件
- 排查 TLS close 崩溃、握手失败、WebSocket 断连、代理协商失败
- 评估某模块 inner API（`interfaces/innerkits/*`）变更的联动面
