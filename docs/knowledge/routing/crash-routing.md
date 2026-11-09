# 崩溃/内存问题路由

> 遇到崩溃、UAF、内存泄漏时按本文定位：先查高危文件清单，再按"现象→疑因→排查入口"表进入具体文件与行号。本仓历史失效模式第一名是 UAF/double-close，第二名是竞态/锁缺失。

## 1. 崩溃时先默念三条铁律

1. 所有 JS 回调必须经 `utils/napi_utils/src/event_manager.cpp` 的 `EmitByUv`（`uv_queue_work`）切回 JS 线程；绕过即偶崩。
2. 异步回调中必须有 `napi_handle_scope`（历史违规提交 0641ef07）。
3. 证书锁定/SSL 初始化禁止在 JS 线程执行（`http_exec.cpp` 的 `SetServerSSLCertOption` 在 worker 线程做，:696/:707/:713）。

## 2. 高危文件清单

### 2.1 UAF/double-close 热点（改动必须配套回归用例）

| 文件 | 热点说明 |
|---|---|
| `frameworks/js/napi/tls/src/tls_socket.cpp` | TLS 客户端 close 并发、证书对象生命周期（1982 行） |
| `frameworks/js/napi/tls/src/tlssocket_exec.cpp` | exec 层与 native 层对象交叠区 |
| `frameworks/js/napi/tls/src/monitor.cpp` | 连接监测器，close 双杀历史第一案发地 |
| `utils/napi_utils/src/event_manager.cpp` | listener 表与 `EmitByUv` 的共享锁 `mutexForListenersAndEmitByUv_`（:42-:100 独占/共享锁交错，:116 `EmitByUvWithoutCheckShared`）；事件投递与模块卸载并发即 UAF |
| `frameworks/js/napi/socket/socket_exec/src/socket_exec.cpp` | fd 生命周期与 close 路径（3296 行） |

### 2.2 内存泄漏热点

| 位置 | 热点说明 |
|---|---|
| `utils/napi_utils/src/napi_utils.cpp` | uv 入队失败分支的历史泄漏模式：失败路径资源未回收 |
| `frameworks/native/tls_socket/src/tls_certificate.cpp` 等 TLS X509/BIO 结构 | openssl 对象漏 free |

## 3. 崩溃现象 → 疑因 → 排查入口

| 现象 | 疑因 | 排查入口 |
|---|---|---|
| TLS close 时崩溃 | close 并发 UAF/double-close | `frameworks/js/napi/tls/src/monitor.cpp`（先看 close 消息与 join 时序），再对 `tlssocket_exec.cpp` |
| 握手完成拿证书时崩溃 | 证书对象已被释放（跨层所有权交叠） | `frameworks/js/napi/tls/src/tls_socket.cpp` 证书解析/持有段 |
| 异步回调偶发崩溃 | 缺 `napi_handle_scope` | `frameworks/js/napi/http/http_exec/src/http_exec.cpp` 回调入口 + `utils/napi_utils/src/napi_utils.cpp` |
| 事件投递时崩溃 | EmitByUv 生命周期竞争（listener 已销毁仍投递） | `utils/napi_utils/src/event_manager.cpp`（`mutexForListenersAndEmitByUv_`、`EmitByUvWithoutCheckShared` :116） |
| 请求无回调 + 内存增长 | uv 入队失败分支泄漏 | `utils/napi_utils/src/napi_utils.cpp` |
| 长跑内存缓慢增长 | TLS X509/BIO 漏 free | `frameworks/native/tls_socket/src/` 各 cpp 的 openssl 对象配对 |

## 4. 排查链路参考（文字+行号）

- TLS close 崩溃链：JS close() → `frameworks/js/napi/tls/src/tlssocket_exec.cpp`（exec）→ `frameworks/js/napi/tls/src/monitor.cpp`（监测器收 close 消息）→ 释放 `tls_socket.cpp` 侧连接对象；并发点在"同一连接收到两次 close 或 close 与回调并发"。
- 事件投递链：引擎回调（`utils/http_over_curl/include/transfer_callbacks.h`）→ `utils/napi_utils/src/event_manager.cpp` `EmitByUv`（uv_queue_work）→ `EmitByUvWithoutCheckShared`（:116）→ JS 回调；若模块在 uv 排队期间卸载，即命中 `mutexForListenersAndEmitByUv_` 保护范围。
- 异步回调链：`http_exec.cpp:1341` `HttpExec::ExecRequest` … `EmitByUv` 后 JS 线程执行回调；偶崩基本是 handle_scope 或 napi_ref 已失效，见 `request_context.cpp`（1794 行，napi_ref 持有点）。
- 历史高危修复与修复被 revert 的教训：先读 [../expert/historical-failures.md](../expert/historical-failures.md)，避免重复踩坑（如 25bd2e61 引擎区踩内存修复被 revert）。

## 5. 修复后必做

- TLS 系（`tls_socket.cpp`/`tlssocket_exec.cpp`/`monitor.cpp`）改动：close 并发场景用例必须通过。
- 引擎区（`utils/http_over_curl`）改动：确认 socket/tls 回归测试已跑（历史 revert 教训）。
- 新失效模式：回写 [../expert/historical-failures.md](../expert/historical-failures.md)，并在本文增补路由条目。

## 关联知识

- [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)：napi_ref/RequestContext/UAF 陷阱详解
- [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md)：close 并发与线程规则
- [../expert/historical-failures.md](../expert/historical-failures.md)：历史失效模式排行与 revert 教训
- [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md)：TLS/Socket 文件全景
- [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md)：回调链路全景
- [task-routing.md](task-routing.md)：按任务场景路由

## 适用场景

- 拿到崩溃栈/泄漏报告，需要快速定位疑因与热点文件
- 改动 TLS 系、event_manager、socket_exec 等高危文件前的风险评估
- 修复完成后确定必须跑的回归用例范围
