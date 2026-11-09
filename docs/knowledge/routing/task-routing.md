# 任务场景路由

> 拿到一个任务不确定从哪里下手时，先在本文按场景查"先读什么、为什么"，再进入对应 code_map/expert 文档或源码路径。

## 1. 场景路由表

使用方法：按任务描述对号入座第一列 → 读"先读"列的文档/路径 → 按"原因"列确认风险面，再开始改代码。

| 场景 | 先读 | 原因 |
|---|---|---|
| 新增/修改 JS 公共 API | `interfaces/kits/js/*.d.ts` + [../expert/api-compatibility-constraints.md](../expert/api-compatibility-constraints.md) | 接口稳定性以 `interfaces/` 为基线，红线先行 |
| NDK API 变更 | `interfaces/kits/c/` + [../expert/api-compatibility-constraints.md](../expert/api-compatibility-constraints.md) | NDK 兼容约束与 JS 侧同等严格 |
| 修改 HTTP 执行链 | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) + `frameworks/js/napi/http/http_exec/src/http_exec.cpp` | 链路最长（3741 行大文件），需先看全链再动手 |
| 加拦截器 | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 拦截器章节 + `frameworks/js/napi/http/http_interceptor/src/http_interceptor.cpp` | 五类切点各有固定插入位置与签名 |
| 改缓存策略 | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 缓存链章节 + `interfaces/innerkits/http_client/cache/cache_strategy/` | 双层缓存（exec 层 + innerkits 层），策略集中在 cache_strategy，两层必须同步 |
| 修崩溃/UAF | [crash-routing.md](crash-routing.md) + [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md) | 按崩溃特征直接定位热点文件，先看历史失效模式避免重复踩坑 |
| 修竞态/锁问题 | [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md) + `utils/napi_utils/src/event_manager.cpp` | 线程规则与锁边界（如 `mutexForListenersAndEmitByUv_`）是本仓竞态主源 |
| 修内存泄漏 | [crash-routing.md](crash-routing.md) 泄漏热点章节 + `utils/napi_utils/src/napi_utils.cpp` | uv 入队失败分支、TLS X509/BIO 是历史泄漏高发点 |
| 事件分发/线程切换 | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) + `utils/napi_utils/src/event_manager.cpp` | 所有回调回 JS 线程的咽喉，绕过 `EmitByUv` 即偶崩 |
| 多网切换问题 | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) handover 章节 + `utils/http_over_curl/src/http_handover_handler.cpp` | handover/deadflow 逻辑集中在引擎区，历史错乱修复 9993be68 与 revert 教训见 [../expert/historical-failures.md](../expert/historical-failures.md) |
| SOCKS5 代理问题 | [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md) + `frameworks/js/napi/proxy/include/socks5.h` | 状态机（`Socks5AuthState`/`Socks5Status`）决定协商流程；注意 `HAS_NETMANAGER_BASE` 宏分叉 |
| TLS 证书问题 | [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md) + `frameworks/js/napi/tls/src/tls_socket.cpp` | 证书解析/校验横跨 exec 与 `frameworks/native/tls_socket/`，close 并发是第一热点 |
| WebSocket 问题 | [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md) + `frameworks/native/websocket_native/src/websocket_client.cpp` | 基于 libwebsockets，事件回 JS 必经 EmitByUv |
| Rust 侧修改 | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) + `interfaces/innerkits/rust/` | cxx 桥、双后端（reqwest_impl/ylong_impl）、Cargo members 联动 |
| 构建配置/feature 开关 | `netstack_config.gni` + `bundle.json` + `Cargo.toml` | `netstack_http_boringssl`/`netstack_feature_http3` 等开关分叉代码路径，两种配置都要编译验证 |
| 新增测试用例 | `test/unittest` + `test/fuzztest`（按模块目录对号） | 单测与 fuzz 均按模块组织；大文件改动必须绑定回归用例 |
| 多语言绑定同步 | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) 同步检查清单 | JS/NDK/ANI/仓颉/Rust 五个面行为必须一致 |
| 日志/维测问题 | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md)（utils/log、CHR、EventReport 章节） | hilog domain `0xD0015B0`、hiSysEvent、CHR 各有独立通道 |
| 全局认知/影响面评估 | [../code_map/netstack-code-map.md](../code_map/netstack-code-map.md) | 分层架构、目录职责表与高风险文件 Top10 |

## 2. 改动区域 → 必跑测试 target

改动落地前按区域对号跑测试，全部通过才算完成：

| 改动区域 | 必跑测试 target |
|---|---|
| HTTP 执行链 | `http_unittest`、`http_client_unittest`、`SocketExecFuzzTest` |
| 缓存 | `http_cache_unittest` |
| 拦截器 | `http_interceptor_unittest` |
| TLS | `tls_socket_unilateral_connection`、`two_way_tls_socket_server_unittest`、`TlsSocketFuzzTest` |
| Socket | `socket_unittest`、`SocketExecFuzzTest` |
| WebSocket | `websocket_unittest` |
| 多网切换 | `http_handover_handler_test` |
| 公共工具 | `netstack_common_utils_test` |
| net_ssl | `NetsslExecFuzzTest` |

测试代码按模块组织于 `test/unittest`（如 `test/unittest/utils/http_handover_handler/`）与 `test/fuzztest`。

## 3. 路由基本原则

- 大文件（`http_exec.cpp` 3741 行、`socket_exec.cpp` 3296 行等）改动必须绑定回归测试。
- 涉及接口的改动先过 [../expert/api-compatibility-constraints.md](../expert/api-compatibility-constraints.md) 红线，再考虑多语言同步（见 [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) 检查清单）。
- 高危区改动（TLS 系、引擎区）遵守 [crash-routing.md](crash-routing.md) 第 5 节"修复后必做"。

## 关联知识

- [vocabulary-routing.md](vocabulary-routing.md)：按术语触发
- [crash-routing.md](crash-routing.md)：按崩溃现象触发
- [../code_map/netstack-code-map.md](../code_map/netstack-code-map.md)
- [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md)
- [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md)
- [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md)
- [../expert/api-compatibility-constraints.md](../expert/api-compatibility-constraints.md)
- [../expert/historical-failures.md](../expert/historical-failures.md)

## 适用场景

- 任务描述模糊、不确定改动落点与风险面
- 新成员熟悉"什么任务先读什么"
