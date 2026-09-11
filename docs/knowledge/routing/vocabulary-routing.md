# 词汇触发路由

> 任务描述或评审意见中出现下表术语时，先读"指向"的文档对应小节再动手。术语是本仓的行话，每个词背后都绑定一组文件与约束。

使用方法：在任务描述、需求文档、MR 评审意见中搜到表中术语 → 按术语"含义"判断是否相关 → 跳转"指向"列。
若术语未命中，先查 [task-routing.md](task-routing.md) 的场景表，再看 [../code_map/netstack-code-map.md](../code_map/netstack-code-map.md) 的目录职责表。

| 术语 | 含义 | 指向 |
|---|---|---|
| `HttpExec` | HTTP 请求执行核心（`frameworks/js/napi/http/http_exec/src/http_exec.cpp`，3741 行；`ExecRequest`→`RequestWithoutCache`→`AddCurlHandle`） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) |
| `RequestWithoutCache` | 缓存未命中后的真实网络请求构造（`http_exec.cpp:726`：curl_easy_init→SetOption→AddCurlHandle） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 主链路 |
| `AddCurlHandle` | 把 easy handle 交给引擎（`http_exec.cpp:674`；:695 Hitrace StartAsyncTrace、:696/:707/:713 `SetServerSSLCertOption` 在 worker 线程做） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 主链路 |
| `HttpSession` | curl 会话封装（easy handle 池化；`frameworks/native/http/http_client/http_client.cpp:63` GetInstance 入口） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) NDK 路径章节 |
| `HttpClientTask` | innerkits HTTP 客户端任务对象（`frameworks/native/http/http_client/http_client_task.cpp`，1867 行，直接持有 `CURL*`） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) NDK 路径章节 |
| `EpollMultiDriver` | epoll + curl_multi 驱动引擎（`utils/http_over_curl/src/epoll_multi_driver.cpp`） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) |
| `EpollRequestHandler` | 单请求 epoll 事件处理器（`utils/http_over_curl/src/epoll_request_handler.cpp:41` `Process`，socket/timer 管理） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) |
| `TransferCallbacks` | curl 数据/头部/进度回调集合（`utils/http_over_curl/include/transfer_callbacks.h`） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 主链路 |
| `EventManager`/`EventListener` | JS 事件管理器；`EmitByUv` 是回 JS 线程唯一合法通道（`utils/napi_utils/src/event_manager.cpp`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) + [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md) |
| `RequestContext` | 异步请求上下文（`frameworks/js/napi/http/async_context/src/request_context.cpp`，1794 行；持有 napi_ref，生命周期/UAF 敏感） | [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md) |
| `HttpInterceptor` | 网络拦截器（五类切点，`frameworks/js/napi/http/http_interceptor/src/http_interceptor.cpp:1416` `ExecuteConnectNetworkInterceptor`） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 拦截器章节 |
| `CacheProxy`/`LruCache`/`CacheStrategy` | HTTP 缓存代理、LRU 淘汰与缓存策略（`frameworks/js/napi/http/cache/cache_proxy/` + `interfaces/innerkits/http_client/cache/{lru_cache,cache_strategy}/`） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 缓存链章节 |
| handover/`DeadFlowReset` | 多网切换与死流复位（`utils/http_over_curl/include/http_handover_handler.h`、`http_deadflow_info.h`，宏 `HTTP_DEADFLOWRESET_FEATURE`） | [../expert/historical-failures.md](../expert/historical-failures.md) |
| `HttpHandoverHandler` | handover 事件处理器（`utils/http_over_curl/src/epoll_multi_driver.cpp:44` 创建并注册 polling，:113-116 事件/超时分支） | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) handover 章节 |
| `Socks5AuthState` | SOCKS5 认证状态机状态枚举（`frameworks/js/napi/proxy/include/socks5.h:50`，配套 `Socks5Status:56`） | [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md) SOCKS5 章节 |
| `TaskPriority` | socket 异步任务优先级（`frameworks/js/napi/socket/task_queue/`，`PushTask` 按级入队） | [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md) Socket 章节 |
| `EmitByUv` | EventManager 中经 `uv_queue_work` 把事件切回 JS 线程的投递函数（`utils/napi_utils/src/event_manager.cpp`，无锁变体 `EmitByUvWithoutCheckShared:116`） | [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md) |
| `BaseAsyncWork`/`BaseContext` | 异步工作模板与上下文基类（`utils/napi_utils/include/base_async_work.h`；`napi_create_async_work` 落点 `utils/napi_utils/src/base_context.cpp:107`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) napi_utils 章节 |
| `module_template.h` | 模块注册/接口定义模板（`utils/napi_utils/include/module_template.h`），各 `*_module.cpp` 的母版 | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) napi_utils 章节 |
| CHR | Call Home Record，高频问题维测上报（`utils/netstack_chr_client/`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) 维测章节 |
| ANI | ArkTS Native Interface，ArkTS↔Rust 绑定（`frameworks/ets/ani/`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) |
| cxx 桥 | Rust↔C++ 互操作层（`interfaces/innerkits/rust/netstack_rs/`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) Rust 章节 |
| ylong | `ylong_http_client` 适配器 crate（`interfaces/innerkits/rust/ylong_http_client/`，reqwest_impl/ylong_impl 双后端） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) Rust 章节 |
| `SecureChar` | 脱敏字符串容器（密码/token 不落日志，`utils/napi_utils/include/secure_char.h:24`；TLS 侧对偶 `SecureData`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) napi_utils 章节 |
| `SecureData` | TLS 证书/密钥数据安全容器（`frameworks/native/tls_socket/include/secure_data.h:26`） | [../code_map/socket-tls-websocket-map.md](../code_map/socket-tls-websocket-map.md) TLS 章节 |
| `netstack_rs`/`ffrt_rs` | Rust inner API crate（`interfaces/innerkits/rust/`，Cargo.toml members） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) Rust 章节 |
| `NETSTACK_LOGx` | 日志宏族（`utils/log/include/netstack_log.h`，hilog domain `0xD0015B0`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) 日志章节 |
| HiAppEvent | 应用事件上报（`utils/napi_utils/include/hi_app_event_report.h`，事件名 "NetworkKit"/"HttpRequest"） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) napi_utils 章节 |
| `napi_handle_scope` | 异步回调必须持有的 napi 作用域（历史违规提交 0641ef07） | [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md) |
| `@system.fetch` | 旧 fetch API（`interfaces/kits/js/@system.fetch.d.ts` + `frameworks/js/napi/fetch/`） | [../code_map/netstack-code-map.md](../code_map/netstack-code-map.md) 目录职责表 |
| `netstack_http_boringssl` | BoringSSL 切换开关（`netstack_config.gni` declare_args，默认 `false`） | [task-routing.md](task-routing.md) 构建配置行 |
| `EmitByUvWithoutCheckShared` | EmitByUv 的无共享锁检查变体（`utils/napi_utils/src/event_manager.cpp:116`，与 `mutexForListenersAndEmitByUv_` 交界） | [crash-routing.md](crash-routing.md) 事件投递行 |
| `EventReport` | hiSysEvent 观测封装（`utils/common_utils/include/netstack_hisysevent.h`） | [../code_map/napi-multilanguage-map.md](../code_map/napi-multilanguage-map.md) common_utils 章节 |
| hasNetmanagerBase | 宏 `HAS_NETMANAGER_BASE`：编译期决定是否接入 netmanager_base（`NetConnClient` 取代理），关闭时走 `http_exec.cpp:1512-1577` 降级路径 | [../code_map/http-pipeline-map.md](../code_map/http-pipeline-map.md) 降级路径章节 |

## 术语维护规则

- 新增模块/能力引入新行话时：更新本表与 `AGENTS.md` §4 词汇触发路由，两表保持同源。
- 术语"指向"只允许指向真实存在的文档/文件；文档只增不删，过期术语标注沿用原文保留。
- 与崩溃强相关的术语（如 double-close、handover 错乱）补充路由到 [crash-routing.md](crash-routing.md) 对应现象行。

## 关联知识

- [task-routing.md](task-routing.md)：按任务场景路由
- [crash-routing.md](crash-routing.md)：按崩溃现象路由
- [../code_map/netstack-code-map.md](../code_map/netstack-code-map.md)：术语对应文件的全局位置

## 适用场景

- 阅读 PR/MR 描述、评审意见或需求文档时遇到行话
- 写 commit message / 知识文档前校准术语口径
