# AGENTS.md — netstack 领域知识入口（AI Agent 必读）

> 组件 `@ohos/netstack` | subsystem `communication` | SysCap `SystemCapability.Communication.NetStack` | hilog domain `0xD0015B0`
> 本文件是本仓 AI Agent 工作的第一入口。领域知识库位于 `docs/knowledge/`（13 篇，见 §3）。**编辑任何代码前必须完成 §5 编辑前声明。**

## 1. 项目定位

- 职责一句话：为应用与系统提供 HTTP(S)/HTTP3、TCP/UDP Socket、TLS Socket、WebSocket 的多语言客户端网络协议栈。
- 定位：**无 SA 进程的设备侧客户端协议栈库**——所有能力以库形态运行在调用方进程内，不存在独立网络服务进程；`Cargo.toml` members 含 `frameworks/ets/ani/*`、`interfaces/innerkits/rust/*`（C++/Rust 混合仓）。
- 与 netmanager_base 的关系：运行时通过 `NetConnClient` 获取代理与网络信息；编译期由宏 `HAS_NETMANAGER_BASE` 决定是否接入（决定代码路径分叉，改动代理逻辑必须两种宏配置都考虑）。
- 特性开关：`netstack_feature_http3`（HTTP3/QUIC）、`netstack_http_boringssl`（默认 `false`，切换 BoringSSL）、`ENABLE_HTTP_INTERCEPT`（拦截器）、`HTTP_DEADFLOWRESET_FEATURE`（死流复位）。
- 分层（自上而下，禁止跨层耦合）：
  1. JS API 声明：`interfaces/kits/js/*.d.ts`
  2. NAPI/exec 层：`frameworks/js/napi/{http,socket,tls,websocket,net_ssl,proxy}`
  3. 原生层：`frameworks/native/{http/http_client,tls_socket,websocket_native}` + innerkits `interfaces/innerkits/{http_client,websocket_native,net_ssl,http_interceptor,tls_socket}`
  4. 执行引擎：`utils/http_over_curl`（epoll + curl_multi）
  5. 三方依赖：curl / openssl / libwebsockets
- 多语言绑定：`frameworks/cj/*`（仓颉 FFI）、`frameworks/ets/ani/*`（ArkTS Rust ANI）、`interfaces/kits/c/{net_http,net_websocket,net_ssl,http_interceptor}`（NDK）。**同一能力变更需同步所有绑定。**
- 观测：`EventReport`（hiSysEvent）、HiAppEvent（`"NetworkKit"` / `"HttpRequest"`）、CHR 上报。

## 2. 任务到路径映射

| 任务类型 | 先看这里 | 原因 |
|---|---|---|
| 公共 JS API 变更 | `interfaces/kits/js/` + [docs/knowledge/expert/api-compatibility-constraints.md](docs/knowledge/expert/api-compatibility-constraints.md) | 接口稳定性基线在此 |
| NDK 变更 | `interfaces/kits/c/` | NDK 头文件与实现，兼容性约束同上 |
| HTTP 执行链修改 | [docs/knowledge/code_map/http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) | 链路最长，横跨 exec/引擎/缓存/拦截器 |
| NAPI 基础设施/多语言绑定 | [docs/knowledge/code_map/napi-multilanguage-map.md](docs/knowledge/code_map/napi-multilanguage-map.md) | js/cj/ani/NDK 四套绑定共享生命周期规则 |
| 崩溃/UAF/内存问题 | [docs/knowledge/routing/crash-routing.md](docs/knowledge/routing/crash-routing.md) | 按崩溃特征直接定位热点文件 |
| HTTP 缓存逻辑 | `frameworks/js/napi/http/cache/`（cache_proxy/lru_cache/cache_strategy）+ `interfaces/innerkits/http_client/cache/` | 双层缓存结构，策略集中在 cache_strategy |
| TLS Socket | `frameworks/js/napi/tls/` + `frameworks/native/tls_socket` | UAF/double-close 历史第一高发区 |
| TCP/UDP Socket | `frameworks/js/napi/socket/` | `socket_exec.cpp`（3296 行）大文件 |
| 代理/SOCKS5 | `frameworks/js/napi/proxy/` + `NetConnClient` 取代理逻辑 | 依赖 `HAS_NETMANAGER_BASE` 宏 |
| WebSocket | `frameworks/js/napi/websocket/` + `frameworks/native/websocket_native` | 基于 libwebsockets |
| 多网切换/handover | `utils/http_over_curl/src/http_handover_handler.cpp` | 历史错乱修复 9993be68 所在区 |
| Rust/ANI 变更 | `interfaces/innerkits/rust/` + `frameworks/ets/ani/` | Rust 侧 inner API，Cargo members |
| 事件分发/线程切换 | `utils/napi_utils/src/event_manager.cpp` | 所有回调回 JS 线程的咽喉 |
| 新增任务类型（不确定去处） | [docs/knowledge/routing/task-routing.md](docs/knowledge/routing/task-routing.md) | 场景路由总表 |

## 3. 知识索引（场景路由）

全部知识文档位于 `docs/knowledge/`，按场景先读一篇再动手：

| 场景 | 先读 |
|---|---|
| 了解全仓分层/目录职责 | [docs/knowledge/code_map/netstack-code-map.md](docs/knowledge/code_map/netstack-code-map.md) |
| HTTP 请求如何一步步执行 | [docs/knowledge/code_map/http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| Socket/TLS/WebSocket 模块结构 | [docs/knowledge/code_map/socket-tls-websocket-map.md](docs/knowledge/code_map/socket-tls-websocket-map.md) |
| NAPI 基础设施与 cj/ani/NDK 绑定 | [docs/knowledge/code_map/napi-multilanguage-map.md](docs/knowledge/code_map/napi-multilanguage-map.md) |
| 不确定任务归类 | [docs/knowledge/routing/task-routing.md](docs/knowledge/routing/task-routing.md) |
| 看到术语不知道是什么 | [docs/knowledge/routing/vocabulary-routing.md](docs/knowledge/routing/vocabulary-routing.md) |
| 崩溃/泄漏/越界排查 | [docs/knowledge/routing/crash-routing.md](docs/knowledge/routing/crash-routing.md) |
| 线程/异步/callback 规则 | [docs/knowledge/expert/threading-model-constraints.md](docs/knowledge/expert/threading-model-constraints.md) |
| 生命周期/napi_ref/UAF 高发区 | [docs/knowledge/expert/lifecycle-uaf-pitfalls.md](docs/knowledge/expert/lifecycle-uaf-pitfalls.md) |
| API 兼容性红线 | [docs/knowledge/expert/api-compatibility-constraints.md](docs/knowledge/expert/api-compatibility-constraints.md) |
| 历史高危修复与 revert 教训 | [docs/knowledge/expert/historical-failures.md](docs/knowledge/expert/historical-failures.md) |
| 编译与测试命令 | [docs/knowledge/verify/build-and-test.md](docs/knowledge/verify/build-and-test.md) |
| 验证循环与 Done 定义 | [docs/knowledge/verify/verification-loop.md](docs/knowledge/verify/verification-loop.md) |

## 4. 词汇触发路由

任务描述中出现以下术语时，先读指向文档对应小节：

| 术语 | 含义 | 指向 |
|---|---|---|
| `HttpExec` | HTTP 请求执行核心（`http_exec.cpp`，3741 行，`ExecRequest`→`RequestWithoutCache`→`AddCurlHandle`） | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| `HttpSession` | curl 会话封装（easy handle 池化） | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| `HttpClientTask` | innerkits HTTP 客户端任务对象（C++ 调用方入口） | [socket-tls-websocket-map.md](docs/knowledge/code_map/socket-tls-websocket-map.md) |
| `EpollMultiDriver` | epoll + curl_multi 驱动引擎（`utils/http_over_curl`） | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| `EpollRequestHandler` | 单请求 epoll 事件处理器（socket/timer 管理） | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| `TransferCallbacks` | curl 数据/头部/进度回调集合 | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| `EventManager`/`EventListener` | JS 事件管理器，`EmitByUv` 是回 JS 线程唯一合法通道 | [napi-multilanguage-map.md](docs/knowledge/code_map/napi-multilanguage-map.md) + [threading-model-constraints.md](docs/knowledge/expert/threading-model-constraints.md) |
| `RequestContext` | 异步请求上下文（持有 napi_ref，生命周期/UAF 敏感） | [lifecycle-uaf-pitfalls.md](docs/knowledge/expert/lifecycle-uaf-pitfalls.md) |
| `HttpInterceptor` | 网络拦截器（五类切点，`ExecuteConnectNetworkInterceptor` 等） | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| `CacheProxy`/`LruCache` | HTTP 缓存代理与 LRU 淘汰（`frameworks/js/napi/http/cache/`） | [http-pipeline-map.md](docs/knowledge/code_map/http-pipeline-map.md) |
| handover / `DeadFlowReset` | 多网切换与死流复位（`HTTP_DEADFLOWRESET_FEATURE`） | [historical-failures.md](docs/knowledge/expert/historical-failures.md) |
| CHR | Call Home Record 高频问题上报 | [netstack-code-map.md](docs/knowledge/code_map/netstack-code-map.md) |
| ANI | ArkTS Native Interface（ArkTS↔Rust 绑定，`frameworks/ets/ani/`） | [napi-multilanguage-map.md](docs/knowledge/code_map/napi-multilanguage-map.md) |
| `SecureChar` | 脱敏字符串（密码/token 不落日志） | [netstack-code-map.md](docs/knowledge/code_map/netstack-code-map.md) |
| `EventReport` | hiSysEvent 观测封装 | [netstack-code-map.md](docs/knowledge/code_map/netstack-code-map.md) |

## 5. 编辑前声明要求

Agent 在编辑任何文件前，**必须在回复中显式回答以下三项**（缺一不可，答不出必须先读 §3 对应文档）：

1. **本次任务类别**：API 变更 / 执行链修改 / 崩溃修复 / 缓存策略 / 多语言绑定同步 / 工具与测试 / 文档（多选可叠加，如「崩溃修复 + tls」）。
2. **已读哪些知识文档**：列出本次已读的 `docs/knowledge/` 文档路径；至少包含任务类别对应的 §3 场景文档一篇。
3. **已知约束中哪些适用本任务**：从 §6 中点名适用的条目（如「适用：禁止绕过 EmitByUv；适用：tls 系 UAF 高发区需绑定回归」）。

## 6. 约束和边界

### 6.1 禁止事项（红线）

- 禁止在 JS 线程直接执行 curl/SSL 初始化；**证书锁定必须在 worker 线程**（详见 [threading-model-constraints.md](docs/knowledge/expert/threading-model-constraints.md)）。
- 禁止绕过 `EmitByUv`/`uv_queue_work` 直接在工作线程调用 JS 回调。
- 禁止在异步回调中缺少 `napi_handle_scope`（历史违规提交 0641ef07）。
- 禁止删除/注释失败测试用例使测试通过。
- 禁止未经用户确认提交代码。
- 禁止修改 auto-generated 代码段（如 IDL/工具生成物）。

### 6.2 需确认规则（改动前向用户确认）

- 修改 `utils/http_over_curl` 引擎区：历史 curl 踩内存修复曾被 revert（25bd2e61），需确认配套 socket/tls 回归测试已跑（见 [historical-failures.md](docs/knowledge/expert/historical-failures.md)）。
- 修改 tls 系文件（`tls_socket.cpp`/`tlssocket_exec.cpp`/`monitor.cpp`）：需确认 close 并发场景用例通过。

### 6.3 架构不变量

- NAPI exec 层**不得直接耦合底层 curl API**，必须经 `utils/http_over_curl` 封装。
- 接口稳定性以 `interfaces/`（kits 与 innerkits）为基线，行为变更须对照 [api-compatibility-constraints.md](docs/knowledge/expert/api-compatibility-constraints.md)。
- 所有 JS 回调必须经 `utils/napi_utils/src/event_manager.cpp` 的 `EmitByUv` 切回 JS 线程。

### 6.4 项目特定陷阱（历史失效模式排行）

1. **UAF/double-close**（第一热点）：`tls_socket.cpp`、`tlssocket_exec.cpp`、`monitor.cpp`、`utils/napi_utils/event_manager.cpp`——此区修复必须配套回归用例。
2. 竞态/锁缺失；3. 空指针；4. 内存泄漏（uv 入队失败分支、X509 结构）；5. NAPI/uv 生命周期违规（handle_scope 缺失）；6. 整数溢出；7. 多网切换 handover 错乱（9993be68）；8. **修复被 revert 的教训**（25bd2e61）。

大文件警告：`http_exec.cpp`（3741 行）、`socket_exec.cpp`（3296 行）改动必须绑定回归测试。详见 [lifecycle-uaf-pitfalls.md](docs/knowledge/expert/lifecycle-uaf-pitfalls.md) 与 [crash-routing.md](docs/knowledge/routing/crash-routing.md)。

### 6.5 Agent 失败模式（自我检查）

- 只改 JS 层，忘改 NDK/ANI/cj 绑定 → 改动任何接口后逐一核对 `interfaces/kits/c/`、`frameworks/ets/ani/`、`frameworks/cj/`。
- 在 close 路径加同步调用引发死锁 → close 并发设计见 [threading-model-constraints.md](docs/knowledge/expert/threading-model-constraints.md)。

## 7. 构建和验证

### 7.1 编译

```bash
# 组件整体
./build.sh --product-name rk3568 --build-target http --ccache
# innerkits 目标
./build.sh --product-name rk3568 --build-target http_client --ccache
./build.sh --product-name rk3568 --build-target websocket_native --ccache
./build.sh --product-name rk3568 --build-target net_ssl --ccache
```

### 7.2 按任务类型的验证表（改动 → 必跑测试）

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

### 7.3 Done 定义（全部满足才算完成）

1. 编译成功（上述命令无错误）。
2. §7.2 对应测试全部通过。
3. LSP/静态检查无新增 error。
4. 未破坏 API 兼容（`interfaces/` 基线，见 [api-compatibility-constraints.md](docs/knowledge/expert/api-compatibility-constraints.md)）。
5. 未违反 §6.1 任何禁止事项。
6. 代码已格式化（提交前 `clang-format` 校验）。

### 7.4 回退方案

- 验证不通过且短期无法修复：`git revert` 对应提交，不留在主干带病代码。
- **回退后必须把失效模式与教训回写** [historical-failures.md](docs/knowledge/expert/historical-failures.md)（参照 25bd2e61 revert 案例的记录格式）。

## 8. 文档维护

目录结构与更新规则：

```
docs/knowledge/
├── code_map/    # 代码地图：netstack-code-map.md, http-pipeline-map.md, socket-tls-websocket-map.md, napi-multilanguage-map.md
├── routing/     # 路由：task-routing.md, vocabulary-routing.md, crash-routing.md
├── expert/      # 专家约束：threading-model-constraints.md, lifecycle-uaf-pitfalls.md, api-compatibility-constraints.md, historical-failures.md
└── verify/      # 验证：build-and-test.md, verification-loop.md
```

更新规则：

- **新失效模式**（线上/测试新发现的崩溃形态、revert 教训）必须回写 `historical-failures.md`，同时在 `crash-routing.md` 增加路由条目。
- 新增目录/模块/测试 target：更新对应 `code_map/` 文档与本文 §2 表格。
- 新增术语：更新 `vocabulary-routing.md` 与本文 §4 表格。
- 修改编译命令/测试 target：同步 `build-and-test.md`、`verification-loop.md` 与本文 §7。
- 知识文档只增不删；过期内容标注 `已废弃` 并保留原文（历史教训不可丢弃）。
