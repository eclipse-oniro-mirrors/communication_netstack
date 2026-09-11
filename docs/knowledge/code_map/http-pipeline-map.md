# HTTP 请求执行链路地图

> 本文逐步拆解一次 HTTP 请求从 JS 调用到回调返回的完整路径，含拦截器五类切点、双层缓存链、无 netmanager_base 的降级路径、NDK 独立路径与多网切换 handover。修改 HTTP 执行链前必读。

## 1. 主链路（JS API → curl → JS 回调）

```
JS @ohos.net.http（interfaces/kits/js/@ohos.net.http.d.ts）
  → frameworks/js/napi/http/http_module/src/http_module.cpp（:70 InitHttpModule 注册模块）
  → frameworks/js/napi/http/async_context/src/request_context.cpp（构造 RequestContext：持有 EventManager、napi_create_reference 保存回调）
  → utils/napi_utils/src/base_context.cpp（:107 napi_create_async_work 创建异步工作）
  → frameworks/js/napi/http/async_work/src/http_async_work.cpp（:23 HttpAsyncWork::ExecRequest → BaseAsyncWork::ExecAsyncWork<RequestContext, HttpExec::ExecRequest>）
  → frameworks/js/napi/http/http_exec/src/http_exec.cpp:1341 HttpExec::ExecRequest
       ├─ 权限校验
       ├─ InitialRequest 拦截器（ExecuteInitialInterceptor）
       └─ HandleInitialRequestPostProcessing（http_exec.cpp:1260，读缓存 CacheProxy，命中则直接回包）
  → http_exec.cpp:726 RequestWithoutCache
       ├─ curl_easy_init
       ├─ SetOption（URL/头/方法/代理等）
       └─ http_exec.cpp:674 AddCurlHandle
            ├─ :695 StartAsyncTrace（Hitrace）
            └─ SetServerSSLCertOption（:696/:707/:713，在 worker 线程做证书锁定，避免阻塞主线程）
  → frameworks/js/napi/http/http_interceptor/src/http_interceptor.cpp:1416 ExecuteConnectNetworkInterceptor
  → utils/http_over_curl/src/epoll_request_handler.cpp:41 EpollRequestHandler::Process（单请求 socket/timer 事件处理）
  → utils/http_over_curl/src/epoll_multi_driver.cpp EpollMultiDriver（epoll + curl_multi 驱动，含 handover/deadflow 分支）
  → curl 数据/头部/进度回调经 TransferCallbacks（utils/http_over_curl/include/transfer_callbacks.h）
  → utils/napi_utils/src/event_manager.cpp EmitByUv（uv_queue_work 切回 JS 线程，回 JS 回调唯一合法通道）
  → JS on('headerReceive') / on('dataReceive') 与 Promise resolve/reject
```

要点：

- `RequestContext` 持有 napi_ref 与 EventManager，是链路中生命周期最长的对象，工作线程全程引用，详见 [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)。
- 禁止在工作线程直接调 JS 回调；必须经 `EmitByUv`，详见 [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md)。

## 2. 拦截器五类切点

`ENABLE_HTTP_INTERCEPT` 宏控制启用；实现集中在 `frameworks/js/napi/http/http_interceptor/src/http_interceptor.cpp`（1510 行）与 `frameworks/native/http_interceptor/`。

| 切点 | 时机 |
|---|---|
| Initial | 请求进入 `HttpExec::ExecRequest` 后、读缓存前 |
| CacheChecked | 缓存判定完成后 |
| ConnectNetwork | `ExecuteConnectNetworkInterceptor`（http_interceptor.cpp:1416），建连前后 |
| FinalResponse | 拿到最终响应 |
| Redirection | 重定向决策处 |

## 3. 缓存链（双层结构）

```
frameworks/js/napi/http/cache/cache_proxy/（exec 层代理，对接 HttpExec）
  ↔ interfaces/innerkits/http_client/cache/{lru_cache,cache_strategy}/（淘汰与策略核心）
```

- 两层目录下均有 `base64`/`cache_constant`/`cache_proxy`/`cache_strategy`/`lru_cache` 五个子模块；策略集中在校 cache_strategy，淘汰在 lru_cache。
- 入口：`HttpExec::ExecRequest` 中 `HandleInitialRequestPostProcessing`（http_exec.cpp:1260）读取 CacheProxy。
- 禁止只改一层：exec 层与 innerkits 层的字段/编码必须同步，Base64 变体见 `cache/base64`。

## 4. 降级路径：`!HAS_NETMANAGER_BASE`

未接入 netmanager_base 时（如部分轻量场景），`http_exec.cpp:1512-1577` 的 `HttpExec::RunThread()` 自建线程直接驱动：

- `curl_multi_perform` + `curl_multi_poll` + `curl_multi_info_read` 轮询循环。
- 不经 `EpollMultiDriver`，也没有 handover 能力。
- 改动代理/驱动相关逻辑时，两种宏配置（有/无 `HAS_NETMANAGER_BASE`）都必须编译验证。

## 5. NDK 路径（独立于 NAPI 链）

```
NDK 调用方（interfaces/kits/c/net_http/include/net_http.h）
  → interfaces/kits/c/net_http/src/net_http_c.cpp
  → frameworks/native/http/http_client/http_client.cpp:63 HttpSession::GetInstance() → CreateTask
  → frameworks/native/http/http_client/http_client_task.cpp（HttpClientTask，1867 行，直接持有 CURL*）
  → utils/http_over_curl（引擎与回调复用）
```

- NDK 无 JS 层：事件以 C 回调/句柄方式给出，但请求对象生命周期仍由 `HttpClientTask` 管理。
- `HttpClientTask` 持有 `CURL*` 意味着引擎区（`utils/http_over_curl`）改动同样波及 NDK 用户。

## 6. 多网切换 handover 与死流复位

- 头文件：`utils/http_over_curl/include/http_handover_handler.h`、`http_handover_info.h`（handover），`http_deadflow_info.h`（死流）。
- 驱动：`epoll_multi_driver.cpp:41` 起初始化 `HttpHandoverHandler` 并注册 polling；事件分支在 `epoll_multi_driver.cpp:113-116`（handover 事件 → `HandoverRequestCallback`，超时事件 → `HandoverTimeoutCallback`）。
- 宏 `HTTP_DEADFLOWRESET_FEATURE` 控制死流复位（相关文件：`request_info.h`、`transfer_callbacks.h`、`epoll_multi_driver.cpp`）。
- 历史多网切换错乱修复（9993be68）与引擎修复被 revert 的教训（25bd2e61）见 [../expert/historical-failures.md](../expert/historical-failures.md)——改引擎区前必读，并确认 `http_handover_handler` 回归测试已跑。

## 关联知识

- [netstack-code-map.md](netstack-code-map.md)：全局目录与分层
- [napi-multilanguage-map.md](napi-multilanguage-map.md)：EmitByUv 与事件设施细节
- [../routing/crash-routing.md](../routing/crash-routing.md)：回调偶崩/事件投递崩溃排查
- [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md)：线程与回调规则
- [../expert/lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)：RequestContext/napi_ref 陷阱
- [../expert/historical-failures.md](../expert/historical-failures.md)：handover 与引擎 revert 教训

## 适用场景

- 修改 HTTP 执行链（`http_exec.cpp`/引擎/拦截器/缓存）前定位改动点与影响面
- 排查请求无响应、回调不触发、回调偶崩等链路级问题
- 评估 NDK 与 NAPI 两条路径是否需要同步修改
