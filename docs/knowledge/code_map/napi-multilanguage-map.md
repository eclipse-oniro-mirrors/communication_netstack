# NAPI 基础设施与多语言绑定地图

> 本文覆盖所有模块共用的 NAPI 公共设施（事件、异步工作、安全容器、日志、维测），以及同一网络能力暴露出的四套语言绑定面。**改任何接口时必须在此核对需要同步修改的面。**

## 1. utils/napi_utils —— NAPI 公共设施

| 文件 | 职责 |
|---|---|
| `utils/napi_utils/src/event_manager.cpp`、`utils/napi_utils/include/event_manager.h` | EventManager：JS 事件管理器；`EmitByUv` 经 `uv_queue_work` 切回 JS 线程，是回 JS 回调**唯一合法通道**；共享锁 `mutexForListenersAndEmitByUv_` 保护 listener 表 |
| `utils/napi_utils/include/event_listener.h` | EventListener：事件订阅封装 |
| `utils/napi_utils/src/base_context.cpp`（:107） | BaseContext：`napi_create_async_work` 创建点，异步上下文基类 |
| `utils/napi_utils/include/base_context.h`、`utils/napi_utils/include/base_async_work.h` | BaseAsyncWork：`ExecAsyncWork<Context, Exec>` 模板，各模块 async_work 同构来源 |
| `utils/napi_utils/include/module_template.h` | 模块注册/接口定义模板，各 `*_module.cpp` 的生成母版 |
| `utils/napi_utils/include/secure_char.h`（:24） | `SecureChar`：敏感信息（密码/token）安全容器，内容不清真文本落日志 |
| `frameworks/native/tls_socket/include/secure_data.h`（:26） | `SecureData`：证书/密钥数据的安全容器（TLS 侧对偶物） |
| `utils/napi_utils/include/hi_app_event_report.h` | HiAppEvent 上报（"NetworkKit"/"HttpRequest"） |
| `utils/napi_utils/src/napi_utils.cpp` | napi 值转换/异常工具；uv 入队失败分支是历史泄漏热点 |

## 2. utils/common_utils / utils/log / CHR 维测

| 路径 | 职责 |
|---|---|
| `utils/common_utils/include/netstack_common_utils.h` + `src/netstack_common_utils.cpp` | 字符串/通用工具 |
| `utils/common_utils/include/netstack_hisysevent.h` + `src/netstack_hisysevent.cpp` | `EventReport`：hiSysEvent 观测封装 |
| `utils/common_utils/include/netstack_apipolicy_utils.h` | API 策略（限制类上报等） |
| `utils/common_utils/include/netstack_bundle_utils.h` | bundle 信息查询 |
| `utils/common_utils/include/socket_statistics.h` | socket 流量统计 |
| `utils/log/include/netstack_log.h` | 日志封装：domain `0xD0015B0`，宏 `NETSTACK_LOGx` |
| `utils/netstack_chr_client/include/{i_netstack_chr_client.h,netstack_chr_client.h,netstack_chr_report.h}` | CHR（Call Home Record）维测上报客户端 |

## 3. 同一 API 的四个语言面（+Rust 封装）

同一网络能力对外暴露多套绑定，**行为必须一致、变更必须同步评估**：

| 语言面 | 路径 | 形态 |
|---|---|---|
| JS/NAPI | `frameworks/js/napi/{http,socket,tls,websocket,fetch,net_ssl,proxy}` | 模块注册 + exec，主链路 |
| NDK | `interfaces/kits/c/{net_http,net_websocket,net_ssl,http_interceptor,common}` | C 头文件 + 实现（如 `interfaces/kits/c/net_http/src/net_http_c.cpp`） |
| ANI | `frameworks/ets/ani/{http,net_ssl,web_socket,common}` | ArkTS↔Rust 绑定（Cargo member） |
| 仓颉 | `frameworks/cj/{http,socket,websocket,network_security}` | 仓颉 FFI（如 `frameworks/cj/http/src/net_http_client_exec.cpp`） |
| Rust 封装 | `interfaces/innerkits/rust/` | 见下 |

## 4. interfaces/innerkits/rust —— Rust 侧结构

```
interfaces/innerkits/rust/
  ├─ netstack_rs/   # ANI 上层封装，cxx 桥接 C++ 与 Rust
  ├─ ffrt_rs/       # FFRT Rust 绑定
  └─ ylong_http_client/
       ├─ src/reqwest_impl/   # reqwest 后端（当前默认 feature）
       └─ src/lib.rs          # 适配器 crate：describe "adapter of Reqwest and Ylong"，
                              # feature 门控：default = ["reqwest_impl"]；ylong_impl 走外部 crate ylong_http_client_inner
```

- `Cargo.toml` members：`frameworks/ets/ani/http`、`frameworks/ets/ani/net_ssl`、`frameworks/ets/ani/web_socket`、`frameworks/ets/ani/common`、`interfaces/innerkits/rust/netstack_rs`、`interfaces/innerkits/rust/ffrt_rs`。
- 改 Rust 侧接口时核对：ANI 绑定（`frameworks/ets/ani/`）与 `cxx` 桥文件是否同步、双后端（reqwest_impl/ylong_impl）行为是否一致。

## 5. 改接口时的同步检查清单

1. `frameworks/js/napi/`（JS 主链路）行为与 `interfaces/kits/js/*.d.ts` 声明一致。
2. `interfaces/kits/c/` NDK 头文件、.json 清单与实现同步。
3. `frameworks/ets/ani/` ANI 导出面同步（改 `interfaces/innerkits/rust/` 时必查）。
4. `frameworks/cj/` 仓颉 FFI 行为对齐。
5. `interfaces/innerkits/` inner API 与 `.map` 版本约束未被破坏（红线见 [../expert/api-compatibility-constraints.md](../expert/api-compatibility-constraints.md)）。
6. 回调全部经 `utils/napi_utils/src/event_manager.cpp` 的 `EmitByUv`；异步上下文经 BaseAsyncWork/BaseContext。

## 关联知识

- [netstack-code-map.md](netstack-code-map.md)：全局目录与分层
- [http-pipeline-map.md](http-pipeline-map.md)：EmitByUv 在 HTTP 链路中的位置
- [socket-tls-websocket-map.md](socket-tls-websocket-map.md)：各模块 exec 同构结构
- [../routing/crash-routing.md](../routing/crash-routing.md)：napi_utils.cpp/event_manager.cpp 泄漏与崩溃热点
- [../expert/threading-model-constraints.md](../expert/threading-model-constraints.md)：EmitByUv/handle_scope 规则
- [../expert/api-compatibility-constraints.md](../expert/api-compatibility-constraints.md)：接口兼容红线

## 适用场景

- 新增/修改任何对外接口（JS/NDK/ANI/仓颉/Rust），核对同步修改面
- 排查回调线程违规、事件不触发、敏感信息落日志
- 维测能力（hilog/hisysevent/HiAppEvent/CHR）接入或排障
