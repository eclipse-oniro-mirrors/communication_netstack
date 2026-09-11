# API 兼容性与配置约束（API Compatibility & Configuration Constraints）

> `interfaces/` 是接口稳定性基线；同一能力对应 JS/NAPI、NDK、ANI、仓颉、Rust innerkits 多条绑定面——只改一个面是本仓典型错误。本文件同时收录错误码、feature 开关、证书格式、提交规范四类硬约束，改接口前全文过一遍。

## 公共 JS API 兼容基线

| 声明文件（`interfaces/kits/js/`） | 能力 |
|---|---|
| `@ohos.net.http.d.ts` | HTTP/HTTPS 客户端 |
| `@ohos.net.socket.d.ts` | TCP/UDP Socket |
| `@ohos.net.webSocket.d.ts` | WebSocket |
| `@system.fetch.d.ts` | fetch |

- ❌ 未经兼容性审查变更 `*.d.ts` 的签名、参数默认值、枚举值、错误码语义（一切可观察行为变更）。
- ✅ 行为变更先逐条对照 d.ts 判定是否破坏既有调用方，再按下表做多面同步。

## 接口多语言面联动（只改一个面 = 典型错误）

| 绑定面 | 路径 | 同步内容 |
|---|---|---|
| JS/NAPI | `interfaces/kits/js/` + `frameworks/js/napi/` | 签名、错误码、事件语义 |
| NDK | `interfaces/kits/c/`（`net_http`、`net_websocket`、`net_ssl`、`http_interceptor`、`common`） | 头文件与实现同步 |
| ANI（ArkTS↔Rust） | `frameworks/ets/ani/`（`common`、`http`、`net_ssl`、`web_socket`） | 同能力变更同步 |
| 仓颉 | `frameworks/cj/`（`http`、`socket`、`websocket`、`network_security`） | FFI 仓颉侧同步 |
| Rust innerkits | `interfaces/innerkits/rust/`（`ylong_http_client`、`netstack_rs` 等，见 `bundle.json` 组件清单） | Cargo members 同步 |

自检：改任何接口后逐一核对 `interfaces/kits/c/`、`frameworks/ets/ani/`、`frameworks/cj/`、`interfaces/innerkits/rust/`。

## 错误码约束

- 拦截器参数类型错误统一抛 `2300801`，message 为 `Parameter type not supported by the interceptor`，注册校验处见 `frameworks/js/napi/http/http_module/src/http_module.cpp:651`（同码多处：665/672/723/741）。
- ❌ 自定义新 message 文本复用已有错误码，或改已有 message 语义；✅ 新错误码先登记再使用，各语言面 message 保持一致。

## feature 开关与编译路径

| 开关 | 默认/位置 | 影响 |
|---|---|---|
| `netstack_feature_http3` | 组件特性（`bundle.json`） | HTTP3/QUIC 能力面 |
| `netstack_http_boringssl` | 默认 `false`（`netstack_config.gni:26`） | TLS 后端切换（BoringSSL） |
| `HAS_NETMANAGER_BASE` | 宏分叉（如 `frameworks/js/napi/http/http_exec/src/http_exec.cpp:1512-1577` 的 `#if !HAS_NETMANAGER_BASE` 路径） | 是否接入 netmanager_base 的代理/网络信息，两条编译路径都必须成立 |
| `ENABLE_HTTP_INTERCEPT` | `frameworks/js/napi/http/BUILD.gn:184`（定义处） | 拦截器编译面（如 `http_interceptor.cpp`、`request_context.h` 内分叉） |
| `HTTP_DEADFLOWRESET_FEATURE` | `frameworks/js/napi/http/BUILD.gn:186`（定义处） | 死流复位 |

- ⚠️ 改代理逻辑（`NetConnClient` 取代理相关）必须 `HAS_NETMANAGER_BASE` 有/无两种配置都编译并通过测试。
- ⚠️ 切换 `netstack_http_boringssl` 影响全部 TLS 用例，需确认 TLS 测试矩阵通过后才能动默认值。

## TLS 证书格式约束

- 仅支持 PEM=0 与 DER=1 两种 `encodingFormat`，实现见 `frameworks/native/tls_socket/src/tls_certificate.cpp`，非法值日志 `%{public}u is not supported, only support PEM =0 and DER = 1`。
- ❌ 扩展新格式而未同步 d.ts 枚举与各语言面。

## 接口变更自查清单

- [ ] d.ts 行为差异已逐条列出并经兼容性审查（签名/参数默认值/枚举/错误码语义均属可观察行为）；
- [ ] NDK 头文件（`interfaces/kits/c/`）与实现同步更新，无破坏性变更；
- [ ] ANI（`frameworks/ets/ani/`）、仓颉（`frameworks/cj/`）、Rust innerkits（`interfaces/innerkits/rust/`）逐面核对无遗漏；
- [ ] 新增/变更错误码已登记，各语言面 message 一致（对照 `2300801` 的既有写法）；
- [ ] 受 feature 开关影响的编译路径全部验证（`HAS_NETMANAGER_BASE` 两种配置、`netstack_http_boringssl` 开/关）；
- [ ] TLS 侧未私自扩展证书编码格式（仅 PEM=0 / DER=1）。

## 提交规范约束

- 提交信息必须携带 `TicketNo: DTSxxxxxxxx` 单号（仓内提交一致遵循，如 `TicketNo: DTS2026090107583`）。
- 标注 `DO NOT MODIFY, AUTO-GENERATED` 的生成段（IDL/工具生成物）❌ 不可手改。
- 未经用户确认不得提交代码（AGENTS.md §6.1 红线）。

## 关联知识

- [NAPI 与多语言绑定代码地图](../code_map/napi-multilanguage-map.md)
- [Socket/TLS/WebSocket 结构代码地图](../code_map/socket-tls-websocket-map.md)
- [生命周期与 UAF 高发区](lifecycle-uaf-pitfalls.md)
- [编译与测试命令](../verify/build-and-test.md)
- [AGENTS.md](../../../AGENTS.md)

## 适用场景

- 变更 `interfaces/kits/js/`、`interfaces/kits/c/` 任何接口；
- 改错误码/message、新增枚举或配置项；
- 动 feature 开关、`HAS_NETMANAGER_BASE` 代理路径、TLS 证书/后端；
- 提交前的合规自检（TicketNo、生成段、多面同步）。
