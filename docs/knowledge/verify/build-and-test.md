# 编译与测试命令（Build & Test）

> 本文件是 netstack 的验证命令权威清单：编译入口、按模块分组的单测 target 实名表、历史遗留目录警告与观测点。改动任何代码后，按 [verification-loop.md](verification-loop.md) 的最小验证矩阵选 target；本文件回答"跑什么"。

## 编译

统一入口（`--build-target` 换目标，`--ccache` 提速）：

```bash
./build.sh --product-name rk3568 --build-target http --ccache
```

| 常用 target | 说明 |
|---|---|
| `http` / `socket` / `websocket` / `fetch` | JS/NAPI 四大模块 |
| `http_client` / `websocket_native` / `net_ssl` / `http_interceptor` | innerkits 目标 |
| `net_http_ndk` / `net_websocket` | NDK（`interfaces/kits/c/`） |
| `ylong_http_client` / `netstack_rs` | Rust（`interfaces/innerkits/rust/`，Cargo members） |
| `common_utils` | 公共工具 |
| `netstack_test` | 全量测试聚合 group（`test/BUILD.gn`） |

单测同样用 `--build-target` 编出，例如 `--build-target http_unittest`。

## 单测 target 实名表（按模块分组）

| 模块 | target |
|---|---|
| HTTP | `http_unittest` / `http_cache_unittest` / `http_client_unittest` / `http_interceptor_unittest` / `nethttp_unittest` |
| socket | `socket_unittest` / `socket_error_unittest` |
| websocket | `websocket_unittest` / `websocket_capi_unittest` / `websocket_inner_unittest` |
| TLS | `tls_socket_unilateral_connection` / `tls_socket_core_test` / `tls_socket_branch_test` / `two_way_tls_socket_server_unittest` / `tls_key_test` / `tls_cert_test` / `tls_configuration_test` / `tls_context_test` / `secure_data_unittest` |
| netssl | `netssl_unittest` |
| utils | `netstack_common_utils_test` / `netstack_chr_client_test` / `netstack_network_profiler_utils_test` / `http_handover_handler_test` |
| fuzz | `SocketExecFuzzTest` / `TlsSocketFuzzTest` / `NetsslExecFuzzTest` / `NetsslInnerFuzzTest` / `WebSocketCApiFuzzTest` |

## 注意事项

- ⚠️ `test/unittest` 下 `http_client_test`、`sockettest`、`tcp_test`、`udp_test`、`tls_test`、`test_tls`、`websocket_test` 七个目录**无 BUILD.gn，不参与编译**（历史遗留）。把用例写进这些目录 = 用例不会被执行；新用例必须落在参与编译的 target 目录（如 `test/unittest/socket/`）。
- ⚠️ TLS 用例多依赖证书/网络环境，个别 target 名义编译不等于可跑，跑不通先看是否为环境依赖。
- 编译失败优先核对：target 名拼写、feature 开关（见 [api-compatibility-constraints.md](../expert/api-compatibility-constraints.md) 的开关表）、`HAS_NETMANAGER_BASE` 两种配置。

## 观测点

| 观测面 | 位置/用法 |
|---|---|
| hilog | 统一 domain `0xD0015B0`（定义于 `utils/log/include/netstack_log.h`），抓包过滤以此为准 |
| EventReport | hiSysEvent 封装（`utils/common_utils/include/netstack_hisysevent.h`） |
| HiAppEvent | `"NetworkKit"` / `"HttpRequest"` 事件（如 `frameworks/js/napi/http/http_exec/src/http_exec.cpp:1343`） |
| CHR | Call Home Record 高频问题上报（utils 侧，配 `netstack_chr_client_test`） |

## 关联知识

- [HTTP 执行链代码地图](../code_map/http-pipeline-map.md)
- [验证循环与 Done 定义](verification-loop.md)
- [API 兼容性与配置约束](../expert/api-compatibility-constraints.md)
- [历史高危修复案例](../expert/historical-failures.md)
- [AGENTS.md](../../../AGENTS.md)

## 适用场景

- 任何改动后的编译与测试选 target；
- 用例新增时确认目录可编译；
- 抓日志/上报排查问题时定位 domain 与事件名。
