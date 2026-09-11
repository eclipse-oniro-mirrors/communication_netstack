# 验证循环与 Done 定义（Verification Loop & Definition of Done）

> 本文件回答"改完之后怎么算完"：按任务类型选最小验证矩阵跑绿，对照 Done 定义六条逐项核验；验证不过走回退方案。命令与 target 名见 [build-and-test.md](build-and-test.md)，过程约束回顾 expert 三篇。

## 任务类型 → 最小验证矩阵

| 任务类型 | 最小验证集 |
|---|---|
| HTTP 执行链改动 | `http_unittest` + `http_client_unittest` + `SocketExecFuzzTest` + 真机抓包（hilog domain `0xD0015B0`） |
| TLS 改动 | TLS 全家桶（`tls_socket_unilateral_connection`、`two_way_tls_socket_server_unittest` 等，见 build-and-test.md 分组表）+ 多线程 close 场景自测（并发 close × callback、close × getState） |
| `event_manager` / `napi_utils` 改动 | 全量 `netstack_test`（事件管理器是所有回调的咽喉，影响面全局） |
| 缓存改动 | `http_cache_unittest` |
| NDK 改动 | `nethttp_unittest` |
| socket 改动 | `socket_unittest` + `socket_error_unittest` + `SocketExecFuzzTest` |
| websocket 改动 | `websocket_unittest` + `websocket_capi_unittest` + `WebSocketCApiFuzzTest` |
| 多网切换 / handover 改动 | `http_handover_handler_test` + 真机双网切换回归 |

> 最小集只是下限：台账文件（见 [lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md)）上的任何改动，按 expert 要求追加并发回归。

## 验证顺序（推荐执行流）

1. 编译改动相关 target（先小后大：模块 target 先于 `netstack_test`）；
2. 跑矩阵最小集；失败先写最小复现单测锁住行为再修；
3. 台账文件改动追加并发场景自测（并发 close × callback、close × getState、Finalize × uv 回调）；
4. LSP/静态检查通过，编译警告归零；
5. 对照下方 Done 定义六条与提交前检查清单收尾。

## Done 定义（6 条全满足才算完成）

1. ✅ 编译成功：[build-and-test.md](build-and-test.md) 的对应命令无错误。
2. ✅ 相关测试通过：上方矩阵选出的最小验证集全绿。
3. ✅ 无新增编译警告。
4. ✅ LSP/静态检查无新增 error。
5. ✅ 未破坏 API 兼容：`interfaces/` 基线未破坏，JS/NAPI、NDK（`interfaces/kits/c/`）、ANI（`frameworks/ets/ani/`）、仓颉（`frameworks/cj/`）、Rust（`interfaces/innerkits/rust/`）各面逐一核对（见 [api-compatibility-constraints.md](../expert/api-compatibility-constraints.md)）。
6. ✅ 未违反 expert 禁止事项：[threading-model-constraints.md](../expert/threading-model-constraints.md) 5 条约束、[lifecycle-uaf-pitfalls.md](../expert/lifecycle-uaf-pitfalls.md) 检查清单逐项自查。

## 回退方案

| 情形 | 处置 |
|---|---|
| 编译失败 | 先核对 target 名拼写与 feature 开关（`HAS_NETMANAGER_BASE` 两种配置、`netstack_http_boringssl`、`ENABLE_HTTP_INTERCEPT` 等，见开关表），再排查代码 |
| 测试失败 | 先写最小复现单测锁住失效行为，再修复——❌ 禁止删除/注释失败用例使测试通过 |
| 修复被质疑 | 参考 `25bd2e61` revert 教训（[historical-failures.md](../expert/historical-failures.md)）：补足 socket/tls 回归后再合并，不带病上主干 |
| 验证不过且短期无法修复 | `git revert` 对应提交；**回退后必须把失效模式与教训回写 [historical-failures.md](../expert/historical-failures.md)（参照 25bd2e61 案例格式）** |

## 提交前检查

- [ ] 提交信息携带 `TicketNo: DTSxxxxxxxx` 单号；
- [ ] `clang-format` 校验通过（代码已格式化）；
- [ ] `DO NOT MODIFY, AUTO-GENERATED` 段（IDL/工具生成物）未改动；
- [ ] 大文件（`http_exec.cpp`、`socket_exec.cpp`）改动已在描述中绑定回归用例名；
- [ ] 未经用户确认不执行 git commit（AGENTS.md §6.1 红线）。

## 关联知识

- [编译与测试命令](build-and-test.md)
- [线程模型约束](../expert/threading-model-constraints.md)
- [生命周期与 UAF 高发区](../expert/lifecycle-uaf-pitfalls.md)
- [历史高危修复案例](../expert/historical-failures.md)
- [AGENTS.md](../../../AGENTS.md)

## 适用场景

- 任何代码改动完成后的收尾验证；
- MR 合入前的自查与门禁对照；
- 验证失败或修复被质疑时的回退决策。
