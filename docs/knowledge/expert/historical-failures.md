# 历史高危修复案例（Historical Failures & Lessons）

> 本文件是仓内已核实的失效模式权威台账：每条含现象/根因/修复文件/验证要点，供改动前"对号入座"与排查时定位。新失效与 revert 教训必须按此模板回写本文件（AGENTS.md §8），并同步 [crash-routing](../routing/crash-routing.md)。

## 案例台账（12 条，全部经 `git show --stat` 核实）

### UAF-TLS 握手完成后访问对端证书崩溃（7e264cc7）

- 现象：DTS2026090107583，TLS 握手成功后访问对端证书即崩溃。
- 根因：握手完成后缓存的证书对象，其宿主已被释放，访问成悬垂指针。
- 修复文件：`tls_socket.cpp`
- 验证要点：握手完成→读取对端证书回归用例；并发握手 + close 压测；跑 `tls_socket_unilateral_connection` 等 TLS 矩阵。

### UAF-TLS close 时崩溃（d81405b9）

- 现象：DTS2026080332485，调用 TLS close 崩溃。
- 根因：close 路径与请求状态的共享对象未加保护。
- 修复文件：`tls_socket.cpp` + `tls_socket.h`
- 验证要点：并发 close × 回调场景用例必须通过（AGENTS.md §6.2 规则）。

### double-free/UAF-socket double-close 与 tlsocket use-after-close（c7a11046）

- 现象：socket 重复 close 崩溃（double-close）；TLS socket close 后继续使用崩溃（use-after-close）。
- 根因：同一 close 可由多条路径触发，第二次作用于已释放对象；回调经 `event_manager` 双触发导致 double-free。
- 修复文件：`socket_exec.cpp` + `tlssocket_exec.cpp` + `event_manager.{h,cpp}`
- 验证要点：重复 close、close 后各 API 调用、Finalize 与 uv 回调并发释放用例；`socket_unittest` 回归。

### UAF-事件投递共享检查后继续执行崩溃（0e4c9693）

- 现象：事件投递时崩溃；监听器销毁窗口内仍发生 emit。
- 根因：`EmitByUvWithoutCheckShared` 共享检查后未返回，继续执行投递。
- 修复文件：`event_manager.cpp`
- 验证要点：共享检查失败即前置 return；并行销毁监听器 × emit 压测。

### 竞态-TLS 监听回调与 close 竞态线上崩溃（88860419）

- 现象：DTS2025061330693，手机百度线上崩溃 libsocket.z.so；TLS 监听回调路径崩溃。
- 根因：`monitor.cpp` 回调与 close 并发竞态。
- 修复文件：`monitor.cpp`
- 验证要点：监听回调进行中触发 close 循环压测；线上三方应用场景回归。

### 竞态-TlsSocket close 后 getState 崩溃（287dbe3d）

- 现象：TlsSocket close 后调用 getState 发生 crash。
- 根因：close 与查询并发时 `manager->GetData` 无锁并发访问。
- 修复文件：`tlssocket_exec.cpp`
- 验证要点：close × `getState` 并发用例；所有 `manager->GetData` 调用点判空 + 加锁审查。

### 空指针+溢出-HTTP 缓存与请求处理异常（0d7119df）

- 现象：DTS2026072356462 等 3 单（另两单 DTS2026072356663、DTS2026072356745），HTTP 缓存与请求处理异常。
- 根因：多处空指针解引用 + 整数溢出。
- 修复文件：`http_exec.cpp` + `lru_cache.cpp` + `cache_proxy.cpp` + `netstack_common_utils.cpp`
- 验证要点：`http_cache_unittest` + `http_unittest` + `http_client_unittest` 全量；边界值（极大头/超长 key/空 entry）用例。

### NAPI 生命周期违规-HTTP 异步回调偶崩/值错误（0641ef07）

- 现象：DTS2026082742564，HTTP 异步回调偶崩、偶发返回值错误。
- 根因：UV 队列回调缺 `napi_handle_scope`，JS 对象生命周期无保障。
- 修复文件：`http_exec.cpp` + `napi_utils.cpp`
- 验证要点：高频短生命周期请求压测；回调内创建对象的场景回归（约束见 [threading-model-constraints.md](threading-model-constraints.md) 约束③）。

### 内存泄漏-uv_queue_work_with_qos 失败后内存增长（dcfe2f33）

- 现象：DTS2024101008443，运行期间内存持续增长。
- 根因：`uv_queue_work_with_qos` 入队失败分支未释放上下文。
- 修复文件：`napi_utils.cpp`
- 验证要点：入队失败注入用例；长稳内存曲线对比（泄漏类必带前后曲线）。

### 生命周期/线程-TCP Server 回调崩溃（f080ac6e）

- 现象：DTS2026070659459，TCP Server 回调路径崩溃。
- 根因：回调生命周期与线程管理缺陷。
- 修复文件：`socket_exec.cpp`
- 验证要点：该提交同时补入 `test/unittest/socket/SocketTest.cpp` 用例（183 行）——回调生命周期用例须随改动保留并扩展。

### 修复回退风险样本-curl 踩内存修复被 revert（25bd2e61）

- 现象：DTS2024082260561 的 curl 踩内存修复因自身引入新问题，2024-09 被整体 revert（revert 提交即本 hash）。
- 根因：引擎区修复未配套充分回归，修复本身引入新缺陷，只能回退主干。
- 修复文件：`request_context.{h,cpp}` + `http_exec.cpp`
- 教训：`utils/http_over_curl` 引擎区改动必须配套充分 socket/tls 回归（AGENTS.md §6.2）；被质疑的修复先补回归再合并，不与主干"带病共存"。
- 验证要点：重构引擎相关代码时先读本条，评估回归覆盖面后再动手。

### 多网切换状态错乱-handover 后 response 拼接错乱（9993be68）

- 现象：2026-07，网络切换后非流式 + 安全 + 已读请求的 response 被重复拼接。
- 根因：handover 后请求状态判定不全，重复触发拼包。
- 修复文件：`http_exec.cpp` + `http_client_response.cpp` + `request_info.h` + `transfer_callbacks.h`
- 验证要点：`http_handover_handler_test`（该提交扩展 73 行用例）；真机双网切换回归。

## TOP 失效模式排行

| 排名 | 失效模式 | 代表提交 | 规避要点 |
|---|---|---|---|
| 1 | UAF/double-close | `7e264cc7`、`d81405b9`、`c7a11046`、`0e4c9693` | [lifecycle-uaf-pitfalls.md](lifecycle-uaf-pitfalls.md) 全文 |
| 2 | 竞态/锁缺失 | `88860419`、`287dbe3d` | 共享对象先锁后用；`GetData` 判空+加锁 |
| 3 | 空指针 | `0d7119df` | 外部输入/缓存 entry 一律判空 |
| 4 | 内存泄漏 | `dcfe2f33` | 入队/异步失败分支必须走释放路径 |
| 5 | NAPI/uv 生命周期违规 | `0641ef07` | 工作线程不碰 JS；回调先开 `napi_handle_scope` |
| 6 | 整数溢出 | `0d7119df` | 长度/偏移计算用安全边界检查 |
| 7 | 多网切换 handover 错乱 | `9993be68` | 改请求状态机时跑 `http_handover_handler_test` |
| 8 | 安全敏感（脱敏/明文落日志） | 持续防范（暂无案例，新增即回写本表） | 密码/token 用 `SecureChar`，不得明文入日志 |
| 9 | 修复回退风险 | `25bd2e61` | 引擎区改动绑定充分 socket/tls 回归后再合 |

## 关联知识

- [崩溃排查路由](../routing/crash-routing.md)
- [生命周期与 UAF 高发区](lifecycle-uaf-pitfalls.md)
- [线程模型约束](threading-model-constraints.md)
- [验证循环与 Done 定义](../verify/verification-loop.md)
- [AGENTS.md](../../../AGENTS.md)

## 适用场景

- 改动台账所列文件前，逐条对号预判风险；
- 线上/DT 崩溃排查时按失效模式反查历史修复；
- 新失效发生或修复被 revert 后，按本模板回写条目并更新排行表。
