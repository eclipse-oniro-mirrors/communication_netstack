# 生命周期与 UAF 高发区（Lifecycle & UAF Pitfalls）

> UAF/double-close 是本仓历史失效模式第一热点（完整排行见 [历史高危修复案例](historical-failures.md)）。TLS 系、socket 系、事件管理器三大区域集中了绝大多数崩溃修复提交；在此区域任何改动，修复必须绑定回归用例，回调纪律遵循 [线程模型约束](threading-model-constraints.md)。

## 高发文件台账

| 文件 | 历史失效（提交） | 典型风险点 |
|---|---|---|
| `frameworks/js/napi/tls/src/tls_socket.cpp` | `7e264cc7` UAF；`d81405b9` close UAF | 握手后证书对象宿主已释放；close 路径与请求状态共享对象未保护 |
| `frameworks/js/napi/tls/src/tlssocket_exec.cpp` | `287dbe3d` getState 竞态；`c7a11046` use-after-close | `manager->GetData` 无锁并发取对象 |
| `frameworks/js/napi/tls/src/monitor.cpp` | `88860419` 线上崩溃（libsocket.z.so） | 监听回调与 close 竞态 |
| `utils/napi_utils/src/event_manager.cpp` | `0e4c9693` 事件投递 UAF；`c7a11046` | 监听器销毁窗口内仍投递；回调双触发 double-free |
| `frameworks/js/napi/socket/socket_exec/src/socket_exec.cpp` | `c7a11046` double-close；`f080ac6e` 回调崩溃 | close 重复下发；TCP Server 回调生命周期与线程管理缺陷 |

> 大文件警告：`socket_exec.cpp`（3296 行）、`http_exec.cpp`（3741 行）——改动必须绑定回归测试。

## 典型失效场景

| # | 场景 | 机理 | 历史提交 |
|---|---|---|---|
| 1 | TLS close 与监听回调竞态 | close 销毁 socket/监听资源的同时，监听线程回调仍持有原始指针 | `88860419`、`d81405b9` |
| 2 | close 后调用 getState | close 已释放/置空 manager 数据，getState 侧无锁读取 | `287dbe3d` |
| 3 | socket double-close / tlsocket use-after-close | 两条路径都能触发同一 close，第二次 close 作用于已释放对象 | `c7a11046` |
| 4 | 事件 destroy 后仍 emit | 监听器销毁与 EmitByUv 投递并发，共享检查通过后对象被销毁 | `0e4c9693` |
| 5 | Finalize/回调多次触发 | napi Finalize 与 uv 队列回调各自释放同一上下文 → double-free；修复须同时落 `event_manager.{h,cpp}` | `c7a11046` |

附：握手完成后访问对端证书时证书对象宿主已释放（`7e264cc7`）——异步结果对象的所有权归属不清是同一族根因。

## 规避规则

1. ✅ close 路径加锁序：先持"对象管理锁"标记 closing/销毁状态，再释放底层资源；锁序全链路一致，禁止锁序反转。
2. ✅ 回调先检查存活：任何异步回调入口先判断宿主是否已 close/destroy，检查动作本身须持锁或用原子量保护，禁止"检查与使用"分离。
3. ✅ `manager->GetData` 前判空 + 加锁：从 manager 取对象的位置一律取值判空、取值过程持锁（`287dbe3d` 的修复即对 GetData 资源加锁）；锁外不得长期持有在锁内取得的裸指针。
4. ✅ 上下文唯一删除点：async context / uv 上下文只允许一个释放点（Finalize 与队列回调二选一），另一路径只置标记不释放。
5. ❌ close 路径内加同步等待回调完成的调用（死锁风险）；交叉等待一律改为状态标记 + 异步收敛。

**规避写法对照（模式示例）**

```cpp
// ❌ 错误写法：close 与回调无互斥，回调直达已释放对象（d81405b9 / 88860419 的失效形态）
void OnClose() { free(res); }
void OnCallback() { res->field; }              // 竞态窗口内悬垂访问

// ✅ 正确写法：先标记状态再释放；回调入口持锁做存活检查
void OnClose() {
    std::lock_guard<std::mutex> lock(mgrMutex);
    closed = true;                             // 1. 先标记 closing
    FreeResource(res);                         // 2. 持锁释放
}
void OnCallback() {
    std::lock_guard<std::mutex> lock(mgrMutex);
    if (closed || res == nullptr) { return; }  // 存活检查 = 判空 + 加锁
}
```

```cpp
// ✅ 正确写法：manager->GetData 前判空 + 加锁（287dbe3d 修复的核心动作）
std::lock_guard<std::mutex> lock(managerMutex);
auto *data = manager->GetData();
if (data == nullptr) { return Error(NETSTACK_PARSE_ERROR); }   // 判空后才能用
```

## 此区域改动的检查清单

改动上表文件（含新增相邻能力）前逐项勾选：

- [ ] 已按台账逐条读本文件对应的 [历史高危修复案例](historical-failures.md) 条目，确认未重蹈旧辙；
- [ ] close/析构路径的加锁顺序已画时序图确认：无锁序反转、无 close 内同步等待；
- [ ] 所有异步回调入口都有"存活检查"（判空 + 锁/原子），不存在绕过检查的直达路径；
- [ ] `manager->GetData` 系列调用全部判空且持锁，锁外不保存裸指针跨函数使用；
- [ ] 上下文/Finalizer 只有一个释放点，其余路径只置标记（对照场景 5）；
- [ ] 新增回调走 `EmitByUv` 并遵守 `napi_handle_scope` 约束（见 [线程模型约束](threading-model-constraints.md) 约束②③）；
- [ ] close 并发场景（并发 close × callback、close × getState、并发 close × repeat）已写多线程用例并跑通；
- [ ] 大文件（`socket_exec.cpp` / `http_exec.cpp`）改动已在 MR 描述绑定回归测试用例名。

## 关联知识

- [线程模型约束](threading-model-constraints.md)
- [历史高危修复案例](historical-failures.md)
- [API 兼容性与配置约束](api-compatibility-constraints.md)
- [编译与测试命令](../verify/build-and-test.md)
- [AGENTS.md](../../../AGENTS.md)

## 适用场景

- 修改 TLS 系（`tls_socket.cpp`、`tlssocket_exec.cpp`、`monitor.cpp`）任何函数；
- 修改 `event_manager.cpp` / `napi_utils.cpp` 的事件注册、删除、投递路径；
- 修改 `socket_exec.cpp` 的 close/回调/状态查询代码；
- 排查 UAF/double-free/竞态崩溃时确定优先怀疑对象与修复姿势。
