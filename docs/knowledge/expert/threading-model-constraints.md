# 线程模型约束（Threading Model Constraints）

> netstack 无独立 SA 进程，全部能力以库形态运行在调用方进程内。跨线程正确性建立在"三线程域分工 + 单一回调通道"之上：阻塞操作下沉 worker 线程，JS 回调一律经 `utils/napi_utils/src/event_manager.cpp` 的 EmitByUv 通道切回 JS 线程。本文件 5 条硬约束对 `frameworks/`、`utils/` 全部 C/C++ 改动生效。

## 三线程域

| 线程域 | 典型负载 | ✅ 允许 | ❌ 禁止 |
|---|---|---|---|
| JS 主线程 | napi API 入口、参数解析、JS 回调落地 | 创建 async work、注册/删除监听、轻量取值 | curl/SSL 初始化、证书锁定等阻塞操作；长时间持锁 |
| napi worker 线程（BaseAsyncWork） | `napi_create_async_work` 的 executor（`utils/napi_utils/include/base_async_work.h:31`） | curl/SSL 初始化与证书锁定、socket 收发、缓存 IO | 直接调用 JS 回调；直接操作 napi_ref/napi_value |
| uv 事件线程 | libuv loop 分发 `uv_queue_work` 完成回调 | 事件 Handler 经 uv 队列落地后回 JS 线程执行 | 绕过 uv 队列自行"切线程"回 JS |

## 约束清单

### ① curl/SSL 初始化与证书锁定必须在 worker 线程

- 依据：`frameworks/js/napi/http/http_exec/src/http_exec.cpp:707` 注释 `Do SetServerSSLCertOption here to avoid blocking the main thread.`；提交 `f50e40a9` 将证书锁定与应用级证书处理移到子线程。
- ❌ 在 JS 主线程（napi API 同步段）做证书文件读取、SSL 初始化类阻塞操作。
- ✅ 放进 `BaseAsyncWork` executor 或等价 worker 线程执行；主线程只准备参数并入队。

### ② 所有 JS 回调必须经 EmitByUv 切回 JS 线程

- 依据：`utils/napi_utils/src/event_manager.cpp` 的 `EmitByUvWithoutCheckShared`（`event_manager.cpp:116`）→ `NapiUtils::CreateUvQueueWork`（`event_manager.cpp:151`）→ `uv_queue_work` → JS 线程执行 Handler。**EmitByUv 是回 JS 线程唯一合法通道。**
- ❌ 在 worker 线程持着 napi_env/napi_ref 直接调用 napi 函数构造并触发 JS 回调（偶现崩溃或返回值错乱，且难以复现）。
- ✅ 工作线程只准备数据结构，调用 `EventManager` 的 Emit 系列接口，由 uv 队列统一回切。

### ③ 异步回调内 napi 调用必须有 napi_handle_scope

- 依据：提交 `0641ef07`（DTS2026082742564）——HTTP 异步回调偶崩/返回值错误，根因是 UV 队列回调缺 `napi_handle_scope`，修复为 HTTP 异步回调及 UV 同步队列补充 handle_scope 生命周期管理（`http_exec.cpp` + `napi_utils.cpp`）。
- ❌ UV 队列回调/cleanup/Finalize 中不开 handle_scope 直接创建 JS 对象/引用。
- ✅ 回调入口先 `napi_handle_scope scope(env);`（或 `napi_open_handle_scope` / `napi_close_handle_scope` 成对），再执行 napi 操作。

### ④ EmitByUvWithoutCheckShared 的共享锁语义

- 依据：`utils/napi_utils/include/event_manager.h:161` 声明 `std::shared_mutex mutexForListenersAndEmitByUv_`；提交 `0e4c9693` 在 `EmitByUvWithoutCheckShared`（`event_manager.cpp:116`）共享检查后加前置 return，避免事件投递 UAF。
- 语义：读 listeners 投递事件 → `std::shared_lock`（如 `event_manager.cpp:118`）；增删监听/销毁 listeners → `std::unique_lock`。共享检查失败（监听器正在销毁）必须立即 return，不得继续投递；投递所需数据在锁内拷贝完毕，出锁后不再解引用 listener。
- ⚠️ 改动该锁的作用域必须在并行销毁监听器场景下重验（见 [验证循环与 Done 定义](../verify/verification-loop.md)）。

### ⑤ socket task_queue 优先级模型

- 位置：`frameworks/js/napi/socket/task_queue/`（`include/task_queue.h`、`src/task_queue.cpp`）。
- 模型：`TaskPriority` 枚举标注任务类别（`CLOSE`、`SEND`、`CONNECT`、`BIND`、`SET_OPTIONS`）；executor 队列与 callback 队列两条 `std::priority_queue`（`g_taskExecutorQueue` / `g_taskCallbackQueue`）各配独立互斥锁（`g_execMutex` / `g_callbackMutex`），socket 任务经优先级队列串行化，防止操作乱序触发生命周期问题。
- ⚠️ 新增 socket 任务类型必须显式给出 `TaskPriority` 并评估与 `CLOSE` 的次序关系，❌ 禁止绕开队列直连 async work。

## 违反后果与写法对照

**场景 1：阻塞操作跑在 JS 线程**

```cpp
// ❌ 错误写法（模式示例）：主线程读证书/做 SSL 初始化，阻塞 JS
napi_value HttpRequest(napi_env env, napi_callback_info info) {
    SetServerSSLCertOption(...);
}

// ✅ 正确写法（模式示例，http_exec.cpp:707 所在模式）：worker 线程执行
std::thread([context, handle] {          // 或 BaseAsyncWork executor
    std::lock_guard guard(...);
    SetServerSSLCertOption(...);         // Do SetServerSSLCertOption here to avoid blocking the main thread.
});
```

**场景 2：worker 线程直接调 JS 回调**

```cpp
// ❌ 错误写法（模式示例）：工作线程直接进 JS
void OnWorkerThreadDone(Context *ctx) {
    napi_value cb;  GetReference(ctx->env, ctx->callbackRef, &cb);
    napi_call_function(ctx->env, undefined, cb, ...);
}

// ✅ 正确写法（模式示例）：经 uv 队列回切
void OnWorkerThreadDone(EventManager *manager) {
    manager->EmitByUvWithoutCheckShared(type, data, Handler);   // uv_queue_work → JS 线程
}
```

**场景 3：UV 队列回调缺 handle_scope**

```cpp
// ❌ 错误写法（模式示例）：
void UvWorkCallback(uv_work_t *work, int status) {
    napi_value obj;
    napi_create_object(env, &obj);       // 引用无生命周期保障（0641ef07 修复的形态）
}

// ✅ 正确写法（模式示例）：
void UvWorkCallback(uv_work_t *work, int status) {
    napi_handle_scope scope(env);        // 先开 handle_scope 再做 napi 操作
    napi_value obj;
    napi_create_object(env, &obj);
}
```

**场景 4：emit 前未过共享检查**

```text
❌ 错误写法（模式示例）：共享检查通过后、投递前 listeners 被销毁，仍继续取 listener 投递 → UAF（0e4c9693 修复形态）
✅ 正确写法（模式示例）：共享检查失败立即 return；数据锁内拷贝，锁外只投递不解引用
```

## 关联知识

- [HTTP 执行链代码地图](../code_map/http-pipeline-map.md)
- [生命周期与 UAF 高发区](lifecycle-uaf-pitfalls.md)
- [历史高危修复案例](historical-failures.md)
- [验证循环与 Done 定义](../verify/verification-loop.md)
- [AGENTS.md](../../../AGENTS.md)

## 适用场景

- 新增/修改任何 napi 异步工作（BaseAsyncWork、uv 队列、线程派生）；
- 触碰 `event_manager.cpp`、`napi_utils.cpp`、`http_exec.cpp` 证书/线程初始化段；
- socket 侧新增任务类型，需要选定 task_queue 优先级；
- 排查"回调偶崩、返回值错乱、JS 卡顿"类问题时按本清单逐条对号。
