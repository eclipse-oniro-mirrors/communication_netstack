# TLS Socket fd 与 SSL 生命周期（专项稳定性知识）

> 适用范围：`frameworks/js/napi/tls/src/tls_socket.cpp`、`frameworks/native/tls_socket/src/tls_context.cpp`。
> 一句话结论：**fd 与 SSL 必须在同一条路径、同一个临界区里一起释放；`TLSSocket::Close()` 只允许 `shutdown`，不允许 `close(fd)`，也不允许释放 SSL。**
> 违反这条约束的代价：并发 UAF（崩在 `libcrypto_openssl`）+ fd 编号被复用（badfd / 串连接），并且历史上付出过一次完整回退。

## 1. 三条硬性不变量

| # | 不变量 | 违反后的现象 |
|---|---|---|
| 1 | `close(fd)` **只能**出现在 `TLSContext::CloseCtx()`，且必须在 `SSL_free` **之前**紧邻执行；fd 用 `SSL_get_fd(ctxSsl_)` 取，不要依赖上层 `TLSSocket::sockFd_` | `close()` 把 fd 编号立刻归还内核，编号被新连接复用后，晚到的读写打到别的连接上 → badfd / 读到别人的数据 |
| 2 | `TLSSocket::Close()` **只做** `shutdown(sockFd_, SHUT_RDWR)` + `sockFd_ = -1`；**禁止**在里面 `close(sockFd_)`，**禁止**在里面调 `CloseTlsContext()` / `SSL_free` | SSL 被提前释放，而其它线程此前已从 `ssl_` 取出的 `SSL*` / `SSL_CIPHER*` / `X509*` 裸指针变成悬垂 → 并发 UAF |
| 3 | `SSL_get_ciphers` / `SSL_get_peer_cert_chain` / `SSL_get_SSL_CTX` 返回的指针，必须在同一 `mutexForSsl_` 临界区内用完再释放锁；`if (!ssl_)` 判空**不等于**安全（判空与使用之间不持锁就是 TOCTOU） | 遍历期间 SSL 被释放 → 崩在 `libcrypto`（`ossl_i2c_ASN1_INTEGER`、`X509_verify_cert` 栈），且崩溃线程不是调用 close 的线程 |

## 2. 事实链：引入 → 表面修补 → 回退 → 闭环

| 阶段 | CR / commit | 单号 / 日期 | 改了什么 | 结果 |
|---|---|---|---|---|
| **引入** | CR 3686 / `bfb09310` | DTS2026081021955 / 2026-08-10 | `TLSSocket::Close()` 在 `close(sockFd_)` **之前**插入 `tlsSocketInternal_.CloseTlsContext()`（持 `mutexForSsl_` 做 `ssl_ = nullptr` + `CloseCtx()` 内含 `SSL_free`） | 为修 badfd 而提前关 fd，**顺手把 SSL 也提前释放了** → fd 与 SSL 生命周期脱钩 → 并发 UAF |
| 表面修补 | CR 3722 / `72a8025f` | DTS2026081506200 / 2026-08-20 | 握手接口加 `if (!ssl_)` 判空 | 只压制崩溃表象；判空与使用之间不持 `mutexForSsl_`，TOCTOU 窗口仍在。**这不是引入点** |
| 回退 | CR 3828 / `0a1375e5` | DTS2026091407095 / 2026-09-15 | 整体回退 3686 | 主干恢复"Close 不碰 SSL"旧行为（badfd 复发但不再 UAF） |
| **闭环** | CR 3863 / `aeb16f70` | DTS2609150113615 / 2026-09-28 | ① `Close()` 的 `close(sockFd_)` 改 `shutdown(sockFd_, SHUT_RDWR)` + `sockFd_ = -1`；② `CloseCtx()` 在 `SSL_free` **前**加 `int sslFd = SSL_get_fd(ctxSsl_); if (sslFd >= 0) { close(sslFd); }` | fd 与 SSL 收口到同一条路径 → UAF 与 badfd 同时收敛 |

> 只读其中一个 CR 会得出错误结论：**3686 才是原始引入点，3722 只是加了判空**。

## 3. 当前代码里 fd / SSL 分别在哪关

```
TLSSocket::Close()                    ← JS 层 close() 进来
  └─ shutdown(sockFd_, SHUT_RDWR)     ← 只断连接，不归还 fd 编号
  └─ sockFd_ = -1                     ← 上层不再持有 fd

~TLSSocket() → tlsContextPointer_ 释放
  └─ ~TLSContext() → CloseCtx()       ← 唯一真正收口点
       ├─ int sslFd = SSL_get_fd(ctxSsl_)
       ├─ SSL_free(ctxSsl_)
       └─ if (sslFd >= 0) close(sslFd)   ← fd 与 SSL 一起走
```

关键点：**`Close()` 之后 fd 仍然是打开的**，要等 `TLSSocket` 对象析构才归还。JS 层如果长期持有 TLSSocket 实例不释放，fd 就一直占着（可用 EMFILE 暴露）。

## 4. 残留风险清单（CR 3863 闭环后仍未收口，2026-10 审计）

> 以下为**当前主干代码的实际状态**，不是历史案例。改动关闭/读取路径前必须知道这些窗口存在；修复属于独立任务，不要夹带在无关 CR 里。

| # | 位置 | 现状 | 后果 |
|---|---|---|---|
| 1 | `TLSSocket::CloseTlsContext()` | **生产代码零调用**——只剩 `tls_socket.h` 声明 + `tls_socket.cpp` 定义，3863 已把它从 `Close()` 移除 | fd 的唯一收口点变成"对象析构"。JS 层持对象不释放 → fd 泄漏窗口。另外这个"看起来像收口点却没人调"的接口本身有误导性，应要么真正收口、要么删除 |
| 2 | `TLSSocket::GetCipherSuite()` | 锁内取 `ssl_`，**锁外**遍历 `SSL_get_ciphers(ssl_)` 返回的栈 | 遍历期间 SSL 被释放 → 栈指针悬垂 → libcrypto 崩溃 |
| 3 | `TLSSocket::CacheCertificates()` | 锁外使用 `certificatesStack` | 证书链悬垂 |
| 4 | `TLSSocket::SetSNIandLoadCachedCaCert()` | 锁外使用 `sslCtx` | `SSL_CTX` 已释放仍被读取 |
| 5 | `TLSSocket::StartShakingHands()` | `if (!ssl_)` 判空在锁外 | TOCTOU：判空通过后 `ssl_` 被置空/释放（正是 3722 想解决但没解决掉的窗口） |

彻底收口的方向（供后续任务参考）：`Close()` 走统一路径——`shutdown` → 标记 closing → 在 `mutexForSsl_` 内一次性完成 `SSL_free` + `close(SSL_get_fd())` + `ssl_ = nullptr`；任何读 `ssl_` 派生指针的接口，要么在同一临界区内完成，要么进入前检查 closing 标记并直接返回 `TLS_ERR_SSL_NULL`。

## 5. 改这块的检查清单

- [ ] 全文搜索 `close(` 只在 `tls_context.cpp` 的 `CloseCtx()` 命中，`tls_socket.cpp` 的 `Close()` 内只有 `shutdown`；
- [ ] `CloseCtx()` 中 `SSL_get_fd` 取 fd 的语句在 `SSL_free` **之前**，两者在同一临界区；
- [ ] SSL 派生裸指针没有带出 `mutexForSsl_` 锁外使用；
- [ ] `if (!ssl_)` 类判空与随后的使用之间持锁（不留 TOCTOU）；
- [ ] `Close()` 后重复调用安全（幂等），不会二次 `shutdown`/二次 `close` 造成误关复用 fd；
- [ ] 已跑下方 DT + XTS 生命周期用例；
- [ ] CR 描述里写明本次改动为什么不会让 fd 与 SSL 生命周期再次脱钩。

## 6. 回归用例（改关闭路径必跑）

| 层次 | 用例 | 位置 |
|---|---|---|
| DT | `tls_socket_lifecycle_test` | `test/unittest/tlssocket/client/TlsSocketLifecycleTest.cpp` |
| XTS | `ActsTLSSocketCloseConcurrentTest` | `test/xts/acts/telephony/telephonyjstest/netmanager_tlssocket/tlssocketcloseconcurrent` |

覆盖内容：`CloseCtx` 关闭 fd；重复 `CloseCtx` 不误关已被复用的 fd；析构释放 fd；**`Close()` 后 fd 仍打开且 `sockFd_ == -1`**（3686 回归守卫）；重复 close 幂等；循环 close 无 fd 增长（`/proc/self/fd` 计数）；`Close()` 与 SSL 派生接口并发稳定；close 后接口返回 `2303501`（`TLS_ERR_SSL_NULL`）。

跑法：DT `./build.sh --product-name rk3568 --build-target tls_socket_lifecycle_test --ccache`；XTS 走 acts 标准流程构建安装 `ActsTLSSocketCloseConcurrentTest` hap。

## 7. 排查信号速查

| 现象 | 疑因 | 先看哪里 |
|---|---|---|
| close 后崩在 `libcrypto_openssl.z.so`（`ossl_i2c_ASN1_INTEGER`、`X509_verify_cert`），**崩溃线程 ≠ 调用 close 的线程** | SSL 被提前释放，其它线程仍在用取出的 `SSL*`/`X509*` | `Close()` 里是否又出现了 `CloseTlsContext()` / `SSL_free`；`CloseCtx()` 里 `SSL_free` 与 `close(fd)` 的顺序 |
| TLS 报 badfd / 连接读到不属于自己的数据 | fd 编号被提前归还并复用 | `Close()` 里是否出现了 `close(sockFd_)` |
| 长稳跑 fd 持续增长、最终 EMFILE | `TLSSocket` 对象未析构，fd 收口点（`~TLSContext`）迟迟不触发 | JS 层是否泄漏 TLSSocket 实例；`CloseTlsContext()` 是否仍无人调用 |

## 8. 教训

1. 修 badfd 时只想"早点关 fd"，就会把 SSL 一起提前释放——**fd 与 SSL 必须同源释放，不能各自为政**。
2. 只加判空不加锁 = TOCTOU，挡不住并发。
3. **没有回归用例的关闭路径改动不要合入**：3686 合入 5 天后才发现 UAF，最终付出一次回退（3828）+ 一次重做（3863）的代价。
4. 回退之后必须把失效模式写进知识库（本文件的由来），否则同一坑还会再踩。
