# Task 256 安全分析报告：PSA 密钥槽引用计数与并发销毁诊断

- 分析对象：Mbed TLS 分支 `task/256`（顶层提交 `0e2cc5f`），PSA 实现位于子模块 `tf-psa-crypto`，本地按锁定提交 `1468113`（TF-PSA-Crypto 1.3.0 mergeback）检出；测试框架 `framework` 按锁定提交 `ced3149` 检出。
- 分析范围：`psa_key_slot_t` 的状态机、`registered_readers` 引用计数、`psa_destroy_key()` 并发销毁路径、诊断接口 `mbedtls_psa_get_stats()`，以及既有测试材料的覆盖情况。
- 所有结论按 **【事实】（代码或本地运行证实）/【推断】（基于事实的分析，未直接证实）/【缺口】（未验证项）** 分类标注。

---

## 1. 数据流、状态转换与异常传播

### 1.1 槽状态机（四态）

【事实】状态枚举定义于 `tf-psa-crypto/core/psa_crypto_core.h:19-24`：

```
PSA_SLOT_EMPTY(0) → PSA_SLOT_FILLING → PSA_SLOT_FULL → PSA_SLOT_PENDING_DELETION → PSA_SLOT_EMPTY
```

| 转换 | 触发函数 | 代码位置 | 约束 |
|---|---|---|---|
| EMPTY → FILLING | `psa_reserve_free_key_slot()` + `psa_key_slot_state_transition()` | `psa_crypto_slot_management.c:571-655`，头文件内联实现 `psa_crypto_slot_management.h:204-213` | 必须持 `mbedtls_threading_key_slot_mutex`；期望态不符返回 `PSA_ERROR_CORRUPTION_DETECTED` |
| FILLING → FULL | `psa_finish_key_creation()` | `psa_crypto.c:1875-1911` | 持久键先写存储，再在互斥下转换；线性化点为该函数内的解锁 |
| FILLING → EMPTY | `psa_fail_key_creation()` → `psa_wipe_key_slot()` | `psa_crypto.c:1923-1941`、`1136-1206` | FILLING 态要求 `registered_readers == 0` |
| FULL → PENDING_DELETION | `psa_destroy_key()` | `psa_crypto.c:1257-1258` | 仅 FULL 可转换；该态阻止新读者注册 |
| PENDING_DELETION → EMPTY | 最后一个读者的 `psa_unregister_read()` → `psa_wipe_key_slot()` | `psa_crypto_slot_management.c:862-867` | “last one out closes the door” |
| FULL → EMPTY（回收/驱逐） | 槽饥饿时 `psa_reserve_free_key_slot()` 驱逐无读者的持久键；`psa_purge_key()` | `psa_crypto_slot_management.c:609-624`、`923-956` | 仅可驱逐 `registered_readers == 0` 的非易失键 |

### 1.2 引用计数 `registered_readers` 的数据流

【事实】计数器为 `size_t`，与空闲链表共用 union（`psa_crypto_core.h:71-121`），全部读写点只有以下几处，且均要求持有全局槽互斥（`threading_internal.h:45-56` 明确注释）：

1. **递增**：`psa_register_read()`（`psa_crypto_slot_management.h:229-238`）——要求 `state == PSA_SLOT_FULL` 且计数器 `< SIZE_MAX`，否则返回 `PSA_ERROR_CORRUPTION_DETECTED`，不递增。
2. **递减/归零擦除**：`psa_unregister_read()`（`psa_crypto_slot_management.c:852-884`）：
   - NULL 入参合法，直接成功（便于错误路径清理）；
   - 状态必须是 FULL 或 PENDING_DELETION，否则 `CORRUPTION_DETECTED`；
   - PENDING_DELETION 且计数器为 1（调用者是最后读者）→ 调用 `psa_wipe_key_slot()`；
   - 正常递减；若已无读者仍调用递减 → `MBEDTLS_TEST_HOOK_TEST_ASSERT` 断言 + `CORRUPTION_DETECTED`（下溢防护）。
3. **包装器**：`psa_unregister_read_under_mutex()`（`886-902`）在非持锁上下文自动加/解槽互斥；所有公开 API 出口均走该包装器或已持锁。
4. **强制清理**：`psa_wipe_all_key_slots()`（`427-473`）无视读者数，把每个槽置读者数 1、PENDING_DELETION 后擦除；仅由 `mbedtls_psa_crypto_free()`（`psa_crypto.c:8741`）在全局互斥下调用，文档明确该函数不具备线程安全性、必须单线程收尾。

【事实】典型一次操作的数据流（以 `psa_mac_sign_setup()` 为例，`psa_crypto.c:2718-2779`）：

```
psa_get_and_lock_key_slot_with_policy()
  ├─ 加槽互斥 → psa_get_and_lock_key_slot_in_memory()
  │    ├─ 易失 id：按 slice/slot 定位唯一候选槽，校验 state==FULL 且完整 svc id（含 owner）相等
  │    └─ 持久/内建 id：线性扫描缓存片，匹配 FULL 且 id 相等
  │    └─ psa_register_read()：读者数 +1
  ├─ 策略校验（usage/alg，不满足 → NOT_PERMITTED 并注销读者）
  ├─ 驱动 setup：把 slot->key.data/bytes 拷贝进 operation 对象
  └─ psa_unregister_read_under_mutex()：读者数 -1（setup 结束即不再持有槽引用）
```

【事实】多步操作在 setup 阶段复制密钥材料，之后不再访问槽。`psa_wipe_key_slot()` 内注释明确说明这一点（`psa_crypto.c:1184-1188`）：多步操作对象独立于槽，销毁后其密钥副本可继续存在，直到操作结束。

### 1.3 并发销毁的交错处理

【事实】`psa_destroy_key()`（`psa_crypto.c:1208-1304`）在启用 `MBEDTLS_THREADING_C` 时：

1. 先经 `psa_get_and_lock_key_slot()` 取得槽并注册为读者（该函数内部整体持槽互斥完成“查找/加载/注册”，注释 `773-778` 说明持久键加载期间不能放锁，否则另一线程可先加载再销毁）；
2. 再次获取槽互斥，若发现槽已是 PENDING_DELETION（被别的线程抢先销毁），注销读者并返回 `PSA_ERROR_INVALID_HANDLE`（`1238-1247`）；
3. FULL → PENDING_DELETION，此后 `psa_get_and_lock_key_slot_in_memory()` 只接受 FULL 槽（`375`、`385` 行条件），新读者无法进入；
4. 只读生命周期键 → `PSA_ERROR_NOT_PERMITTED`，但仍走清理擦除 RAM 副本（`1264-1272`）；
5. 持久键调 `psa_destroy_persistent_key()` 删存储（`psa_crypto_storage.c:166-187`）：ITS remove 失败或删除后仍能 get_info → `PSA_ERROR_DATA_INVALID`；
6. 出口 `psa_unregister_read()`：最后读者触发擦除；`CORRUPTION_DETECTED` 优先级高于存储错误（`1290-1294`）；互斥解锁失败 → `PSA_ERROR_SERVICE_FAILURE`。

【事实】异常传播与输入边界的对应关系：

| 边界输入 / 异常条件 | 传播结果 | 代码依据 |
|---|---|---|
| 库未初始化（`key_slots_initialized == 0`） | `PSA_ERROR_BAD_STATE` | `slot_management.c:578-581`、`765-767` |
| NULL 键 id（0）调用 destroy | `PSA_SUCCESS`（空操作）；其它操作 → `INVALID_HANDLE` | `psa_crypto.c:1214-1216` |
| id 不属于易失/user/builtin 任一区间 | `PSA_ERROR_INVALID_HANDLE` | `slot_management.c:392-394` |
| 易失 id 解析出的 slice/slot 越界（动态库） | 候选槽 NULL → `DOES_NOT_EXIST` → 对外 `INVALID_HANDLE` | `slot_management.c:271-286` |
| 持久/易失 id 存在但 owner 不匹配（KEY_ID_ENCODES_OWNER） | 完整 svc id 比较失败 → `DOES_NOT_EXIST`/`INVALID_HANDLE` | `slot_management.c:374-376`；`crypto_values.h:2529-2534`；测试 `transient_slot_lifecycle` |
| 持久键存储中不存在 | 加载失败后 `DOES_NOT_EXIST` 重映射为 `INVALID_HANDLE` | `slot_management.c:821-828` |
| 无空槽且无可驱逐持久键 | `PSA_ERROR_INSUFFICIENT_MEMORY` | `slot_management.c:649` |
| 存储加载损坏/失败 | `DATA_CORRUPT`/`STORAGE_FAILURE`/`CORRUPTION_DETECTED` 原样传播，保留槽被擦除 | `slot_management.c:821-822` |
| 读者计数达到 `SIZE_MAX` 仍注册 | `CORRUPTION_DETECTED`，不递增 | `slot_management.h:231-234` |
| 读者下溢（无读者仍 unregister） | 测试钩子断言 + `CORRUPTION_DETECTED` | `slot_management.c:882-883` |
| 互斥 lock/unlock 失败 | `PSA_ERROR_SERVICE_FAILURE` | `psa_crypto_core.h:146-155` |
| 导入零长度密钥 | `PSA_ERROR_INVALID_ARGUMENT`（在进入槽流程前拒绝） | `psa_crypto.c:1987-1989` |

【事实】关键标识区间（`crypto_values.h:2449-2457`、`crypto_extra.h:380-387`）：user `0x00000001–0x3fffffff`；vendor 起 `0x40000000`（即易失下限）；builtin `0x7fff0000–0x7fffefff`；builtin 上限与 vendor 上限 `0x7fffffff` 之间的 id 不被任何分支接受，落入 `INVALID_HANDLE`。

### 1.4 边界输入如何影响最终安全结论

【事实+推断】

1. **状态/计数不变量是销毁安全性的核心保障**：PENDING_DELETION 拒绝新读者 + 最后读者擦除，保证槽内存不会在仍有读者时被复用。所有不变量破坏都收敛到 `CORRUPTION_DETECTED`，且动态库下 `psa_wipe_key_slot()` 发现异常时宁可让槽泄漏也不归还空闲链表（`psa_crypto.c:1195-1203`），属故障封闭设计。【事实】
2. **持久键存储删除失败不影响“id 立即失效”这一功能结论**：状态已先转为 PENDING_DELETION，RAM 副本在最后读者注销时擦除；即使返回 `DATA_INVALID`，该 id 后续访问仍走“槽不存在 → INVALID_HANDLE”。安全语义上 id 不可再用，但存储介质上的残留是否清除取决于 ITS 实现，这部分库无法保证。【事实+推断】
3. **合法区间外的 id 全部在进入计数逻辑前被拒绝**，不存在通过畸形 id 触达任意槽的路径：静态库用 `key_id - VOLATILE_MIN` 直接索引并有编译期静态断言（`slot_management.c:308-311`）；动态库解码 slice/slot 位域后做两级越界检查（`274-280`）。【事实】

---

## 2. 易被忽略的兼容/攻击面及本地复核方式

### 2.1 首要发现：诊断接口 `mbedtls_psa_get_stats()` 无锁读取活动槽，存在确定性数据竞争

【事实】该函数在公开头文件 `include/psa/crypto_extra.h:153-160` 声明，用途是“PSA 密钥库资源消耗统计”，注释中无任何线程安全限制。实现（`psa_crypto_slot_management.c:958-996`）遍历全部 slice 的全部槽，**未获取 `mbedtls_threading_key_slot_mutex`**，直接读取：

- `slot->state`（970 行）；
- `slot->var.occupied.registered_readers`（经 `psa_key_slot_has_readers()`，974 行 → `psa_crypto_core.h:188`）；
- `slot->attr.lifetime`、`slot->attr.id`（977-991 行）。

而这些字段的每一个写入点（`psa_register_read`、`psa_key_slot_state_transition`、`psa_free_key_slot`、擦除时的 `memset`）都在槽互斥保护下。

【事实】本地 ThreadSanitizer 实证（clang 18，`-fsanitize=thread`，启用 `MBEDTLS_THREADING_C/PTHREAD`）：复核程序 `task256-verify/stats_race_probe.c` 让 4 个销毁线程与 1 个 stats 轮询线程并发，单次运行 TSan 报告 **12–14 条 data race 告警（计数随线程调度波动，进程零崩溃退出）**，告警读取方全部位于 `mbedtls_psa_get_stats`，写入方覆盖：

- `psa_register_read`（`slot_management.h:235`）；
- `psa_key_slot_state_transition`（`slot_management.h:211`）；
- `psa_free_key_slot`（`slot_management.c:564`，动态库空闲链表编码写入，与 stats 读取的槽处于同一 union 存储）；
- `psa_wipe_key_slot` 的 `memset`（`__tsan_memset` 告警）。

【事实】既有测试未覆盖该并发面：仓库内仅 3 处调用 `mbedtls_psa_get_stats`（`test_suite_psa_crypto_init.function:11`、`test_suite_psa_crypto_slot_management.function:742,921`），全部为单线程顺序调用；官方并发套件 `test_suite_psa_crypto.concurrent`（43 个用例）不含 stats 调用，因此该竞争在 CI 的 TSan 作业中不可见。

【推断】安全影响评估：
- 直接后果是统计结果撕裂/失真（C 语言数据竞争属未定义行为），密钥材料本身不经过该接口外泄；
- 但该接口位于公开头文件、无并发限制说明，集成方合理地可能用其做容量监控/告警决策，错误的 `empty_slots/locked_slots` 可诱发错误的资源调度决策；
- 与 `psa_free_key_slot`/`memset` 的竞争发生在受支持的并发键管理调用（import/destroy 属文档承诺线程安全的 key management API）期间，无需违反 PSA 并发约定即可触发，因此构成真实的兼容性攻击面而非纯理论问题；
- 缓解因素：stats 只读计数/状态/元数据，不读取 `key.data` 密钥缓冲；动态库的 slice 内存在运行期不会被 `free`（仅 `crypto_free` 时释放，而该场景文档要求单线程），故未观察到堆 UAF，最坏情况限定在错误统计与 UB 层面。

### 2.2 次要面：销毁后多步操作仍持有可用密钥副本（文档自认的未满足要求）

【事实】本地复核程序 `task256-verify/slot_refcount_verify.c` 的 B 组实测：`psa_mac_sign_setup()` 后立即 `psa_destroy_key()` 返回 SUCCESS、id 立即 `INVALID_HANDLE`，但随后的 `psa_mac_update()`/`psa_mac_sign_finish()` 仍成功产出正确 CMAC——操作对象中的密钥副本在销毁后继续可用。

【事实】架构文档 `docs/architecture/psa-thread-safety/psa-thread-safety.md:300-310` 将“销毁后不存在任何密钥材料副本”列为长期目标第 3 条并明确标注“we do not have this requirement yet … document this as a security weakness”；同文档 59-65 行说明 PSA 约定本身允许“销毁与同键调用重叠”为未定义行为。

【推断】这在规范内不构成漏洞，但对把 `psa_destroy_key()` 等同于“立即擦除所有密钥材料”的集成方是易踩的兼容性陷阱；FIPS/零化要求场景下需自行保证先 abort 所有多步操作再销毁。

### 2.3 有限的本地复核方式（可重复执行）

【事实】以下步骤均在本机完成，构建为树外构建，不修改源码：

```bash
# 1) 常规线程+测试钩子构建（动态 key store，默认配置）
cmake -S tf-psa-crypto -B build-psa \
  -DENABLE_TESTING=On -DENABLE_PROGRAMS=Off -DGEN_FILES=On \
  -DTF_PSA_CRYPTO_CONFIG_SET="MBEDTLS_THREADING_C;MBEDTLS_THREADING_PTHREAD;MBEDTLS_TEST_HOOKS"
cmake --build build-psa -j$(nproc) -- \
  test_suite_psa_crypto_slot_management test_suite_psa_crypto.concurrent test_suite_psa_crypto_init

# 2) 既有测试与压测（本机结果：50/50、43/43、8/8 全通过；并发套件连跑 10 轮全通过）
./build-psa/tests/test_suite_psa_crypto_slot_management
./build-psa/tests/test_suite_psa_crypto.concurrent
for i in $(seq 1 10); do ./build-psa/tests/test_suite_psa_crypto.concurrent >/dev/null || break; done

# 3) ThreadSanitizer 构建并跑官方并发套件（本机：43/43 通过，0 条 TSan 告警）
cmake -S tf-psa-crypto -B build-tsan -DCMAKE_C_COMPILER=clang \
  -DENABLE_TESTING=On -DENABLE_PROGRAMS=Off -DGEN_FILES=On \
  -DTF_PSA_CRYPTO_CONFIG_SET="MBEDTLS_THREADING_C;MBEDTLS_THREADING_PTHREAD;MBEDTLS_TEST_HOOKS" \
  -DCMAKE_C_FLAGS="-fsanitize=thread -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
cmake --build build-tsan -j$(nproc) -- test_suite_psa_crypto.concurrent
./build-tsan/tests/test_suite_psa_crypto.concurrent

# 4) 定向复核（18 项断言，覆盖 id 边界/销毁后多步副本/8 线程竞争销毁/purge 语义）
clang -fsanitize=thread -g -O1 \
  -Ibuild-tsan/include -Itf-psa-crypto/include -Itf-psa-crypto/drivers/builtin/include \
  task256-verify/slot_refcount_verify.c build-tsan/core/libtfpsacrypto.a -lpthread \
  -o task256-verify/slot_refcount_verify_tsan
./task256-verify/slot_refcount_verify_tsan

# 5) stats 竞争复现（确定性复现 12+ 条 TSan data race）
clang -fsanitize=thread -g -O1 \
  -Ibuild-tsan/include -Itf-psa-crypto/include -Itf-psa-crypto/drivers/builtin/include \
  task256-verify/stats_race_probe.c build-tsan/core/libtfpsacrypto.a -lpthread \
  -o task256-verify/stats_race_probe
TSAN_OPTIONS=halt_on_error=0 ./task256-verify/stats_race_probe
```

修复方向（仅建议，未改动代码）：在 `mbedtls_psa_get_stats()` 外层加槽互斥，或在公开头文件中明确标注该接口非线程安全、不得与并发键管理调用同时使用。

---

## 3. 已证实事实 / 推断 / 验证缺口

### 3.1 已由代码或本地运行证实的事实

1. 四态状态机与全部合法转换、`CORRUPTION_DETECTED` 封闭路径均与代码一致（§1.1 表）。
2. `registered_readers` 的递增/递减/下溢/`SIZE_MAX` 溢出防护仅经 `psa_register_read`/`psa_unregister_read` 两个原语发生，且全部在槽互斥下；公开 API 均通过 `_under_mutex` 包装器注销。
3. PENDING_DELETION 阻止新读者、最后读者擦除的并发销毁算法与架构文档一致；并发同键销毁恰有一个 SUCCESS、其余 `INVALID_HANDLE`，本地 8 线程实测通过。
4. 异常码映射表（§1.3）逐项可在源码定位；NULL id 销毁返回 SUCCESS、区间外 id 返回 INVALID_HANDLE 经本地程序 A 组实测。
5. 多步操作 setup 后注销槽引用、持有密钥副本；销毁后操作仍可完成（本地 B 组实测）。
6. `mbedtls_psa_get_stats()` 无锁读取活动槽字段，TSan 确定性报告 12–14 条数据竞争（随调度波动）；官方测试无并发 stats 覆盖。
7. 官方并发套件在 TSan 下 43/43 通过且零告警，槽管理套件 50/50（3 跳过）、init 套件 8/8 通过；并发套件 10 轮重复压测无失败。
8. 动态 key store 为本仓库默认（`crypto_config.h:1311` 启用 `MBEDTLS_PSA_KEY_STORE_DYNAMIC`），易失 id 经 slice(5 bit)/slot(25 bit) 位域解码并带越界检查。

### 3.2 推断（未经直接证实的分析判断）

1. stats 竞争的实际危害主要是统计失真与未定义行为，无证据表明可导致密钥材料泄露或槽内存复用破坏；未做形式化验证，不能排除极端时序下的更严重后果。
2. 持久键 `psa_destroy_persistent_key` 返回 `DATA_INVALID` 时存储残留的真实可利用性取决于 ITS 后端，本分析未涉及 ITS 文件实现的取证残留评估。
3. `MBEDTLS_THREADING_ALT` 用户自定义互斥返回失败时的 `SERVICE_FAILURE` 全链路行为仅经代码审阅推断，未做故障注入。

### 3.3 验证缺口

1. 未本地编译/测试**静态 key store**（关闭 `MBEDTLS_PSA_KEY_STORE_DYNAMIC`）配置，相关用例 `non_reusable_key_slots_integrity_in_case_of_key_slot_starvation` 在动态构建下被依赖条件排除（50 项中 3 跳过即含此类）。
2. 未做自定义互斥（ALT）故障注入，`SERVICE_FAILURE` 路径无运行证据。
3. 未用故障注入框架模拟 ITS remove 失败，`DATA_INVALID` 传播与存储残留为代码级结论。
4. 未对 `test_suite_psa_crypto_slot_management` 单线程套件做 TSan 运行（仅跑了并发套件与两个定向程序）。
5. 外部安全处理器驱动（opaque/external key）的并发行为文档明确不提供保证，本次未测驱动入口并发。
6. 未评估 `MBEDTLS_PSA_STATIC_KEY_SLOTS`（静态密钥缓冲）配置下的擦除时序差异。
7. 未运行 TLS/SSL 层集成场景，结论限定在 tf-psa-crypto core 的键管理面。

### 3.4 最终核对：输入边界确认清单

| 边界项 | 确认结论 | 确认方式 |
|---|---|---|
| NULL id（0） | destroy→SUCCESS；其余→INVALID_HANDLE | 源码 + 本地实测 |
| user 区间 `1–0x3fffffff` | 不存在→INVALID_HANDLE；存在→按完整 id 匹配 | 源码 + 本地实测 |
| 易失区间起 `0x40000000`，动态库 slice/slot 解码 | 越界 slice/slot→NULL 槽→INVALID_HANDLE，无越界内存访问 | 源码位域检查 + 静态断言 |
| builtin 区间 `0x7fff0000–0x7fffefff` | 走平台/驱动加载，失败按 INVALID_HANDLE/DOES_NOT_EXIST 传播 | 源码审阅，未运行（需平台回调） |
| 空隙 `0x7fffefff–0x7fffffff` 及其它非三类区间 | 一律 INVALID_HANDLE | 源码 + 本地实测 `0x7fffffff` |
| owner 不匹配（SVC 编码构建） | 完整 id 比较失败→INVALID_HANDLE | 既有测试 `transient_slot_lifecycle` 覆盖 |
| 读者计数 0 下溢 / SIZE_MAX 上溢 | 均收敛 CORRUPTION_DETECTED，状态不被破坏 | 源码 + 测试钩子断言机制 |
| 零长度密钥导入 | 入槽前 INVALID_ARGUMENT 拒绝 | 源码 |
| 槽满（无空槽、无可驱逐持久键） | INSUFFICIENT_MEMORY，既有填充测试覆盖 | 既有测试 `fill_key_store` |
| 只读生命周期销毁 | NOT_PERMITTED，RAM 副本仍擦除 | 源码审阅，未运行 |
| 并发同键销毁（8 线程） | 恰 1 个 SUCCESS，其余 INVALID_HANDLE，无崩溃/无 TSan 告警 | 本地实测 |
| 销毁与 stats 诊断并发 | TSan 12–14 条数据竞争（随调度波动；本报告首要发现） | 本地实测 |

---

## 附：分析产物

- 复核程序：`task256-verify/slot_refcount_verify.c`（18 项功能/并发断言）、`task256-verify/stats_race_probe.c`（stats 竞争复现）。
- 构建目录：`build-psa`（gcc Debug，线程+测试钩子）、`build-tsan`（clang TSan）。
- 子模块按主仓库锁定提交检出；嵌套 `tf-psa-crypto/framework` 以绝对符号链接复用顶层 framework（同一锁定提交 `ced3149`），未修改任何受版本控制的源码。
