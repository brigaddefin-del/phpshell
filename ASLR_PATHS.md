# ASLR 路径分析：纯 Zend 绕过 vs. 地址泄漏

日期：2026-10-21
前提：no-ASLR 纯 HTTP RCE 已打通（`NOASLR_REPORT.md`）。
约束：**完全远程、纯 HTTP；不构造目标侧特定 PHP**。目标页面只有
普通 `echo`（无 session 调用）。

本文只分析 ASLR 打开后的两条路径，不把旧的自定义 PHP 泄漏/ROP 结果当作有效交付。

---

## 0. 结论摘要

| 路径 | 当前判断 | 主要阻塞 |
|---|---|---|
| 路径一：纯 Zend、无泄漏绕过 | 未找到可靠原语 | 所有可控写入都以 NUL 结尾；partial overwrite 会固定写坏一个 ASLR 相关字节；没有已知的固定函数地址 |
| 路径二：纯 HTTP 地址泄漏 | 默认配置下未找到可用入口 | 默认 `session.serialize_handler=php` 拒绝含 `\|` 的 session key；旧泄漏需要 `php_serialize` + 用户态 `__serialize` 重入 |

在“默认 php.ini + vanilla session 页面”条件下，目前没有把 ASLR 打通。
下面给出已做的实验、源码依据和下一步可验证的突破口。

---

## 1. 现有原语回顾

no-ASLR 链的关键写原语：

1. A 请求 OOM，留下悬空 `PS(http_session_vars)` zend_reference（R0）。
2. B 请求的 56B 原始值缓冲区可覆盖 R0，写入：
   - `R0+0x00` gc：refcount=1, type=IS_REFERENCE
   - `R0+0x08` val.value：任意 8 字节指针
   - `R0+0x10` val.type：0x307 (IS_ARRAY_EX)
   - `R0+0x18` sources：0
3. dtor 路径：
   `zend_delete_global_variable` → `zval_ptr_dtor` →
   `zend_reference_destroy` → `zend_array_destroy(val.value)` →
   `zend_hash_destroy` → `pDestructor(&bucket->val)`。
4. 承载 fake HashTable 的最佳位置是**存活的 192B zend_string** 的 data
   （L=167），因为它不会被 free-list 的 next 指针覆盖 gc；内容是字段值，
   从 data+0 开始可控。

因此 ASLR 下缺的是：`val.value`（堆地址）和/或 `pDestructor`（libc/libphp
代码地址）。

---

## 2. 路径一：纯 Zend、无泄漏 ASLR 绕过

目标：不使用任何泄漏，直接构造出对 ASLR 不敏感的指针/函数指针。

### 2.1 方案 A：复用旧 reference 的 val.value = A0（真实 session HashTable）

- A 中旧 reference 的 `val.value` 指向真实 session HashTable A0。
  no-ASLR 实测 A0 = `0x7ffff5e03268`（`R0+0xf48`）。
- 如果 B 不覆盖 R0 的 val.value，而是让 A0 的内存变成攻击者可控的
  fake HashTable，就不需要知道堆基址。
- 可行性检查：
  - A0 是 56B 的 HashTable 结构（sizeof(zend_array)=56，bin 6）。
  - A0 的 `pDestructor` 原本是 `ZVAL_PTR_DTOR`（libphp 指针）。
  - 需要 A0 被一个**存活**的、内容可控的分配重占，且 `gc.type == IS_ARRAY`。
  - 但 B 中内容可控的分配有两类：
    1. `multipart_buffer_read_body` 的 raw value buffer：在字段处理完就被
       `efree()`；释放后 allocator 会把 `next_free_slot` 写到块 offset 0，
       覆盖 gc，导致 `GC_DELREF` 不归零，不会进入 array dtor。
    2. 存活的 zend_string：gc type 是 IS_STRING（6），`rc_dtor_func` 会调用
       `zend_string_destroy`，不是 `zend_array_destroy`。
  - 存活的真实 HashTable 有正确 type=7，但 `pDestructor` 是真实的
    `ZVAL_PTR_DTOR`，我们无法在不改变 gc 的情况下改它。
- 结论：A0 复用需要一个“存活、可控、type=IS_ARRAY”的分配，目前没有。

### 2.2 方案 B：partial pointer overwrite（保留 libphp 高字节）

思路：把 A0 的 `pDestructor` 从 `ZVAL_PTR_DTOR` 改成 libphp 内另一个
函数/ gadget，只覆盖低 2–3 字节，保留 libphp 基址高字节。这样不需要泄漏。

需要解决两个问题：

1. **能否写到 A0+0x30 且只覆盖低字节？**
   - 字符串/raw buffer 的写总是带一个 NUL：
     `zend_string_init` 在 data[len] 写 0；`multipart_buffer_read_body`
     在 out[total] 写 0。
   - 若从 `pDestructor` 开始写 N 字节，则第 N 字节一定是 0。
   - 例如覆盖低 2 字节：`b0,b1` 可控，`b2=0`；覆盖低 3 字节：`b0..b2`
     可控，`b3=0`。
   - 目标 libphp 地址的高字节中，`b3/b4/b5` 都带 ASLR 随机性；强制为 0
     只有在目标绝对地址对应字节本来就为 0 时才成立。这依赖基址，不可靠。
2. **能否找到 2–3 字节范围内的有用 target？**
   - 已实测当前构建的 libphp 符号（未 strip）：
     ```text
     zif_system          0x43a870
     zend_call_function  0x566d20
     zend_hash_destroy   0x5cbb90
     zend_array_destroy  0x5cbdc0
     zval_ptr_dtor       0x613c50
     ```
   - `zval_ptr_dtor` 与 `zend_call_function` 相距 0xacf30（约 700KB），
     与 `zif_system` 相距 0x1d93e0（约 1.9MB）。
   - 低 2 字节 partial overwrite 只能在同 64KB 内跳转；低 3 字节加上
     强制 NUL 的 b3=0 又依赖基址字节。当前没有落在同一 64KB 的可用
     gadget。
   - libphp 只导入 `popen`（`objdump -T` 可见），没有导入 `system`；
     `popen@plt` 也需要 libphp 基址，且第二次参数 rsi 不可控。
   - 旧情报的 `zend_call_function → zif_system` 需要 fake FCI，属于需要
     libphp 基址的另一条链。

结论：partial overwrite 是目前最接近“纯 Zend”思路的方向，但 NUL 终止符
是硬阻塞；除非找到**不带终止符的任意长度前缀写**。

### 2.3 方案 C：allocator 自写指针（free-list next / shadow）

- 释放块的 offset 0 有明文 `next_free_slot`（堆指针），offset size-8 有
  XOR 编码的 shadow。
- 如果把 fake reference 的 val.value 放在某个释放块的 `next_free_slot`
  位置，allocator 会替我们写一个真实堆指针。
- 但该指针指向**另一个释放块的起点**，其 offset 0 又是 next 指针，
  不是合法的 array gc；`GC_DELREF` 不会归零。
- 对齐上，R0+8 要成为某个 bin 的 slot 起点；在 R0=0x...2320 时，
  R0+8=0x...2328 只有 8B bin 能整除（页内偏移 0x328=808=8×101），
  8B 块没有可控内容。
- 结论：不能直接得到“指向可控 fake HashTable 的堆指针”。

### 2.4 方案 D：固定地址代码

- Apache 主程序是 PIE（`file /usr/sbin/apache2` = pie executable），
  `libphp.so`、libc 都受 ASLR。
- 唯一固定可执行页是 vsyscall `0xffffffffff600000`，只有
  gettimeofday/time/getcpu，不能任意 syscall/RCE。
- 主程序/模块都没有可直接用的 `system@popen@execve` 固定 PLT（已检查
  导入；且 PIE 基址随机）。
- 结论：没有固定代码地址可用。

### 2.5 路径一小结

在现有原语下，纯 Zend 无泄漏绕过需要以下之一：

- **不带 NUL 的 partial write**（可改 A0->pDestructor 低字节且保留高字节）；
- **存活、可控、type=IS_ARRAY 的分配**（可重占 A0）；
- **allocator 自写指针 + 可控内容**的组合；
- 某个可在同一 64KB 内完成攻击的 libphp 真实函数指针。

这些目前都未被证实。下一步最值得做的是测量 libphp 内
`zval_ptr_dtor` 附近 64KB 的 gadget/函数，并寻找是否有“写 N 字节不带
终止符”的 PHP 分配路径。

---

## 3. 路径二：纯 HTTP 地址泄漏

目标：把堆 chunk base / libphp base / libc base 泄漏到 HTTP 响应，
再由 no-ASLR 链动态计算地址。

### 3.1 默认配置下的 session 序列化器限制（已实验）

默认：

```ini
session.serialize_handler = php
session.use_only_cookies = 1
```

默认 `php` encoder 在写每个 session key 前：

```c
smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
    /* key 含 '|'：放弃整个 encode，返回 NULL */
    fail = true;
    break;
}
smart_str_appendc(&buf, PS_DELIMITER);
php_var_serialize(&buf, struc, &var_hash);
```

实测（gdb `ps_files_write`）：

```text
progress key = upload_progress_X|E:20:"AAAAAAAAAAAAAAAAAAAA";
FWRITE key=injtest0005 klen=11 vlen=0
php_session_decode len=0
```

即：progress key 含 `|` 时，encoder 直接返回 NULL，session 写为空；
END cleanup 读到的 session data 长度为 0。**默认配置下无法用 key 注入
任意 serialized 数据。**

默认 decoder 也不是 C 字符串解析：

```c
while (*q != PS_DELIMITER) {
    if (++q >= endptr) { retval = FAILURE; goto break_outer_loop; }
}
```

NUL 不能绕过 `|` 分隔符。

### 3.2 旧泄漏原语的依赖（不满足当前约束）

`NOTES.md` 第 10 节的两个泄漏都依赖：

1. `session.serialize_handler = php_serialize`（非默认；脚本 `ini_set` 或
   应用配置）。
2. 用户态类 `C::__serialize()` 在 encode 过程中释放 `$_SESSION` 数组，
   再用 `zend_reference`/`stream_bucket_new` 重占，制造 encoder 的 UAF。
3. 应用调用 `session_encode()` 并把结果输出/保存在可读位置。

当前目标页面只有普通 `echo`，没有用户态类，也没有 `session_encode()`
输出；默认 handler 又是 `php`。因此这两条泄漏在本约束下不可达。

### 3.3 纯 HTTP 下可控的 session 数据面

默认配置里，attacker 能影响并进入 session 文件的只有：

- progress key（key 名，不能含 `|`）；
- progress data 数组的固定键/值：
  `start_time`, `content_length`, `bytes_processed`, `done`,
  `files[0].field_name`, `files[0].name`, `files[0].tmp_name`,
  `files[0].error`, ...
- 其中 `field_name`/`name` 是 attacker 字符串，但作为**序列化值**
  （`s:<len>:"...";`）写入，binary-safe，不能变成 key 或 enum。

session decoder 读到的结构由 PHP 自己生成；没有 attacker 可控的
`E:`/`O:`/`C:`/`R:` 语法，也没有跨变量注入。

### 3.4 候选泄漏点与阻塞

| 候选 | 结果 |
|---|---|
| progress key 注入 serialized `E:` → enum warning `%.*s` | 默认 `php` encoder 拒绝含 `\|` 的 key；写入 0 字节 |
| `E:` 长度越界读 | `maxlen < len` 检查，len 被输入缓冲区长度限制 |
| session file 作为泄漏载体 | 需要先有 encoder OOB 写；默认 encoder 没有 |
| `unserialize` 内置类 handler 的 OOB/警告 | 默认配置无法注入 `O:`/`C:`；progress data 只有数组/字符串 |
| 错误信息 `%p`/指针格式 | session/unserialize 路径没有 `%p`；只有 enum 的 `%.*s` |
| `session_start` 警告打印 id/path（仅在应用调用时才有此候选） | 不含内存地址；id 字符受限 |
| `/proc/self/maps` | 需要目标侧 PHP 读文件，违反约束 |

### 3.5 如果允许改 php.ini（不是应用 PHP）

把 `session.serialize_handler` 改成 `php_serialize` 后：

- progress key 里的 `|` 不再被 encoder 拒绝（`php_serialize` 用
  `php_var_serialize` 序列化整个数组，不检查 key 的 `|`）；
- 可以用 key 注入额外 session 变量，触发 decode warning/内置类 handler；
- 但旧的两个泄漏仍需要“encode 期间释放 session 数组”的重入，而
  vanilla 页面没有这个重入。

因此即使改 INI，也不等于自动有泄漏；还需要一个纯 PHP 内置的
reentrancy gadget，目前未找到。

---

## 4. 两条路径的下一步实验

### 路径一（纯 Zend）

1. **测量 libphp 布局**：`nm -D`/`objdump` 取
   `zval_ptr_dtor`、`zend_call_function`、`zif_system`、`system@plt`
   的偏移，确认是否存在同一 64KB/16MB 内的可用 partial target。
2. **找无终止符写**：检查 `erealloc` 增长、stream bucket、`smart_str`
   等路径是否有“只复制前缀、不写 NUL”的分配；若有，可对
   A0->pDestructor 做真正的低字节 partial overwrite。
3. **A0 存活重占**：尝试在 B 中把 A0（56B HashTable）用**存活**的
   可控分配重占，且保持 `gc.type=IS_ARRAY`；例如：
   - 用 session decode 生成真实小数组，落在 A0；
   - 再用一个只覆盖 pDestructor 低字节、不覆盖 gc 的写。
4. **allocator 指针对齐**：扫 A 的参数（progress key 长度、SID 长度、
   文件数量/大小）看 R0 是否能移动，使 R0+8 成为更大 bin 的 slot，
   从而用 free-list next 指针得到“可控指向”的堆指针。

### 路径二（泄漏）

1. **只在默认配置下**枚举所有能把 attacker 字符串输出到 warning 的
   路径（`php_error` 的 `%s`/`%.*s`），确认是否有长度未校验的
   `%.*s`。
2. **内置 `Serializable` 类 handler fuzz**：`ArrayObject`、
   `SplObjectStorage`、`DateTime`、`SimpleXMLElement`、`ZipArchive`、
   `Phar` 等的 `unserialize()` C 实现，寻找越界读/把输入打印到 warning
   的路径。注意默认配置目前无法把 `C:`/`O:` 注入 session，所以这条
   只在 `php_serialize` 或应用可控 session 数据时才有意义。
3. **progress data 的值**：确认 `field_name`/`name`/`tmp_name` 是否
   在任何错误路径被 `%.*s` 打印；目前源码中未找到。
4. **BG(unserialize) 写原语**：如果能在纯 HTTP 下绕过
   `serialize_lock` 依赖，`var_push` 的任意写可以伪造一个
   `zend_string.len`，再触发 `%.*s` warning 泄漏。该链目前因需要
   应用层 `__wakeup`/autoload 而暂停。

---

## 5. 约束下的判断

- **纯 Zend 无泄漏**：理论上最优雅，但受“NUL 终止符 + 无固定代码地址”
  限制；目前没有可靠构造。
- **地址泄漏**：在默认 `php` serializer 下，progress key 注入被
  encoder 的 `memchr('|')` 直接拒绝；旧泄漏又依赖非默认 serializer +
  用户态重入。纯 HTTP、无应用代码的泄漏入口尚未找到。
- 若允许**非默认 php.ini**（`session.serialize_handler=php_serialize`），
  可以继续研究 key 注入 + 内置类 handler；这仍不是“写特定 PHP”，但
  已经偏离默认配置。
- 若允许目标应用存在一个 session 对象/进度端点（应用 gadget），旧的
  `php_serialize` 泄漏链可以复用；这属于应用层依赖，不符合当前
  “vanilla session 页面”的约束。

在严格约束下，当前交付应明确标注为 **no-ASLR RCE**；ASLR 的两条路径
均未完成，需要上述实验之一取得突破。

---

## 6. 追加：固定 Zend 偏移实测（2026-10-21）

用户提示“Zend 有些地址可能是固定的”后，做了以下测量。

### 6.1 固定偏移

ASLR 开启（`randomize_va_space=2`）下，用 A/B 触发在
`php_session_track_init` 读取：

- 旧 reference R0 = **chunk + 0x2320**，三次 master 重启均如此。
- session HashTable A0（R0->val.value）：
  - A 的 PHPSESSID 长度 8..32：A0 = **chunk + 0x3268**
  - A 的 PHPSESSID 长度 1..5：A0 = **chunk + 0x3230**
- Zend main chunk 基址 2MB 对齐。
- 同一 Apache master 下，连续 kill -9 worker 5 次，新 worker 的 chunk
  基址完全不变（例：`0x7fa32de00000`，B=7）。即：
  - **一个 master 生命周期内 chunk 基址固定**；
  - 但 master 重启才重新随机化，worker 崩溃不能重试 B。

### 6.2 chunk header 不是代码跳板

dump chunk+0x000..0x100：

- `heap`/`next`/`prev`/`free_slot[]` 全是堆指针；
- `size`/`peak`/`chunks_count`/`pid` 是小整数；
- 没有 libphp/libc 代码指针。
- 1 字节 partial write 只能把旧 val.value 指向 `chunk+0x00XX`，
  正好落在 header，没有可用 pDestructor；2 字节 partial write 会
  清零 b2（16MB 块内 2MB 索引低 3 位），实测该槽是库的只读
  `.eh_frame` 数据，不是可控 Zend chunk。

### 6.3 A0 的旧内容

A0=chunk+0x3268 处的旧 HashTable：

```text
A0+0x00 gc        = 0xffffffff00000106   (refcount 不是 1)
A0+0x10 arData    = chunk+0x33c0
A0+0x30 pDestructor = libphp zval_ptr_dtor (真实代码指针)
```

因为 refcount 不是 1，不覆盖 val.value 时 dtor 只减引用，不会进入
`zend_array_destroy`；所以之前必须伪造 reference。

### 6.4 新原语：二进制 PHPSESSID 写入 A0 的 gc

- `php_session_valid_key()` 用 C 字符串扫描；PHPSESSID 值可以是
  `validprefix\0<binary>`，NUL 之后的二进制仍会进入
  `progress->sid` / `PS(id)` 的 zend_string。
- `PS(id)` 是直接 `zend_string_init`，其 raw 值缓冲先释放，随后
  320B 的 PS(id) 会复用该 slot。
- 实测：SID 长度 280、`sidvalid\0...` + 在 SID offset 0x110 放
  fake gc，B 的 track_init 时 **A0 第一个 qword 变成
  `0x0000000700000001`**，完全不需要知道 chunk 基址。
- 该 320B 存活字符串位于 page3 slot 0x3140（data 0x3158），
  A0=0x3268 正好是 data+0x110。
- 这意味着：**gc（refcount=1, type=IS_ARRAY）可以相对 A0 写入**。

### 6.5 仍未解决：pDestructor / arData

- A0=0x3268 时，pDestructor 在 A0+0x30=0x3298，已经跨到**下一个
  320B slot**（0x3280）；实测该处被 B 的 320B  allocation 覆盖成
  `0xffff...`，旧真实 `zval_ptr_dtor` 丢失。
- 若把 A 的 SID 改到 1..5，A0=0x3230，pDestructor 落在同一个
  320B slot 内；但：
  - 要覆盖/控制 gc/flags/arData，320B 字符串长度需 ≥257，而
    pDestructor 在 data offset 0x108=264，字符串 copy 会**完整覆盖**
    pDestructor（无法保留高字节）；
  - 要保留 pDestructor，长度需 ≤263，此时 arData（data offset
    0xd8+0x10=232）已被覆盖，必须写入一个绝对指针，而基址未知；
  - 想只覆盖 gc/flags 不碰 arData，需要 L<232，但 320B bin 要求
    L≥257；bin 大小与 copy 长度耦合，无法做到。
- 8B header key 方案也失败：R0+8=0x2328 在 page2 内只有 8B slot 101
  对齐，而 page2 被启动期 56B 分配占据（MAP2=bin6），不是 bin0；
  且 8B 块的 free-list shadow 本来就覆盖整 8 字节，无法保留旧高字节。

### 6.6 结论

固定 Zend 偏移是真实的、可用的：

- R0、A0、fake HT 相对 chunk 的偏移固定；
- 同一 master 内 chunk 基址固定；
- 旧的真实 `zval_ptr_dtor` 指针位于 A0+0x30。

但仅靠这些仍不能绕过 ASLR，因为：

1. 需要一个**不写 NUL、只改前缀**的 partial write 才能保留
   pDestructor 高字节；
2. 或者需要把 arData 指向一个**绝对地址可控**的 fake bucket；
3. 当前所有可用写都是“整段 copy + NUL 结尾”，且 bin 几何固定，
   上述两种都未构造出来。

下一步最值得继续的是：
- 用 A 参数把 A0 移到某个地址，使“字符串 data 结束于 pDestructor+1”
  与 bin/slot 几何同时成立（目前 0x3230/0x3268 都不成立）；
- 或找到任意一个“只写 N 字节、不带终止符”的 Zend 分配/复制路径；
- 或先泄漏 chunk 基址（同一 master 内固定，一次泄漏可复用）。

---

## 7. 追加：A0 形态与 page3 bin 实测

### 7.1 A0 不只两个值

细扫 A 的 PHPSESSID 长度（no-ASLR，page3 固定 320B bin）：

| A SID 长度 | A0（chunk 偏移） | A0+0 处 gc | A0+0x30 |
|---|---|---|---|
| 1–13 | `0x3230` | `0x80000000005978e8`（不是 array HashTable） | `0x7ffff5e61208` |
| 14–21 | `0x3268` | `0xffffffff00000106`（refcount 巨大） | 真实 `zval_ptr_dtor` |
| 22–23, 32–40 | `0x3230` | 同上 | 不是 pDestructor |
| **24–30** | **`0x3310`** | **`0xc000040700000001`**（rc=1，type=IS_ARRAY） | **真实 `zval_ptr_dtor`** |

`0x3310` 是首次出现的“本身就可作为 HashTable 使用”的 A0：

```text
A0=chunk+0x3310
A0+0x00 = 0xc000040700000001   gc: rc=1, type=IS_ARRAY
A0+0x10 = chunk+0x4900/0x4540  arData（真实堆指针）
A0+0x30 = libphp zval_ptr_dtor（真实代码指针）
```

也就是说，**不需要伪造 gc/flags**，stale reference 的 val.value=A0、
`zend_array_destroy(A0)` 就会走真实 array 路径。

### 7.2 page3 的 bin 是固定的

在 ASLR/no-ASLR 下，B 的 chunk page map 始终是：

```text
page1 bin3 (32B)
page2 bin6 (56B)
page3-7 bin16 (320B)
page8-12 bin20 (640B)
```

用自定义请求头 `X-Pad: A*N`（N=0/96/320/480/700/1000）测试，page map 完全不变。
gdb 在 `zend_mm_alloc_small_slow` 上抓第一次 320B 分配：

```text
zend_mm_alloc_small_slow(bin_num=16)
  zend_hash_real_init_mixed_ex
  zend_hash_real_init_mixed
  _zend_hash_add_or_update_i
  zend_hash_add
```

第一次 640B 分配是同一个 HashTable 的 `zend_hash_do_resize`。所以 page3
的 320B bin 是启动期 HashTable arData 固定分配的，**不能靠请求头/字段改变**。

### 7.3 320B slot 几何与 A0=0x3310

A0=0x3310 位于 page3 的 320B slot2（block `0x3280`，data `0x3298`）：

```text
A0 = 0x3310 = slot2 data + 0x78
arData       = A0+0x10 = slot2 data + 0x88
nNumUsed     = A0+0x18 = slot2 data + 0x90
pDestructor  = A0+0x30 = slot2 data + 0xa8
```

- 一个 320B zend_string 在 slot2 的 data 从 0x3298 开始，长度只能是 232..295。
- 要覆盖/控制 pDestructor（data offset 0xa8=168），必须用长度 ≥168 的 copy；
  但 320B bin 的最小长度是 232，所以 copy **必然同时覆盖 arData**
  （offset 0x88=136）和前面的 gc/flags。
- 要只 NUL pDestructor 字节0（保留高字节），需要 L=168；这对应
  alloc=193 → **224B bin**，不能占用 320B slot2。
- 要保留 arData（不覆盖），需要 L<136；更不可能占用 320B slot。
- 因此 A0=0x3310 虽然 gc 合法，但仍然被“copy 长度 vs bin 大小”卡住：
  无法在保留 arData 的同时对 pDestructor 做 partial overwrite。

### 7.4 当前判断

- 固定 Zend 偏移确实存在，并且 A0=0x3310 提供了一个真实的、rc=1 的
  可控起点；
- 但 page3 的 320B bin 固定，320B slot 的 data 长度窗口（232..295）
  与 A0 内部字段偏移（arData 136、pDestructor 168）不匹配；
- 仍然缺一个“只写前缀、不带 NUL”的写原语，或者一个能让
  arData 指向受控数据的相对指针。

这条线目前没有闭环；no-ASLR RCE 仍是唯一已验证的代码执行。


