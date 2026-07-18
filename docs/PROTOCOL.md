# BrickGuard Protocol

## Endpoints

~~~text
/proc/brickguard/control  0600
/proc/brickguard/cache    0600
~~~

Open control with O_RDWR, write exactly one command, then read the reply from
the same descriptor. Maximum command length is 255 bytes. Replies are
per-open and at most 127 bytes.

BLG mutation and cache reads/writes are accepted only in mode 0.
Mode changes wait for block calls admitted under the previous mode to finish.

## Compatibility

~~~text
HELLO 1
-> OK HELLO 1 <product-version>
~~~

1 is BG_RPC_API_VERSION.

## Status

~~~text
MODE STATUS
STATUS
BLG CACHE STATUS
BLG MAP STATUS
BLG PACK ID
BLG MAP INFO
~~~

Examples:

~~~text
MODE 1 DENY
BLG READY NO REAL WRITE
OK CACHE READY RO
OK PLAN READY NO WRITE
OK PACK <64-lowercase-hex>
OK MAP <entry-count> <total-image-bytes> <64-lowercase-hex>
~~~

## Cache

~~~text
BLG CACHE BEGIN <total-bytes> <pack-id>
write /proc/brickguard/cache sequentially from offset 0
BLG CACHE COMMIT
BLG CACHE VERIFY
BLG CACHE DROP
~~~

The upload must be exact and sequential. COMMIT hashes all bytes, changes all
vmalloc pages to read-only, and then marks the cache READY. DROP first changes
the pages back to RW; failure keeps the control plane loaded and returns an
error.

## Map

~~~text
BLG MAP BEGIN
BLG MAP ADD <name> <cache-offset> <image-size> <major> <minor>
            <target-size> <flags> <tier>
BLG MAP COMMIT
BLG MAP VERIFY
BLG MAP DROP
~~~

Map validation rejects empty ranges, overflow, ranges outside the cache,
images larger than targets, invalid flag combinations, tiers above 2, and
duplicate target dev_t values. The sum of all mapped image lengths is limited
to 256 MiB even when several entries reuse the same cache range.

Flags:

~~~text
1  A/B target
2  shared target
4  EFISP metadata
~~~

Exactly one of A/B or shared must be present.

## Selftest

~~~text
BLG SELFTEST /dev/block/loopN INJECT
-> OK SELFTEST REPAIRED
~~~

The loop must use the CLI-created /data/local/tmp/brickguard-blg.XXXXXX
regular backing file. This command performs real writes to that loop backing
file; it never consumes map target paths.

## Trusted Manager Control

Mode changes are intentionally outside procfs and use KPM CTL0:

~~~text
STATUS
BLG STATUS
MODE 0
MODE 1
MODE 2
~~~

The loader init argument itself must be exactly 0, 1, or 2.

## Lifetime

Runtime unload returns -EBUSY without changing state. The required patched
KernelPatch loader honors that veto before list deletion or executable-memory
free. Reboot to update or remove BrickGuard. `DEGRADED ... REBOOT REQUIRED`
means init failed after at least one required hook was installed; mode changes
are then disabled and installed hooks remain in DENY mode.
