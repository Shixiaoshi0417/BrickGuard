# Device Test

Use a disposable test device and kernel sources that exactly match it. Do not
run raw-write tests against a real partition.

Apply `kernelpatch/0001-kpm-honor-exit-veto.patch` to the KernelPatch tree used
for the target boot image, then rebuild/repatch that image. An unpatched loader
must reject BrickGuard because `kpm_exit_veto_supported` is unresolved.

## Build

~~~sh
make test
make cli
make kpm KDIR=/path/to/prepared/device-kernel
~~~

Check that the KPM is ELF64, AArch64 and REL. The Makefile also rejects
compiler runtime atomics.

## Deploy

Unload KPMDynaLab and earlier BrickGuard builds first. Push the KPM and CLI
with the mechanism used by your KernelPatch frontend. Load BrickGuard with
the exact init parameter 0.

Manager syntax differs between KernelPatch/APatch frontends. Use these CTL0
payloads when instructed below:

~~~text
MODE 0
MODE 1
MODE 2
STATUS
~~~

## BLG Test

~~~sh
brickguard status
brickguard setup
brickguard verify
brickguard selftest
~~~

Expected core results:

~~~text
MODE 0 OFF
BLG READY NO REAL WRITE
Pack binding: MATCHED
RAM Cache: INTACT
Image Map: INTACT
OK SELFTEST REPAIRED
~~~

selftest must create only a temporary file and a loop device. Confirm dmesg
contains no oops and the temporary loop is detached afterward.

## Mode Matrix

Create a separate regular-file-backed loop with losetup. Record its hash
before each case.

Mode 0:

- dd to the loop succeeds;
- backing-file content changes.

Mode 1:

- dd fails with EPERM;
- BLKZEROOUT/discard/fallocate fail with EPERM;
- backing-file content is unchanged;
- a new shared writable mmap is rejected.

Mode 2:

- dd reports the requested byte count;
- discard/fallocate/uring discard report success;
- backing-file content is unchanged;
- a new shared writable mmap is rejected with EOPNOTSUPP.

Test the same loop through /dev/loopN, /dev/block/loopN, a symlink and a path
containing a doubled slash. Results must be identical because hooks are
object-entry based, not path based.

## Failure Checks

- Loading without a parameter or with 3, 02, or 1 extra must fail.
- BLG mutation in mode 1 or 2 must return ERR MODE LOCKED or EPERM.
- Rebuild the disk Pack after prepare; brickguard verify must reject the pack
  binding until prepare is run again.
- Request unload with and without open proc descriptors; both must return
  EBUSY and BrickGuard status must remain available.
- Do not load BrickGuard alongside an old KPM that removes an entire shared
  hook chain with plain unhook().
- Do not co-load an unaudited KPM that hooks the same blkdev symbols and changes
  the same fargs skip/return fields; callback order can change the final result.

Reboot after the matrix to remove or replace BrickGuard. Runtime hot unload is
not supported.

## Known Boundary

This matrix does not claim coverage for an mmap created before protection was
enabled, mounted-filesystem writeback, direct kernel BIO submission,
vendor-private interfaces, fastboot, EDL or independent recovery.
