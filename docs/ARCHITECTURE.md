# Architecture

## Components

kpm/brickguard_main.c:

- KPM metadata and init/CTL0/exit callbacks
- exact load-parameter parsing
- trusted mode transitions

kpm/brickguard_block.c:

- raw block file-operation hooks
- OFF, DENY and SIMULATE behavior
- in-flight I/O accounting and quiescent mode transitions

kpm/brickguard_blg.c:

- root-only /proc/brickguard/control and /proc/brickguard/cache
- sequential cache upload, SHA-256 and RO page transition
- validated image map and pack binding
- regular-file-backed loop repair selftest

cli/brickguard_blg.c:

- device-local Recovery Pack creation
- strict Pack v3 metadata, device identity, hardlink and fd verification
- active-slot map construction
- minimum-capacity loop setup

## State And Locking

bg_admin_busy serializes mode changes, proc transactions, cache access,
selftest and status. Mode and shutdown flags use acquire/release atomics.
bg_io_active plus bg_mode_transition form a sequentially consistent barrier:
the manager does not acknowledge a new mode until calls admitted under the old
mode have returned from the original block operation.

Initialization publishes DENY before the first hook is installed, then switches
to the requested mode only after all required hooks and BLG control endpoints
are ready.

Each control-file open owns its own reply buffer. CLI uses one O_RDWR file
descriptor for write plus read, so another client cannot replace its reply.

Runtime hook removal is intentionally not attempted. BrickGuard requires the
KernelPatch exit-veto patch, and its live exit callback returns -EBUSY before
changing state. The patched loader retains the module and executable memory.
Reboot is the only supported update/removal boundary.

## Recovery Boundary

The map is metadata only. It records cache ranges and target dev_t values,
but no KPM command opens or writes those target devices.

`BLG MAP VERIFY` proves that the committed in-kernel plan has not changed. It
does not independently reconstruct the expected plan from the current target
topology. The CLI supplies and verifies the Pack/Cache binding before commit.

The old BLG-specific always-simulate EFISP guard is intentionally represented
by the global mode policy: EFISP passes in OFF, is denied in DENY, and is
suppressed with success in SIMULATE.

The only BLG writer is the selftest. It requires:

- mode OFF;
- READY/RO cache and committed map;
- block major 7;
- a backing path matching the CLI private temporary-file prefix;
- a regular backing file large enough for the committed map.

The selftest fsyncs and invalidates the block page cache between stages.
The backing check is based on the loop sysfs name plus a reopened regular file;
it is a defense against accidental real-device use, not an inode attestation
against a hostile root process racing the test.

## Compatibility

The KPM resolves kernel helpers through kallsyms_lookup_name. Exact function
availability and signatures must be checked against the target kernel build.
The intended baselines are ARM64 Android GKI-style Linux 6.6 and 6.12, whose
listed blkdev signatures match this source. Exact vendor kernels and the
KernelPatch fork still require device validation. Optional compat ioctl and
io_uring hooks log reduced coverage when their symbols do not exist. The
required blkdev_mmap symbol is fail-closed: a kernel which has migrated that
entry point will reject load rather than silently omit mmap coverage.
Co-loaded KPMs which hook the same blkdev symbols and mutate the same fargs
skip/return fields require an explicit ordering and compatibility audit.
