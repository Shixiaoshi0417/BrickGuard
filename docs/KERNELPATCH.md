# KernelPatch Integration

BrickGuard installs hooks on hot block-device paths. Runtime removal is not
safe with an unmodified KernelPatch loader: current upstream unload code frees
the KPM even when its exit callback returns an error, and the final chain-hook
removal has no in-flight callback grace period.

BrickGuard therefore uses a pinned-module contract:

1. apply `kernelpatch/0001-kpm-honor-exit-veto.patch` to the exact KernelPatch
   tree used for the target boot image;
2. rebuild/repatch the boot image with that KernelPatch tree;
3. build and load BrickGuard normally;
4. reboot to remove or replace BrickGuard.

The patch exports `kpm_exit_veto_supported=1`. BrickGuard has an undefined
reference to that symbol, so an unpatched loader rejects the KPM before init
and before any block hook is installed.

At runtime BrickGuard's exit callback returns `-EBUSY` without changing any
state. The patched loader checks that result before deleting the module or
freeing executable memory. This also avoids the unsafe hot removal path in the
current hook implementation.

Do not remove this handshake merely to make the KPM load. A stock loader can
turn a failed unload into dangling proc callbacks and block hooks pointing at
freed executable memory.
