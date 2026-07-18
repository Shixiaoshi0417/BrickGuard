#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

CLI="/data/local/tmp/brickguard"
if [ "$#" -gt 0 ]; then
    CLI="$1"
fi

if [ "$(id -u)" != 0 ]; then
    echo "error: run as root" >&2
    exit 1
fi
if [ ! -x "$CLI" ]; then
    echo "error: CLI not executable: $CLI" >&2
    exit 1
fi

"$CLI" status
"$CLI" pack verify
"$CLI" verify
"$CLI" selftest

echo "BrickGuard loop-only smoke test passed."
