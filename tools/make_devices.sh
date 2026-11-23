#!/bin/bash
# Create the simulated relay devices DEV-0, DEV-1 and DEV-2 under devices/
# (git-ignored): <DEV>.seed is the device's secret root-key seed (mode 0600),
# <DEV>.pub its Keystone device public key. Existing devices are kept, so a
# device's key only changes if its files are deleted.
#
# Binding (demo/run_demo.py, controller --device-key): R0 -> DEV-0,
# R1 -> DEV-1, R2 -> DEV-2.
#
# Honest limit: under QEMU the seed is a plain file on the host. The guest
# cannot read it (the boot ROM erases it from SM-protected memory after use),
# but anyone with access to the host can.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTROM="$ROOT/external/keystone/bootrom"
OUT="$ROOT/devices"
TOOL="$OUT/.gen_device_key"

mkdir -p "$OUT"
chmod 700 "$OUT"
gcc -O2 -Wall -DED25519_NO_SEED -iquote "$BOOTROM" -o "$TOOL" \
    "$ROOT/tools/gen_device_key.c" "$BOOTROM"/ed25519/*.c "$BOOTROM"/sha3/*.c

for dev in "${@:-DEV-0 DEV-1 DEV-2}"; do
    for d in $dev; do
        if [ -f "$OUT/$d.seed" ] && [ -f "$OUT/$d.pub" ]; then
            echo "$d: exists, public key $(cat "$OUT/$d.pub")"
            continue
        fi
        rm -f "$OUT/$d.seed" "$OUT/$d.pub"
        "$TOOL" "$OUT/$d.seed" "$OUT/$d.pub"
        echo "$d: created, public key $(cat "$OUT/$d.pub")"
    done
done
