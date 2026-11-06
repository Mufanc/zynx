set -eu

export MODDIR=${0%/*}

"$MODDIR/bin/zynx" --bridge "$MODDIR/bin/libzynx_bridge.so" \
    daemon --wait-bpfloader \
    --features liteloader

"$MODDIR/bin/bpfloader-wrapper" mount
