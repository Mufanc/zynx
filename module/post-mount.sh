set -eu

export MODDIR=${0%/*}

"$MODDIR/bin/zynx" daemon --wait-bpfloader \
    --cfg-bridge-file "$MODDIR/bin/libzynx_bridge.so" \
    --cfg-enable-liteloader

"$MODDIR/bin/bpfloader-wrapper" mount
