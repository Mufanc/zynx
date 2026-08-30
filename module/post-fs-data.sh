set -eu

MODDIR=${0%/*}
ZYNX_BINARY="$MODDIR/bin/zynx"
BRIDGE_LIBRARY="$MODDIR/bin/libzynx_bridge.so"

chmod 744 "$ZYNX_BINARY"
MODDIR="$MODDIR" "$ZYNX_BINARY" daemon \
    --cfg-bridge-file "$BRIDGE_LIBRARY" \
    --cfg-enable-liteloader
