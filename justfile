#!/usr/bin/env just --justfile

TARGET_SDK := "35"
ONDK_VERSION := "r29.5"

# https://developer.android.com/ndk/guides/other_build_systems#overview
HOST_TAG := (if os() == "macos" { "darwin" } else { os() }) + "-x86_64"

ONDK_PATH := env("ANDROID_HOME") / "ndk" / "ondk"
LLVM_BIN := ONDK_PATH / "toolchains/llvm/prebuilt" / HOST_TAG / "bin"

export CC := LLVM_BIN / ("aarch64-linux-android" + TARGET_SDK + "-clang")

package-module variant="release": (build variant "" "false")
    rm -rf target/module target/module-{{variant}}.zip
    cp -R module target/module
    cp target/aarch64-linux-android/{{variant}}/zynx target/module/bin
    cp target/aarch64-linux-android/{{variant}}/libzynx_bridge.so target/module/bin
    rm target/module/bin/.keep
    cd target/module && zip -r ../module-{{variant}}.zip .
    rm -rf target/module

build variant="debug" features="" default_features="true": setup-ondk
    {{ if variant == "release" { "PROFILE=release" } else { "" } }} \
    cargo build \
        -Z build-std \
        --target aarch64-linux-android \
        --config target.aarch64-linux-android.linker=\"{{CC}}\" \
        {{ if variant == "release" { "--release" } else { "" } }} \
        {{ if default_features == "true" { "" } else { "--no-default-features" } }} \
        {{ if features == "" { "" } else { "--features \"" + features + "\"" } }}

deploy variant="debug": (build variant)
    adb push target/aarch64-linux-android/{{variant}}/zynx /data/local/tmp/zynx
    adb shell "chmod +x /data/local/tmp/zynx"

run-emulator variant="debug": (deploy variant)
    adb shell "(su 0 killall zynx || true) && sleep 1"
    adb shell su 0 setenforce 0
    adb shell "RUST_LOG=debug RUST_LOG_STYLE=always RUST_BACKTRACE=1 su 0 /data/local/tmp/zynx --cfg-enable-zygisk --cfg-enable-debugger --cfg-enable-liteloader"

setup-ondk:
    @python3 scripts/setup-ondk.py --version {{ONDK_VERSION}}

clippy: setup-ondk
    cargo clippy --target aarch64-linux-android

clean:
    cargo clean
