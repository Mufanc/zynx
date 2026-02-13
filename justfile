#!/usr/bin/env just --justfile

TARGET_SDK := "35"
ONDK_VERSION := "r29.5"

# https://developer.android.com/ndk/guides/other_build_systems#overview
HOST_TAG := (if os() == "macos" { "darwin" } else { os() }) + "-x86_64"

ONDK_PATH := env("ANDROID_HOME") / "ndk" / "ondk"
LLVM_BIN := ONDK_PATH / "toolchains/llvm/prebuilt" / HOST_TAG / "bin"

export CC := LLVM_BIN / ("aarch64-linux-android" + TARGET_SDK + "-clang")

build-debug features="": setup-ondk
    cargo build \
        -Z build-std \
        --target aarch64-linux-android \
        --config target.aarch64-linux-android.linker=\"{{CC}}\" \
        {{ if features == "no-zygisk" { "--no-default-features" } else { "" } }}

build-release features="": setup-ondk
    PROFILE=release cargo build \
        -Z build-std \
        --target aarch64-linux-android \
        --config target.aarch64-linux-android.linker=\"{{CC}}\" \
        --release \
        {{ if features == "no-zygisk" { "--no-default-features" } else { "" } }}

run-emulator: build-debug
    adb push target/aarch64-linux-android/debug/zynx /data/local/tmp/zynx
    adb shell "chmod +x /data/local/tmp/zynx"
    adb shell "(su 0 killall zynx || true) && sleep 1"
    adb shell "RUST_LOG=debug RUST_LOG_STYLE=always RUST_BACKTRACE=1 su 0 /data/local/tmp/zynx --cfg-enable-zygisk"

setup-ondk:
    @python3 scripts/setup-ondk.py --version {{ONDK_VERSION}}

clippy: setup-ondk
    cargo clippy --target aarch64-linux-android

clean:
    cargo clean
