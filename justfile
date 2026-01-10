#!/usr/bin/env just --justfile

TARGET_SDK := "35"

# https://developer.android.com/ndk/guides/other_build_systems#overview
HOST_TAG := (if os() == "macos" { "darwin" } else { os() }) + "-x86_64"

export CC := env("ANDROID_NDK") / "toolchains/llvm/prebuilt" / HOST_TAG / "bin" / ("aarch64-linux-android" + TARGET_SDK + "-clang")

build-debug:
    cargo build --package zynx \
        --target aarch64-linux-android \
        --config target.aarch64-linux-android.linker=\"{{CC}}\"

run-emulator: build-debug
    adb push target/aarch64-linux-android/debug/zynx /data/local/tmp
    adb shell "chmod +x /data/local/tmp/zynx"
    adb shell "(su 0 killall zynx || true) && sleep 1"
    adb shell "RUST_LOG=debug RUST_LOG_STYLE=always RUST_BACKTRACE=1 su 0 /data/local/tmp/zynx"

clean:
    cargo clean
