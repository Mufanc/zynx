#!/usr/bin/env python3
"""
ONDK (Oxidized NDK) setup script for zynx project.

This script handles:
1. Downloading ONDK from GitHub releases
2. Extracting and installing to $ANDROID_HOME/ndk/ondk
3. Verifying ONDK version

Reference: https://github.com/topjohnwu/Magisk/blob/master/build.py
"""

import argparse
import os
import platform
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import NoReturn


def error(msg: str) -> NoReturn:
    print(f"\033[31mError: {msg}\033[0m", file=sys.stderr)
    sys.exit(1)


def info(msg: str) -> None:
    print(f"\033[32m{msg}\033[0m", file=sys.stderr)


def get_platform() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    elif system == "linux":
        return "linux"
    elif system == "windows" or "mingw" in system or "cygwin" in system:
        return "windows"
    else:
        error(f"Unsupported platform: {system}")


def get_android_home() -> Path:
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not android_home:
        error(
            "ANDROID_HOME environment variable not set.\n"
            "Please set it to your Android SDK location, e.g.:\n"
            "  export ANDROID_HOME=$HOME/Library/Android/sdk"
        )
    return Path(android_home)


def get_ondk_path(android_home: Path) -> Path:
    return android_home / "ndk" / "ondk"


def download_ondk(version: str, ondk_path: Path) -> None:
    plat = get_platform()
    url = f"https://github.com/topjohnwu/ondk/releases/download/{version}/ondk-{version}-{plat}.tar.xz"
    archive_name = f"ondk-{version}-{plat}.tar.xz"

    info(f"Downloading {archive_name}...")
    info(f"URL: {url}")

    # Ensure parent directory exists
    ondk_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with urllib.request.urlopen(url) as response:
            with tarfile.open(mode="r|xz", fileobj=response) as tar:
                extract_dir = ondk_path.parent
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(extract_dir, filter="tar")
                else:
                    tar.extractall(extract_dir)

        # Rename extracted folder to 'ondk'
        extracted_folder = ondk_path.parent / f"ondk-{version}"
        if extracted_folder.exists():
            if ondk_path.exists():
                import shutil
                shutil.rmtree(ondk_path)
            extracted_folder.rename(ondk_path)

        info(f"ONDK {version} installed to {ondk_path}")

    except urllib.error.HTTPError as e:
        error(f"Failed to download ONDK: HTTP {e.code}\nURL: {url}")
    except urllib.error.URLError as e:
        error(f"Failed to download ONDK: {e.reason}\nURL: {url}")
    except Exception as e:
        error(f"Failed to download/extract ONDK: {e}")


def verify_ondk(ondk_path: Path, expected_version: str) -> bool:
    version_file = ondk_path / "ONDK_VERSION"
    if not version_file.exists():
        return False

    actual_version = version_file.read_text().strip()
    if actual_version != expected_version:
        error(
            f"ONDK version mismatch: expected {expected_version}, found {actual_version}.\n"
            f"Please remove {ondk_path} and run again."
        )
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Setup ONDK (Oxidized NDK) for zynx project"
    )
    parser.add_argument(
        "--version",
        required=True,
        help="ONDK version to install (e.g., r29.5)"
    )

    args = parser.parse_args()

    android_home = get_android_home()
    ondk_path = get_ondk_path(android_home)

    # Install if needed, then verify
    if not verify_ondk(ondk_path, args.version):
        download_ondk(args.version, ondk_path)
        if not verify_ondk(ondk_path, args.version):
            error("ONDK installation verification failed")

    # Output ONDK path for caller
    print(ondk_path)


if __name__ == "__main__":
    main()
