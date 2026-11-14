#!/usr/bin/env bash
set -euo pipefail
# Build the Unicorn engine that runs the interpreted Apple StoreAgent guest.
#
# This follows ipatool's own iOS build (tools/build-ios.sh): Unicorn is built
# for arm64 with its JIT translation buffer, the upstream iOS patch makes that
# buffer executable without MAP_JIT, and the static library is linked into the
# app so purego can resolve the Unicorn API from the main executable.
#
# The guest architecture is ARM64. Current Apple StoreAgent builds are arm64e
# only, so the previous x86-64 StoreAgent can no longer produce a kbsync that
# Apple's store accepts.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT=${1:-"$ROOT/build/Native"}
PLATFORM=${2:-ios}
IPATOOL_COMMIT=b352566155a667d8aaeabaa7ecec4966080f92ab
IPATOOL_SHA256=fc13fe52232e96801f8994defd305d744a2f7c526c6dfb05d9b4c39cbe6867dc
CMAKE_BIN=$(command -v cmake || true)
if [[ -z "$CMAKE_BIN" && -x /opt/homebrew/bin/cmake ]]; then
  CMAKE_BIN=/opt/homebrew/bin/cmake
fi
if [[ -z "$CMAKE_BIN" && -x /usr/local/bin/cmake ]]; then
  CMAKE_BIN=/usr/local/bin/cmake
fi
if [[ -z "$CMAKE_BIN" ]]; then
  echo 'error: CMake is required to build Unicorn; install it (for example "brew install cmake") and rebuild.' >&2
  exit 1
fi
mkdir -p "$OUTPUT"
OUTPUT=$(cd "$OUTPUT" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The upstream iOS Unicorn patch ships with the pinned ipatool release.
curl -fL --retry 3 "https://github.com/majd/ipatool/archive/$IPATOOL_COMMIT.tar.gz" -o "$WORK/ipatool.tar.gz"
python3 - "$WORK/ipatool.tar.gz" "$IPATOOL_SHA256" <<'PY'
import sys,hashlib
with open(sys.argv[1], 'rb') as f: digest=hashlib.sha256(f.read()).hexdigest()
if digest != sys.argv[2]:
    raise SystemExit('ipatool source integrity mismatch')
PY
tar -xzf "$WORK/ipatool.tar.gz" -C "$WORK"
PATCH="$WORK/ipatool-$IPATOOL_COMMIT/tools/patches/unicorn-ios.patch"
if [[ ! -f "$PATCH" ]]; then
  echo 'error: upstream iOS Unicorn patch not found in the pinned ipatool release.' >&2
  exit 1
fi

curl -fL --retry 3 https://github.com/unicorn-engine/unicorn/archive/refs/tags/2.1.4.tar.gz -o "$WORK/unicorn.tar.gz"
python3 - "$WORK/unicorn.tar.gz" <<'PY'
import sys,hashlib
with open(sys.argv[1], 'rb') as f: digest=hashlib.sha256(f.read()).hexdigest()
if digest != 'ea8863f095a0136388694e5a6063afd9bb7650e30243dd6251af59c5ce5601f4':
    raise SystemExit('Unicorn source integrity mismatch')
PY
tar -xzf "$WORK/unicorn.tar.gz" -C "$WORK"
patch -d "$WORK/unicorn-2.1.4" -p1 < "$PATCH"

OPTIONS=(-DUNICORN_ARCH=aarch64 -DUNICORN_BUILD_TESTS=OFF -DUNICORN_INSTALL=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release)
if [[ "$PLATFORM" == ios || "$PLATFORM" == ios-simulator ]]; then
  if [[ "$PLATFORM" == ios-simulator ]]; then
    SDK_NAME=iphonesimulator
  else
    SDK_NAME=iphoneos
  fi
  SDK=$(xcrun --sdk "$SDK_NAME" --show-sdk-path)
  OPTIONS+=(-DCMAKE_SYSTEM_NAME=iOS "-DCMAKE_OSX_SYSROOT=$SDK" -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=16.4)
elif [[ "$PLATFORM" != host ]]; then
  echo 'Platform must be ios, ios-simulator, or host.' >&2
  exit 2
fi
"$CMAKE_BIN" -S "$WORK/unicorn-2.1.4" -B "$WORK/build" "${OPTIONS[@]}"
"$CMAKE_BIN" --build "$WORK/build" --parallel 4
cp "$WORK/build/libunicorn.a" "$OUTPUT/libunicorn.a"
if [[ -f "$WORK/build/libunicorn.so.2" ]]; then
  cp "$WORK/build"/libunicorn.so* "$OUTPUT/"
fi
cp -R "$WORK/unicorn-2.1.4/include" "$OUTPUT/"
# Retain complete modified corresponding source with every generated library.
tar -czf "$OUTPUT/unicorn-corresponding-source.tar.gz" -C "$WORK" unicorn-2.1.4
cp "$WORK/unicorn-2.1.4/COPYING" "$OUTPUT/UNICORN-COPYING"
echo 'Built arm64 Unicorn library with the upstream iOS JIT patch.'
