#!/bin/bash

# this builds Capstone for a wasm host using clang.
# It always includes all architectures.

# https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/libclang_rt.builtins-wasm32-wasi-12.0.tar.gz

set -e

ROOT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && cd ../.. && pwd )"
BUILDDIR="$ROOT_DIR/build-wasm"
WASI_LIBC="$BUILDDIR/wasi-libc"
SYSROOT="$WASI_LIBC/sysroot"

mkdir -p "$BUILDDIR"

if [ ! -d "$WASI_LIBC" ]; then
git clone https://github.com/CraneStation/wasi-libc.git --depth 1 "$WASI_LIBC"
fi

if [ ! -d "$SYSROOT" ]; then
(cd $WASI_LIBC; echo 'Building sysroot...'; mkdir -p build; make -j 6 > /dev/null)
fi

export CFLAGS=" --target=wasm32-unknown-wasi"
CFLAGS+=" '--sysroot=$SYSROOT'"
CFLAGS+=" -Wno-unused-result"
export LDFLAGS=""
LDFLAGS+=" -Wl,--export-dynamic"
LDFLAGS+=" -Wl,--export=malloc"
LDFLAGS+=" -Wl,--export=free"
LDFLAGS+=" -Wl,--import-memory"
LDFLAGS+=" -Wl,--no-entry"

  #-DCMAKE_AR:FILEPATH=$(which llvm-ar) \
  #-DCMAKE_RANLIB:FILEPATH= \
  #'-DCMAKE_C_ARCHIVE_CREATE:STRING=<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>' \

cmake \
  -DCMAKE_BUILD_TYPE:STRING=MinSizeRel \
  -DCAPSTONE_ARCHITECTURE_DEFAULT=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
  -DCMAKE_C_COMPILER:FILEPATH=$(which clang) \
  -DCMAKE_CXX_COMPILER:FILEPATH=$(which clang++) \
  -G Ninja \
  -B$BUILDDIR \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE:STRING=STATIC_LIBRARY \
  -DCMAKE_SYSTEM_NAME:STRING=Generic \
  -DCAPSTONE_BUILD_SHARED:BOOL=OFF \
  -DCAPSTONE_BUILD_STATIC:BOOL=OFF \
  -DCAPSTONE_BUILD_TESTS:BOOL=OFF \
  -DCAPSTONE_BUILD_CSTOOL:BOOL=OFF \
  -DCAPSTONE_BUILD_STATIC_RUNTIME:BOOL=OFF \
  -DCAPSTONE_BUILD_WEBASSEMBLY:BOOL=ON \
  -Wno-dev

cmake --build "$BUILDDIR" -j 6

echo Compressing...
brotli -f -k "$BUILDDIR/capstone.wasm"
SHASUM=$(sha256sum $BUILDDIR/capstone.wasm | grep -E -o '^[a-f0-9]{8}')
mv $BUILDDIR/capstone.wasm $BUILDDIR/$SHASUM.wasm
echo "Uncompressed output: $BUILDDIR/$SHASUM.wasm"
SHASUM=$(sha256sum $BUILDDIR/capstone.wasm.br | grep -E -o '^[a-f0-9]{8}')
mv $BUILDDIR/capstone.wasm.br $BUILDDIR/$SHASUM.wasm
echo "Compressed output: $BUILDDIR/$SHASUM.wasm"
