#!/bin/sh
set -eu

CAPSTONE_VERSION="${CAPSTONE_VERSION:-5.0.9}"
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEPS_DIR="$PROJECT_ROOT/build/deps"
SOURCE_DIR="$DEPS_DIR/capstone-$CAPSTONE_VERSION"
REPOSITORY="https://github.com/capstone-engine/capstone.git"
ZIG_LOCAL_CACHE_DIR="$PROJECT_ROOT/build/.zig-cache"
ZIG_GLOBAL_CACHE_DIR="$PROJECT_ROOT/build/.zig-global-cache"
export ZIG_LOCAL_CACHE_DIR ZIG_GLOBAL_CACHE_DIR

command -v zig >/dev/null 2>&1 || {
	echo "zig is required to compile Capstone to wasm32-wasi" >&2
	exit 1
}

mkdir -p "$DEPS_DIR" "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"
if [ ! -f "$SOURCE_DIR/arch/WASM/WASMModule.c" ]; then
	rm -rf "$SOURCE_DIR"
	echo "Fetching Capstone $CAPSTONE_VERSION (shallow sparse clone)..."
	git clone --quiet --depth 1 --filter=blob:none --no-checkout \
		--branch "$CAPSTONE_VERSION" --single-branch "$REPOSITORY" "$SOURCE_DIR"
	git -C "$SOURCE_DIR" sparse-checkout init --no-cone
	git -C "$SOURCE_DIR" sparse-checkout set \
		'/*' '!/*/' '/include/' '/arch/' '!/arch/*/' \
		'/arch/*/*Module.h' '/arch/WASM/'
	git -C "$SOURCE_DIR" checkout --quiet
fi

set -- \
	"$SOURCE_DIR/cs.c" \
	"$SOURCE_DIR/utils.c" \
	"$SOURCE_DIR/SStream.c" \
	"$SOURCE_DIR/MCInstrDesc.c" \
	"$SOURCE_DIR/MCRegisterInfo.c" \
	"$SOURCE_DIR/MCInst.c" \
	"$SOURCE_DIR/Mapping.c" \
	"$SOURCE_DIR"/arch/WASM/WASM*.c

zig cc -target wasm32-wasi -O3 \
	-DCAPSTONE_HAS_WASM -DCAPSTONE_USE_SYS_DYN_MEM \
	-I"$SOURCE_DIR/include" -I"$SOURCE_DIR" \
	"$@" -Wl,--no-entry -Wl,--export-memory -Wl,--strip-all \
	-Wl,--export=malloc -Wl,--export=free \
	-Wl,--export=cs_open -Wl,--export=cs_close \
	-Wl,--export=cs_disasm -Wl,--export=cs_free \
	-Wl,--export=cs_version \
	-o "$PROJECT_ROOT/build/capstone.wasm"

echo "Built build/capstone.wasm"
