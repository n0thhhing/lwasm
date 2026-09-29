.PHONY: all build native format lint test test-native test-capstone stress dump clean

WASM_SPEC_NAME=global
STRESS_SCALE?=1
LUA_VERSION:=$(shell lua -e 'io.write((_VERSION:gsub("Lua ", "")))')
LUA_INCDIR?=$(firstword $(wildcard /opt/homebrew/include/lua$(LUA_VERSION) /usr/local/include/lua$(LUA_VERSION) /usr/include/lua$(LUA_VERSION) /usr/include/lua))
UNAME_S:=$(shell uname -s)
NATIVE_LDFLAGS:=$(if $(filter Darwin,$(UNAME_S)),-bundle -undefined dynamic_lookup,-shared)

all: build test

build:
	@mkdir -p build
	for f in suite/*.wat; do wat2wasm "$$f" -o "build/$$(basename "$$f" .wat).wasm"; done

native:
	@test -n "$(LUA_INCDIR)" || (echo "Lua headers not found; set LUA_INCDIR=/path/to/lua/include" >&2; exit 1)
	$(CC) -O3 -DNDEBUG -fPIC -Wall -Wextra -I"$(LUA_INCDIR)" $(NATIVE_LDFLAGS) native/lwasm_native.c -o lwasm_native.so

capstone: build/capstone.wasm

build/capstone.wasm: scripts/build_capstone_wasm.sh
	./scripts/build_capstone_wasm.sh

format:
	find . -name '*.bak' -type f -delete
	-stylua **/*.lua *.lua

lint:
	-luacheck *.lua **/*.lua

test: build
	lua tests/run_all.lua

test-native: native
	lua tests/run_all.lua
	lua tests/native_compare_test.lua
	LWASM_PURE_LUA=1 lua tests/run_all.lua

test-capstone: capstone
	lua tests/capstone_wasm_test.lua

stress:
	LWASM_STRESS_SCALE=$(STRESS_SCALE) lua tests/stress_test.lua

dump:
	lua dumper.lua "build/$(WASM_SPEC_NAME).wasm"

clean:
	rm -f lwasm_native.so build/capstone.wasm
	for f in suite/*.wat; do rm -f "build/$$(basename "$$f" .wat).wasm"; done
	rm -rf build/.zig-cache build/.zig-global-cache build/deps
