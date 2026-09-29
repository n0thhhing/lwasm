# lwasm

A fast, comprehensive WebAssembly 2.0 binary decoder, disassembler, decompiler, runtime interpreter, and inspection toolkit written in pure Lua.

Conforms to the **W3C WebAssembly Core 2.0 Specification** (including Typed Function References, Garbage Collection, Exception Handling, Relaxed SIMD, Multi-Memory, and Memory64).

---

## Features

- **Pure Lua**: Runs on standard Lua 5.4+ with zero external dependencies.
- **Optional Native Acceleration**: Builds a small C backend when Lua development headers are available, with automatic pure-Lua fallback.
- **Blazing Fast**: Parses large real-world WebAssembly binaries like `sqlite3.wasm` (869 KiB, 2,668 functions) in **~14 ms**.
- **Wasm 2.0 Runtime Interpreter**:
  - **Full 100% Opcode Coverage**: Interprets all 561 opcodes defined across the WebAssembly 2.0 specification.
  - **Precomputed Jump PC Mapping**: Fast dispatch with precalculated forward/backward targets, skip spans, and exception landing sites.
  - **Exception Handling**: First-class support for `try_table`, `throw`, `throw_ref`, `catch`, `catch_ref`, `catch_all`, and `catch_all_ref`.
  - **Typed Function References**: Indirect and typed calls with `call_ref`, `return_call_ref`, `ref.func`, `ref.null`, `ref.is_null`, `br_on_null`, and `br_on_non_null`.
  - **GC & Polymorphic Types**: Type testing and casting (`ref.test`, `ref.cast`, `br_on_cast`, `br_on_cast_fail`, `ref.i31`).
  - **128-bit SIMD & Relaxed SIMD**: Full vector arithmetic, lane splats/extractions, comparisons, bitmasks, shuffles, swizzles, and relaxed instructions via packed 16-byte vector representations.
  - **Single-Threaded Atomics**: Complete memory atomic load/store, read-modify-write (`rmw.add`, `rmw.sub`, `rmw.and`, `rmw.or`, `rmw.xor`, `rmw.xchg`, `rmw.cmpxchg`), `atomic.notify`, and `memory.atomic.wait32/64`.
  - **Bulk Memory & Tables**: `memory.fill`, `memory.copy`, `memory.init`, `data.drop`, `table.size`, `table.grow`, `table.fill`, `table.copy`, `table.init`, `elem.drop`.
  - **Tail Calls**: Optimized tail calls via `return_call` and `return_call_indirect`.
- **WAT Decompilation**: Convert compiled `.wasm` modules back into readable S-expression WebAssembly Text format (`to_wat`).
- **Objdump Disassembly**: Generate hex-annotated disassembly listings with PC offsets and instruction bytes.
- **Inspection Dumper**: Detailed section breakdowns, custom section inspection (including `"name"` debug symbol extraction), and hex/ASCII segment dumps.
- **Unified & Object-Oriented**: Simple entry points (`require("lwasm")`) and fluent methods on `Module` objects (`mod:run()`, `mod:instantiate()`, `mod:to_wat()`, `mod:dump()`, `mod:disassemble()`).

---

## Project Structure

```
lwasm/
├── bin/
│   └── lwasm              # Standalone executable CLI utility (chmod +x)
├── lwasm.lua              # Unified toolkit module & CLI launcher (`require("lwasm")`)
├── init.lua               # Standard module entry forwarder (`return require("lwasm")`)
├── runtime.lua            # Pure Lua WebAssembly 2.0 interpreter & execution engine
├── decoder.lua            # Wasm binary section & module decoder
├── disassembler.lua       # Bytecode disassembler, objdump formatter, and WAT generator
├── dumper.lua             # Comprehensive binary inspection and section dumper
├── opcodes.lua            # Single source of truth for opcodes, prefixes, types & metadata
├── binary.lua             # Low-level binary reader with LEB128 & IEEE-754 support
├── utils.lua              # Helper utilities (file IO, pretty print, table merge)
├── Makefile               # Build, test, format, and dump workflows
├── tests/
│   ├── tests.lua          # Lightweight unit test framework
│   ├── run_all.lua        # Unified test runner
│   ├── runtime_test.lua   # Runtime interpreter unit & integration test suite (173 tests)
│   ├── decode_test.lua    # Section decoder unit tests (types, globals, data, sqlite3)
│   ├── disasm_test.lua    # Instruction disassembly and WAT decompilation tests
│   ├── sqlite3_compare_test.lua # Full regression suite vs reference WABT (wasm-objdump)
│   └── spec_test.lua      # Comprehensive W3C spec runner (292 suites, Memory64, SIMD, Proposals, Round-Trip)
├── spec/                  # Official WebAssembly spec testsuite & active proposals (.wast files)
├── suite/                 # WebAssembly Text (.wat) test fixtures
└── build/                 # Compiled WebAssembly (.wasm) fixtures
    └── corpus/            # Large third-party stress fixtures and provenance
```

---

## Quickstart

### Requirements

- Lua 5.4 or newer
- [WABT](https://github.com/WebAssembly/wabt) for building fixtures and running tests
- A C compiler and Lua development headers only when building the optional native backend

Clone the repository with its WebAssembly specification tests, then build the
local fixtures:

```bash
git clone --recurse-submodules <repository-url>
cd lwasm
make build
```

Run the CLI directly with `bin/lwasm`, or add the repository's `bin` directory
to your `PATH`. No installation step is required for the pure-Lua library.

### 1. Decoding a WebAssembly Module

```lua
local lwasm = require("lwasm")

-- Decode directly from disk
local mod = lwasm("build/global.wasm")
-- or: local mod = lwasm.decode_file("build/global.wasm")
-- or: local mod = lwasm.decode(raw_bytes)

print(string.format("Version: %d, Sections: %d", mod.version, #mod.sections.section_list))

-- Query sections
local type_sec = mod:get_section("type_section")
local code_sec = mod:get_section("code_section")
local exports  = mod:get_exports()

for name, exp in pairs(exports) do
    print("Export:", name, "Kind:", exp.desc, "Index:", exp.index)
end
```

### 2. Running WebAssembly Code (Runtime)

Execute WebAssembly binaries directly from Lua without native dependencies:

```lua
local lwasm = require("lwasm")

-- Run an exported function directly:
local result = lwasm.run("build/function.wasm", "param-first-i32", 42, 99)
print("Result:", result) -- 42

-- Or instantiate and invoke multiple exports:
local mod = lwasm.decode_file("build/function.wasm")
local instance = mod:instantiate()

print("value-i32:", instance.exports["value-i32"]()) -- 77

-- Access linear memory, tables, and globals:
-- instance.memory:load(0, 4)
-- instance.globals[1]:get()
```

### 3. Decompiling to WAT (WebAssembly Text)

```lua
local lwasm = require("lwasm")

-- Decompile entire module to WAT format
local wat = lwasm.to_wat("build/global.wasm")
print(wat)

-- Or use fluent object method
local mod = lwasm("build/global.wasm")
print(mod:to_wat())
```

### 4. Disassembling Bytecode

```lua
local lwasm = require("lwasm")

-- Disassemble raw instruction bytes
local code = "\x20\x00\x20\x01\x6a\x0b" -- local.get 0, local.get 1, i32.add, end
local insns = lwasm.disasm(code)

for _, insn in ipairs(insns) do
    print(insn:to_dump_line())
end
```

Output:
```
 000000: 20 00                  | local.get 0
 000002: 20 01                  | local.get 1
 000004: 6a                     | i32.add
 000005: 0b                     | end
```

### 5. Comprehensive Binary Inspection

```lua
local lwasm = require("lwasm")

-- Generate a complete inspection dump
local dump_text = lwasm.dump("build/global.wasm")
print(dump_text)

-- Options: { headers_only = true, disasm_only = true, no_disasm = true, raw_data = true }
local headers_only = lwasm.dump("build/global.wasm", { headers_only = true })
```

### 6. Analysis and Automation API

```lua
local lwasm = require("lwasm")

-- Structured, non-throwing decode errors
local mod, err = lwasm.try_decode("module.wasm")
if not mod then
  print(err.kind, err.offset, err.message)
end

-- Structural, index, and instruction validation
local validation = lwasm.validate("module.wasm", {
  lazy_code = true,
  lazy_data = true,
})
assert(validation.valid, validation.error and validation.error.message)

mod = validation.module
local stats = mod:stats()
print(stats.functions, stats.instructions, stats.opcode_counts["call"] or 0)

-- Lazy instruction traversal
for instruction, function_index in mod:instructions() do
  print(function_index, instruction.pc, instruction.opcode)
end

-- Function lookup accepts an export/debug name or zero-based Wasm index
local func = mod:get_function("malloc")
if func then print(func:to_wat()) end
```

Large modules can defer function-body and data-segment copies:

```lua
local mod = lwasm.open("large.wasm")
local first_data, metadata = mod:get_data_segment(0)
```

Backend selection, module comparison, benchmarking, and import stubbing are
available programmatically:

```lua
print(table.concat(lwasm.available_backends(), ", "))
lwasm.set_backend("native") -- also accepts "lua" or "auto"

local diff = lwasm.compare("old.wasm", "new.wasm")
local timings = lwasm.benchmark("module.wasm", {
  iterations = 10,
  operations = { "decode", "disassemble" },
})

local imports = mod:required_imports()
local instance = mod:instantiate(lwasm.stub_imports(mod))
-- Equivalent shorthand: mod:instantiate({ auto_stub = true })
```

---

## CLI Usage

The `lwasm` CLI utility (`bin/lwasm` or `lua lwasm.lua`) provides a complete set of subcommands:

```bash
# Execute exported function from module
lwasm run module.wasm [func_name] [args...]
# Example:
lwasm run build/function.wasm param-first-i32 42 99  # prints 42

# Decompile module to WebAssembly Text (WAT)
lwasm wat module.wasm

# Full binary inspection dump
lwasm dump module.wasm

# Disassemble functions only
lwasm disasm module.wasm

# Section headers summary table only
lwasm headers module.wasm

# Directly invoke dumper with flags
lua dumper.lua module.wasm -h   # headers only
lua dumper.lua module.wasm -d   # disassembly only
lua dumper.lua module.wasm -r   # full hex data dumps
```

---

## High-level API

Modules expose first-class `types()`, `functions()`, `memories()`, `tables()`,
`globals()`, and `tags()` views, plus zero-based `get_*()` lookups. Imported
and defined resources share the WebAssembly index space.

Analysis includes `call_graph()`, per-function `cfg()`, `callers()`,
`callees()`, `signature()`, `locals()`, `references()`, instruction caching,
byte/instruction search, exports, imports, names, and custom sections. Modules
also support validation, encoding, writing, rewriting, stripping, and
instrumentation. Top-level helpers include `from_bytes()`, `detect()`,
`compile_wat()`, `backends()`, and `rewrite()`.

Runtime instances provide structured `invoke()`, instruction tracing,
breakpoints, fuel/time limits, and `snapshot()`/`restore()`:

```lua
local lwasm = require("lwasm")
local module = lwasm("program.wasm")
local memory = module:get_memory(0)
local graph = module:call_graph()

local instance = module:instantiate({ fuel = 100000, timeout = 1.0 })
local events = instance:trace()
local result, trap = instance:invoke("main")
instance:stop_trace()
```

## Development

Run development tasks via `make`:

```bash
# Build all .wat suites in suite/ into build/*.wasm
make build

# Run all test suites
make test

# Run deterministic decoder/disassembler/runtime stress tests
make stress

# Increase every stress workload by 10x
make stress STRESS_SCALE=10

# Build and verify the optional C accelerator
make test-native

# Compile Capstone into WebAssembly and run it through lwasm
make test-capstone

# Force the portable Lua backend even when the native module is present
LWASM_PURE_LUA=1 make stress

# Format Lua code with stylua
make format

# Dump sample module
make dump
```

The library loads `lwasm_native` automatically when it is available. Inspect
`lwasm.backend` (`"native"` or `"lua"`) to see which backend is active.

### Test Coverage

Large real-world fixtures, pinned download URLs, and checksums are documented in
[`build/corpus/README.md`](build/corpus/README.md).

`lwasm` is thoroughly verified against:
- **WebAssembly 2.0 Runtime Verification (173 tests)**: Numerics (i32, i64, f32, f64), Saturating Truncations, Locals/Globals, Memory Load/Store, Control Flow, Direct & Indirect Calls, Multiple Returns, Tail Calls, Bulk Memory & Tables, Typed Function References, Conditional Reference Branches, Exception Handling (`try_table`/`throw`/`catch`), 128-bit SIMD, and Atomics.
- **Comprehensive SQLite3 Binary Verification**: Byte-for-byte comparison of 364,625 instructions and all section structures against reference WABT `wasm-objdump`.
- **W3C WebAssembly Specification (292 suites)**:
  - Core execution, control flow, and numerics
  - Memory64 and 64-bit address space (23 suites)
  - Typed references and tail calls (8 suites)
  - Multi-Memory and Multi-Table (4 suites)
  - 128-bit SIMD, Extended SIMD, and Relaxed SIMD (49 suites)
  - Active proposals: Threads (`atomic`, `memory`, `exports`, `imports`), Wide Arithmetic, Custom Page Sizes, Compact Imports
  - WAT round-trip re-assembly verification (`wat2wasm`) with zero failures
  - Full corpus mass verification (>2,000 modules, >40,000 instructions)

---

## License

Released under the [MIT License](LICENSE). The optional third-party test corpus
remains subject to its upstream projects' licenses.
