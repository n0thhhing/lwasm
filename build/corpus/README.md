# WebAssembly Test Corpus

This directory contains large, real-world WebAssembly modules used to stress-test
`lwasm` decoding and disassembly. These binaries are third-party artifacts and
remain subject to their respective projects' licenses.

## Corpus

| File | Project | Version | Bytes | SHA-256 |
|---|---|---:|---:|---|
| `duckdb.wasm` | [DuckDB-Wasm](https://github.com/duckdb/duckdb-wasm) | `1.33.1-dev57.0` | 41,325,187 | `ee5560145a3d3e0ffa6dce697be802c08842f139a594698eecc7c754f7ad5f05` |
| `ffmpeg.wasm` | [FFmpeg.wasm](https://github.com/ffmpegwasm/ffmpeg.wasm) | `0.12.10` | 32,232,419 | `9f57947a5bd530d8f00c5b3f2cb2a3492faa7e5d823315342d6a8656d0a6b7b7` |
| `onnx.wasm` | [ONNX Runtime Web](https://github.com/microsoft/onnxruntime) | `1.30.0` | 28,312,028 | `3ad23231b5bd6d9dda55a7f84606315e0bf35b6750c28ee993c987c54cacab0f` |
| `esbuild.wasm` | [esbuild](https://github.com/evanw/esbuild) | `0.28.2` | 13,978,850 | `b1831a5c0f6cf688034fb94d0419812f165ea316a3380d3fc00a151e562d2eaf` |
| `pyodide.wasm` | [Pyodide](https://github.com/pyodide/pyodide) | `314.0.7` | 9,598,218 | `cc36e3cab04fdfc9a63ff13eb52eae2b911bf46c025cc7b281f394bd3de1d5e6` |

## Download

```bash
mkdir -p build/corpus

curl -L -o build/corpus/duckdb.wasm \
  'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.33.1-dev57.0/dist/duckdb-mvp.wasm'
curl -L -o build/corpus/ffmpeg.wasm \
  'https://cdn.jsdelivr.net/npm/@ffmpeg/core@0.12.10/dist/umd/ffmpeg-core.wasm'
curl -L -o build/corpus/onnx.wasm \
  'https://cdn.jsdelivr.net/npm/onnxruntime-web@1.30.0/dist/ort-wasm-simd-threaded.jsep.wasm'
curl -L -o build/corpus/esbuild.wasm \
  'https://cdn.jsdelivr.net/npm/esbuild-wasm@0.28.2/esbuild.wasm'
curl -L -o build/corpus/pyodide.wasm \
  'https://cdn.jsdelivr.net/npm/pyodide@314.0.7/pyodide.asm.wasm'
```

Verify the downloads on macOS:

```bash
shasum -a 256 build/corpus/*.wasm
```

On Linux, use `sha256sum build/corpus/*.wasm` instead.

## Testing

Decode a module and print its section headers:

```bash
lua lwasm.lua headers build/corpus/duckdb.wasm
```

Compare the optional native backend with the pure-Lua fallback:

```bash
time lua lwasm.lua headers build/corpus/duckdb.wasm
time env LWASM_PURE_LUA=1 lua lwasm.lua headers build/corpus/duckdb.wasm
```

Disassemble a full module to a file instead of flooding the terminal:

```bash
lua lwasm.lua disasm build/corpus/esbuild.wasm > /tmp/esbuild.disasm
```

The current corpus contains 127,271 functions and approximately 47 million
instructions. All five modules decode and fully disassemble with the current
implementation.

## Notes

- These modules are intended primarily for decoder and disassembler testing.
  Instantiation generally requires substantial JavaScript/Emscripten imports.
- Do not commit regenerated binaries without reviewing their upstream licenses
  and repository size impact.
- Keep version numbers and checksums pinned so benchmark results remain
  reproducible.
