# Examples

## Capstone compiled to WebAssembly, used from Lua

Build Capstone itself as a `wasm32-wasi` guest, then disassemble one Wasm
function by running that guest through lwasm:

```bash
make capstone
lua examples/capstone.lua build/function.wasm value-i32
```

The module can also be used directly:

```lua
local Capstone = require("examples.capstone_wasm")
local capstone = Capstone("build/capstone.wasm")
local instructions, result = capstone:disasm(raw_wasm_instructions, base_address)
```

Each instruction contains `address`, `size`, `id`, `bytes`, `mnemonic`, and
`op_str`. The second return value reports `complete`, `consumed`, `remaining`,
`next_address`, and an error when Capstone stops early. There is no native Lua
Capstone extension and no custom C wrapper: the unmodified Capstone sources are
compiled into `build/capstone.wasm`. Lua calls the exported `cs_open`,
`cs_disasm`, and `cs_free` APIs directly and reads `cs_insn` records from linear
memory through lwasm.

Capstone's Wasm backend does not cover every recent WebAssembly proposal.
`lwasm` remains the comprehensive decoder; this binding is useful for comparing
baseline instruction output or integrating existing Capstone-based tooling.
