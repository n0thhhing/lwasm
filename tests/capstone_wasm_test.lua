local lwasm = require("lwasm")
local Capstone = require("examples.capstone_wasm")

local capstone = Capstone()
local major, minor = capstone:version()
assert(major == 5 and minor == 0, string.format("unexpected Capstone version %d.%d", major, minor))

local func = assert(lwasm("build/function.wasm"):get_function("value-i32"))
local code = assert(func:bytes())
local instructions, result = capstone:disasm(code, func.entry.code_start)
assert(#instructions > 0)
assert(instructions[1].mnemonic ~= "")
assert(result.complete, string.format("decoded only %d/%d bytes", result.consumed, #code))
assert(result.next_address == func.entry.code_start + #code)

print(string.format("Capstone-in-Wasm passed: %d instructions, %d/%d bytes", #instructions, result.consumed, #code))
