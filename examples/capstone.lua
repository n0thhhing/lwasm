local lwasm = require("lwasm")
local Capstone = require("examples.capstone_wasm")

local path = arg[1] or "build/function.wasm"
local identifier = tonumber(arg[2]) or arg[2] or "value-i32"
local func = assert(lwasm(path):get_function(identifier), "function not found: " .. tostring(identifier))
local code = assert(func:bytes(), "imported functions do not have bytecode")

local capstone = Capstone()
local major, minor = capstone:version()
print(string.format("Capstone %d.%d, function %s (%d bytes)", major, minor, func.name or func.index, #code))

local instructions, result = capstone:disasm(code, func.entry.code_start or 0)
for _, instruction in ipairs(instructions) do
	print(string.format("%08x  %-12s %s", instruction.address, instruction.mnemonic, instruction.op_str))
end

if not result.complete then
	io.stderr:write(string.format("Capstone stopped after %d bytes: %s\n", result.consumed, result.error))
end
