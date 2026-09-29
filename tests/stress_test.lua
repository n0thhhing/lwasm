--- Deterministic stress and endurance test for lwasm.
--- Run with `make stress` or increase the load with `make stress STRESS_SCALE=10`.

local lwasm = require("lwasm")
local Binary = require("binary")

local scale = tonumber(os.getenv("LWASM_STRESS_SCALE")) or tonumber(arg[1]) or 1
assert(scale > 0 and scale == math.floor(scale), "stress scale must be a positive integer")

print(string.format("Backend: %s", lwasm.backend))

local function read_file(path)
	local file = assert(io.open(path, "rb"))
	local data = assert(file:read("*a"))
	file:close()
	return data
end

local function timed(name, operations, fn)
	collectgarbage("collect")
	local memory_before = collectgarbage("count")
	local started = os.clock()
	fn()
	local elapsed = os.clock() - started
	collectgarbage("collect")
	local memory_after = collectgarbage("count")
	local rate = elapsed > 0 and operations / elapsed or math.huge
	print(
		string.format(
			"%-18s %10d ops  %8.3fs  %12.0f ops/s  memory %+.1f KiB",
			name,
			operations,
			elapsed,
			rate,
			memory_after - memory_before
		)
	)
end

local random_state = 0x6D2B79F5
local function random_u32()
	random_state = random_state ~ ((random_state << 13) & 0xFFFFFFFF)
	random_state = random_state ~ (random_state >> 17)
	random_state = random_state ~ ((random_state << 5) & 0xFFFFFFFF)
	random_state = random_state & 0xFFFFFFFF
	return random_state
end

local function encode_u32_leb(value)
	local output = {}
	repeat
		local byte = value & 0x7F
		value = value >> 7
		if value ~= 0 then
			byte = byte | 0x80
		end
		output[#output + 1] = string.char(byte)
	until value == 0
	return table.concat(output)
end

local binary_iterations = 1000000 * scale
timed("LEB128 round-trip", binary_iterations, function()
	for _ = 1, binary_iterations do
		local expected = random_u32()
		local reader = Binary:new(encode_u32_leb(expected))
		assert(reader:read_u32LEB() == expected, "u32 LEB128 round-trip mismatch")
		assert(reader:eof(), "u32 LEB128 reader did not consume its input")
	end
end)

local malformed_iterations = 100000 * scale
local malformed = string.char(0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
timed("Malformed rejection", malformed_iterations, function()
	for _ = 1, malformed_iterations do
		local ok = pcall(Binary.read_u32LEB, Binary:new(malformed))
		assert(not ok, "overlong u32 LEB128 encoding was accepted")
	end
end)

local sqlite_bytes = read_file("build/sqlite3.wasm")
local decode_iterations = 200 * scale
timed("Module decode", decode_iterations, function()
	for _ = 1, decode_iterations do
		local mod = lwasm.decode(sqlite_bytes)
		local code = assert(mod:get_section("code_section"), "sqlite3 code section missing")
		assert(#code.code == 2668, "sqlite3 function count changed during repeated decode")
	end
end)

local function_bytes = read_file("build/function.wasm")
local function_mod = lwasm.decode(function_bytes)
local function_code = assert(function_mod:get_section("code_section"), "function code section missing")
local disasm_iterations = 1000 * scale
local functions_per_pass = #function_code.code
timed("Function disasm", disasm_iterations * functions_per_pass, function()
	for _ = 1, disasm_iterations do
		local instruction_count = 0
		for _, entry in ipairs(function_code.code) do
			instruction_count = instruction_count + #lwasm.disasm_function(entry)
		end
		assert(instruction_count > functions_per_pass, "unexpectedly empty function disassembly")
	end
end)

local instance = lwasm.instantiate(function_mod)
local first = assert(instance.exports["param-first-i32"], "runtime fixture export missing")
local second = assert(instance.exports["param-second-i32"], "runtime fixture export missing")
local runtime_iterations = 1000000 * scale
timed("Runtime calls", runtime_iterations * 2, function()
	for i = 1, runtime_iterations do
		local a = i & 0x7FFFFFFF
		local b = (i * 31) & 0x7FFFFFFF
		assert(first(a, b) == a, "param-first-i32 returned an incorrect value")
		assert(second(a, b) == b, "param-second-i32 returned an incorrect value")
	end
end)

print(string.format("\nStress test passed (scale=%d).", scale))
