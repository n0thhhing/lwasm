--- Differential fuzz test for the optional C LEB128 backend.

local native = require("lwasm_native")

-- Load binary.lua with native discovery disabled while retaining direct access
-- to the already-loaded C module above.
local original_cpath = package.cpath
local original_native = package.loaded.lwasm_native
package.cpath = ""
package.loaded.lwasm_native = nil
package.loaded.binary = nil
local Binary = require("binary")
package.cpath = original_cpath
package.loaded.lwasm_native = original_native

assert(not Binary.native_enabled, "differential reference must use the pure-Lua backend")

local methods = {
	{ native = "read_u32_leb", lua = "read_u32LEB", max_bytes = 6 },
	{ native = "read_i32_leb", lua = "read_i32LEB", max_bytes = 6 },
	{ native = "read_u64_leb", lua = "read_u64LEB", max_bytes = 11 },
	{ native = "read_i64_leb", lua = "read_i64LEB", max_bytes = 11 },
}

local state = 0xA341316C
local function random_u32()
	state = state ~ ((state << 13) & 0xFFFFFFFF)
	state = state ~ (state >> 17)
	state = state ~ ((state << 5) & 0xFFFFFFFF)
	state = state & 0xFFFFFFFF
	return state
end

local function random_input(max_bytes)
	local length = (random_u32() % max_bytes) + 1
	local bytes = {}
	for i = 1, length do
		bytes[i] = string.char(random_u32() & 0xFF)
	end
	return table.concat(bytes)
end

local function execute(fn, reader)
	local ok, value = pcall(fn, reader)
	return ok, value, reader.cursor
end

local cases_per_method = tonumber(os.getenv("LWASM_NATIVE_FUZZ_CASES")) or 100000
for _, method in ipairs(methods) do
	for case = 1, cases_per_method do
		local input = random_input(method.max_bytes)
		local native_reader = { data = input, cursor = 1 }
		local lua_reader = Binary:new(input)
		local native_ok, native_value, native_cursor = execute(native[method.native], native_reader)
		local lua_ok, lua_value, lua_cursor = execute(Binary[method.lua], lua_reader)

		assert(native_ok == lua_ok, string.format("%s acceptance mismatch at fuzz case %d", method.native, case))
		if native_ok then
			assert(native_value == lua_value, string.format("%s value mismatch at fuzz case %d", method.native, case))
			assert(
				native_cursor == lua_cursor,
				string.format("%s cursor mismatch at fuzz case %d", method.native, case)
			)
		end
	end
	print(string.format("%s: %d differential cases passed", method.native, cases_per_method))
end

print(string.format("Native differential fuzz passed: %d cases", cases_per_method * #methods))
