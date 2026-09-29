local lwasm = require("lwasm")

local Capstone = {}
Capstone.__index = Capstone

local CS_ARCH_WASM = 13
local CS_MODE_LITTLE_ENDIAN = 0
local CS_ERR_OK = 0
-- Capstone cs_insn struct layout with auto-detected alignments and padding
local CS_Insn = lwasm.struct({
	{ "id", "u32" },
	{ "address", "i64" },
	{ "size", "u16" },
	{ "bytes", "bytes", 24, length_field = "size" },
	{ "mnemonic", "cstring", 32 },
	{ "op_str", "cstring", 160 },
	{ "detail", "ptr" },
})

function Capstone:new(path)
	local module = lwasm.open(path or "build/capstone.wasm")
	local instance = module:instantiate({ auto_stub = true })
	assert(instance.exports.memory, "Capstone guest did not export its memory")
	local exports = instance.exports
	local memory = instance.exports.memory
	local handle_pointer = exports.malloc(4)
	assert(handle_pointer ~= 0, "Capstone could not allocate a handle")
	local error_code = exports.cs_open(CS_ARCH_WASM, CS_MODE_LITTLE_ENDIAN, handle_pointer)
	assert(error_code == CS_ERR_OK, "cs_open failed with error " .. error_code)
	return setmetatable({
		module = module,
		instance = instance,
		memory = memory,
		handle = memory:load_u32(handle_pointer),
		handle_pointer = handle_pointer,
	}, self)
end

function Capstone:version()
	local exports = self.instance.exports
	local pointer = exports.malloc(8)
	assert(pointer ~= 0, "Capstone could not allocate version storage")
	exports.cs_version(pointer, pointer + 4)
	local major, minor = self.memory:load_u32(pointer), self.memory:load_u32(pointer + 4)
	exports.free(pointer)
	return major, minor
end

function Capstone:disasm(code, address)
	assert(type(code) == "string", "code must be a string")
	local exports = self.instance.exports
	local pointer = exports.malloc(math.max(#code, 1))
	assert(pointer ~= 0, "Capstone guest could not allocate input memory")
	self.memory:write_string(pointer, code)
	local result_pointer = exports.malloc(4)
	assert(result_pointer ~= 0, "Capstone could not allocate result storage")
	local count = exports.cs_disasm(self.handle, pointer, #code, address or 0, 0, result_pointer)
	local instructions_pointer = self.memory:load_u32(result_pointer)
	exports.free(result_pointer)
	exports.free(pointer)

	local instructions = CS_Insn:read_array(self.memory, instructions_pointer, count)
	local consumed = 0
	for _, insn in ipairs(instructions) do
		consumed = consumed + insn.size
	end
	if instructions_pointer ~= 0 then
		exports.cs_free(instructions_pointer, count)
	end

	return instructions,
		{
			complete = consumed == #code,
			consumed = consumed,
			remaining = #code - consumed,
			next_address = (address or 0) + consumed,
			error = consumed == #code and nil or "unsupported or invalid instruction",
		}
end

return setmetatable(Capstone, {
	__call = function(class, ...)
		return class:new(...)
	end,
})
