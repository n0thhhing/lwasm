--- WebAssembly Bytecode Disassembler
--- Decodes binary Wasm instruction bytecode into structured instruction representations,
--- formatted assembly (WAT), and hex-annotated disassembly dumps.
---@diagnostic disable: undefined-global

local WASM_disassembler = {}

local Binary = require("binary")
local opcodes = require("opcodes")

--- Metatable for instruction objects
local Instruction = {}
Instruction.__index = Instruction

--- Format instruction as a human-readable assembly string (WAT style).
--- @return string
function Instruction:to_string()
	if self.operands ~= nil and tostring(self.operands) ~= "" then
		return self.opcode .. " " .. tostring(self.operands)
	end
	return self.opcode
end

--- Format instruction as an objdump-style line: `<offset>: <hex bytes> | <assembly>`.
--- @return string
function Instruction:to_dump_line()
	local hex_parts = {}
	if self.raw_bytes then
		for i = 1, #self.raw_bytes do
			hex_parts[#hex_parts + 1] = string.format("%02x", string.byte(self.raw_bytes, i))
		end
	end
	local hex_str = table.concat(hex_parts, " ")
	return string.format(" %06x: %-22s | %s", self.pc or 0, hex_str, self:to_string())
end

--- Decode a heap type immediate.
--- @param bin table
--- @return string
local function read_heap_type(bin)
	local b = bin:peek_byte()
	if opcodes.HEAP_TYPE_NAMES[b] then
		bin:read_byte()
		return opcodes.HEAP_TYPE_NAMES[b]
	else
		local type_idx = bin:read_i64LEB()
		return tostring(type_idx)
	end
end

--- Decode a reference type (e.g. funcref = 0x70, externref = 0x6F, or (ref null? ht)).
--- @param bin table
--- @return string
local function read_ref_type(bin)
	local b = bin:peek_byte()
	if b == 0x63 then
		bin:read_byte()
		local ht = read_heap_type(bin)
		return string.format("(ref null %s)", ht)
	elseif b == 0x64 then
		bin:read_byte()
		local ht = read_heap_type(bin)
		return string.format("(ref %s)", ht)
	elseif opcodes.HEAP_TYPE_NAMES[b] then
		bin:read_byte()
		if b == opcodes.REF_FUNC then
			return "funcref"
		end
		if b == opcodes.REF_EXTERN then
			return "externref"
		end
		return opcodes.HEAP_TYPE_NAMES[b]
	else
		return read_heap_type(bin)
	end
end

--- Decode a block type immediate (used in block, loop, if).
--- @param bin table
--- @return string|integer blocktype, string display_str
local function read_block_type(bin)
	local byte = bin:peek_byte()
	if byte == 0x40 then
		bin:read_byte()
		return "empty", ""
	elseif byte == 0x7F then
		bin:read_byte()
		return "i32", "(result i32)"
	elseif byte == 0x7E then
		bin:read_byte()
		return "i64", "(result i64)"
	elseif byte == 0x7D then
		bin:read_byte()
		return "f32", "(result f32)"
	elseif byte == 0x7C then
		bin:read_byte()
		return "f64", "(result f64)"
	elseif byte == 0x7B then
		bin:read_byte()
		return "v128", "(result v128)"
	elseif byte == 0x70 then
		bin:read_byte()
		return "funcref", "(result funcref)"
	elseif byte == 0x6F then
		bin:read_byte()
		return "externref", "(result externref)"
	elseif byte == 0x63 or byte == 0x64 then
		local ref_str = read_ref_type(bin)
		return ref_str, string.format("(result %s)", ref_str)
	else
		local type_idx = bin:read_i64LEB()
		return type_idx, string.format("(type %d)", type_idx)
	end
end

--- Helper builders for instruction decoding
local function op_none(mnemonic)
	return function()
		local insn = { opcode = mnemonic, operands = "" }
		setmetatable(insn, Instruction)
		return insn
	end
end

local function op_index(mnemonic, field)
	return function(bin)
		local insn = {}
		local idx = bin:read_u32LEB()
		insn[field or "index"] = idx
		insn.opcode = mnemonic
		insn.operands = idx
		setmetatable(insn, Instruction)
		return insn
	end
end

--- Read memarg with Wasm 2.0 multi-memory support (bit 6 of align encodes memidx).
--- @param bin table
--- @return integer align, integer offset, integer mem_index
local function read_memarg(bin)
	local raw_align = bin:read_u32LEB()
	local mem_idx = 0
	local align = raw_align
	if (raw_align & 0x40) ~= 0 then
		mem_idx = bin:read_u32LEB()
		align = raw_align & 0x3F
	end
	local offset = bin:read_u64LEB()
	return align, offset, mem_idx
end

local function op_mem(mnemonic)
	return function(bin)
		local insn = {}
		insn.align, insn.offset, insn.mem_index = read_memarg(bin)
		insn.opcode = mnemonic
		local parts = {}
		if insn.mem_index and insn.mem_index > 0 then
			table.insert(parts, string.format("memory=%d", insn.mem_index))
		end
		if insn.offset > 0 then
			table.insert(parts, string.format("offset=%d", insn.offset))
		end
		if insn.align <= 31 then
			table.insert(parts, string.format("align=%d", 1 << insn.align))
		elseif insn.align <= 62 then
			table.insert(parts, string.format("align=%.0f", 2 ^ insn.align))
		else
			table.insert(parts, string.format("align=2^%d", insn.align))
		end
		insn.operands = table.concat(parts, " ")
		setmetatable(insn, Instruction)
		return insn
	end
end

local function op_mem_lane(mnemonic)
	return function(bin)
		local insn = {}
		insn.align, insn.offset, insn.mem_index = read_memarg(bin)
		insn.lane = bin:read_byte()
		insn.opcode = mnemonic
		local parts = {}
		if insn.mem_index and insn.mem_index > 0 then
			table.insert(parts, string.format("memory=%d", insn.mem_index))
		end
		if insn.offset > 0 then
			table.insert(parts, string.format("offset=%d", insn.offset))
		end
		if insn.align <= 31 then
			table.insert(parts, string.format("align=%d", 1 << insn.align))
		elseif insn.align <= 62 then
			table.insert(parts, string.format("align=%.0f", 2 ^ insn.align))
		else
			table.insert(parts, string.format("align=2^%d", insn.align))
		end
		table.insert(parts, tostring(insn.lane))
		insn.operands = table.concat(parts, " ")
		setmetatable(insn, Instruction)
		return insn
	end
end

--- Core opcode dispatch table
local OPCODES = {}

-- 0x00 - 0x0F: Control Flow
OPCODES[0x00] = op_none("unreachable")
OPCODES[0x01] = op_none("nop")
OPCODES[0x02] = function(bin)
	local bt, disp = read_block_type(bin)
	local insn = { opcode = "block", blocktype = bt, operands = disp }
	return setmetatable(insn, Instruction)
end
OPCODES[0x03] = function(bin)
	local bt, disp = read_block_type(bin)
	local insn = { opcode = "loop", blocktype = bt, operands = disp }
	return setmetatable(insn, Instruction)
end
OPCODES[0x04] = function(bin)
	local bt, disp = read_block_type(bin)
	local insn = { opcode = "if", blocktype = bt, operands = disp }
	return setmetatable(insn, Instruction)
end
OPCODES[0x05] = op_none("else")
-- Legacy exception-handling proposal opcodes still emitted by some Emscripten
-- builds (including current Pyodide distributions).
OPCODES[0x06] = function(bin)
	local bt, disp = read_block_type(bin)
	local insn = { opcode = "try", blocktype = bt, operands = disp }
	return setmetatable(insn, Instruction)
end
OPCODES[0x07] = op_index("catch", "tag_index")
OPCODES[0x08] = op_index("throw", "tag_index")
OPCODES[0x09] = op_index("rethrow", "label_index")
OPCODES[0x0A] = op_none("throw_ref")
OPCODES[0x0B] = op_none("end")
OPCODES[0x0C] = op_index("br", "label_index")
OPCODES[0x0D] = op_index("br_if", "label_index")
OPCODES[0x0E] = function(bin)
	local count = bin:read_u32LEB()
	local targets = {}
	for i = 1, count do
		targets[i] = bin:read_u32LEB()
	end
	local default_target = bin:read_u32LEB()
	local ops = table.concat(targets, " ")
	if #targets > 0 then
		ops = ops .. " " .. default_target
	else
		ops = tostring(default_target)
	end
	local insn = {
		opcode = "br_table",
		targets = targets,
		default_target = default_target,
		operands = ops,
	}
	return setmetatable(insn, Instruction)
end
OPCODES[0x0F] = op_none("return")
OPCODES[0x10] = op_index("call", "index")
OPCODES[0x11] = function(bin)
	local type_idx = bin:read_u32LEB()
	local table_idx = bin:read_u32LEB()
	local insn = {
		opcode = "call_indirect",
		type_index = type_idx,
		table_index = table_idx,
		operands = string.format("(type %d)", type_idx),
	}
	return setmetatable(insn, Instruction)
end

-- 0x12 - 0x15: Tail Calls & Ref Calls
OPCODES[0x12] = op_index("return_call", "index")
OPCODES[0x13] = function(bin)
	local type_idx = bin:read_u32LEB()
	local table_idx = bin:read_u32LEB()
	local insn = {
		opcode = "return_call_indirect",
		type_index = type_idx,
		table_index = table_idx,
		operands = string.format("(type %d)", type_idx),
	}
	return setmetatable(insn, Instruction)
end
OPCODES[0x14] = op_index("call_ref", "type_index")
OPCODES[0x15] = op_index("return_call_ref", "type_index")
OPCODES[0x18] = op_index("delegate", "label_index")
OPCODES[0x19] = op_none("catch_all")

-- 0x1A - 0x1C: Parametric
OPCODES[0x1A] = op_none("drop")
OPCODES[0x1B] = op_none("select")
OPCODES[0x1C] = function(bin)
	local count = bin:read_u32LEB()
	local types = {}
	for _ = 1, count do
		local vt = bin:read_byte()
		table.insert(types, opcodes.valtype_to_string(vt))
	end
	local ops = ""
	if #types > 0 then
		ops = "(result " .. table.concat(types, " ") .. ")"
	end
	local insn = { opcode = "select", types = types, operands = ops }
	return setmetatable(insn, Instruction)
end

-- 0x1F: Exception Handling try_table
OPCODES[0x1F] = function(bin)
	local bt, disp = read_block_type(bin)
	local num_catches = bin:read_u32LEB()
	local catches = {}
	local catch_strs = {}
	for _ = 1, num_catches do
		local kind = bin:read_byte()
		if kind == 0x00 then
			local tag = bin:read_u32LEB()
			local label = bin:read_u32LEB()
			table.insert(catches, { kind = "catch", tag = tag, label = label })
			table.insert(catch_strs, string.format("(catch %d %d)", tag, label))
		elseif kind == 0x01 then
			local tag = bin:read_u32LEB()
			local label = bin:read_u32LEB()
			table.insert(catches, { kind = "catch_ref", tag = tag, label = label })
			table.insert(catch_strs, string.format("(catch_ref %d %d)", tag, label))
		elseif kind == 0x02 then
			local label = bin:read_u32LEB()
			table.insert(catches, { kind = "catch_all", label = label })
			table.insert(catch_strs, string.format("(catch_all %d)", label))
		elseif kind == 0x03 then
			local label = bin:read_u32LEB()
			table.insert(catches, { kind = "catch_all_ref", label = label })
			table.insert(catch_strs, string.format("(catch_all_ref %d)", label))
		end
	end
	local ops = disp
	if #catch_strs > 0 then
		ops = (ops ~= "" and (ops .. " ") or "") .. table.concat(catch_strs, " ")
	end
	local insn = { opcode = "try_table", blocktype = bt, catches = catches, operands = ops }
	return setmetatable(insn, Instruction)
end

-- 0x20 - 0x26: Variables & Tables
OPCODES[0x20] = op_index("local.get", "index")
OPCODES[0x21] = op_index("local.set", "index")
OPCODES[0x22] = op_index("local.tee", "index")
OPCODES[0x23] = op_index("global.get", "index")
OPCODES[0x24] = op_index("global.set", "index")
OPCODES[0x25] = op_index("table.get", "index")
OPCODES[0x26] = op_index("table.set", "index")

-- 0x28 - 0x3E: Memory Load/Store
OPCODES[0x28] = op_mem("i32.load")
OPCODES[0x29] = op_mem("i64.load")
OPCODES[0x2A] = op_mem("f32.load")
OPCODES[0x2B] = op_mem("f64.load")
OPCODES[0x2C] = op_mem("i32.load8_s")
OPCODES[0x2D] = op_mem("i32.load8_u")
OPCODES[0x2E] = op_mem("i32.load16_s")
OPCODES[0x2F] = op_mem("i32.load16_u")
OPCODES[0x30] = op_mem("i64.load8_s")
OPCODES[0x31] = op_mem("i64.load8_u")
OPCODES[0x32] = op_mem("i64.load16_s")
OPCODES[0x33] = op_mem("i64.load16_u")
OPCODES[0x34] = op_mem("i64.load32_s")
OPCODES[0x35] = op_mem("i64.load32_u")
OPCODES[0x36] = op_mem("i32.store")
OPCODES[0x37] = op_mem("i64.store")
OPCODES[0x38] = op_mem("f32.store")
OPCODES[0x39] = op_mem("f64.store")
OPCODES[0x3A] = op_mem("i32.store8")
OPCODES[0x3B] = op_mem("i32.store16")
OPCODES[0x3C] = op_mem("i64.store8")
OPCODES[0x3D] = op_mem("i64.store16")
OPCODES[0x3E] = op_mem("i64.store32")

-- 0x3F - 0x40: Memory Size & Grow (supports multi-memory index)
OPCODES[0x3F] = function(bin)
	local mem_idx = bin:read_u32LEB()
	local insn = { opcode = "memory.size", mem_index = mem_idx, operands = mem_idx > 0 and tostring(mem_idx) or "" }
	return setmetatable(insn, Instruction)
end
OPCODES[0x40] = function(bin)
	local mem_idx = bin:read_u32LEB()
	local insn = { opcode = "memory.grow", mem_index = mem_idx, operands = mem_idx > 0 and tostring(mem_idx) or "" }
	return setmetatable(insn, Instruction)
end

-- 0x41 - 0x44: Constants
OPCODES[0x41] = function(bin)
	local val = bin:read_i32LEB()
	local insn = { opcode = "i32.const", value = val, operands = tostring(val) }
	return setmetatable(insn, Instruction)
end
OPCODES[0x42] = function(bin)
	local val = bin:read_i64LEB()
	local insn = { opcode = "i64.const", value = val, operands = tostring(val) }
	return setmetatable(insn, Instruction)
end
OPCODES[0x43] = function(bin)
	local val = bin:read_f32()
	local insn = { opcode = "f32.const", value = val, operands = tostring(val) }
	return setmetatable(insn, Instruction)
end
OPCODES[0x44] = function(bin)
	local val = bin:read_f64()
	local insn = { opcode = "f64.const", value = val, operands = tostring(val) }
	return setmetatable(insn, Instruction)
end

-- 0x45 - 0x4F: i32 Comparisons
OPCODES[0x45] = op_none("i32.eqz")
OPCODES[0x46] = op_none("i32.eq")
OPCODES[0x47] = op_none("i32.ne")
OPCODES[0x48] = op_none("i32.lt_s")
OPCODES[0x49] = op_none("i32.lt_u")
OPCODES[0x4A] = op_none("i32.gt_s")
OPCODES[0x4B] = op_none("i32.gt_u")
OPCODES[0x4C] = op_none("i32.le_s")
OPCODES[0x4D] = op_none("i32.le_u")
OPCODES[0x4E] = op_none("i32.ge_s")
OPCODES[0x4F] = op_none("i32.ge_u")

-- 0x50 - 0x5A: i64 Comparisons
OPCODES[0x50] = op_none("i64.eqz")
OPCODES[0x51] = op_none("i64.eq")
OPCODES[0x52] = op_none("i64.ne")
OPCODES[0x53] = op_none("i64.lt_s")
OPCODES[0x54] = op_none("i64.lt_u")
OPCODES[0x55] = op_none("i64.gt_s")
OPCODES[0x56] = op_none("i64.gt_u")
OPCODES[0x57] = op_none("i64.le_s")
OPCODES[0x58] = op_none("i64.le_u")
OPCODES[0x59] = op_none("i64.ge_s")
OPCODES[0x5A] = op_none("i64.ge_u")

-- 0x5B - 0x60: f32 Comparisons
OPCODES[0x5B] = op_none("f32.eq")
OPCODES[0x5C] = op_none("f32.ne")
OPCODES[0x5D] = op_none("f32.lt")
OPCODES[0x5E] = op_none("f32.gt")
OPCODES[0x5F] = op_none("f32.le")
OPCODES[0x60] = op_none("f32.ge")

-- 0x61 - 0x66: f64 Comparisons
OPCODES[0x61] = op_none("f64.eq")
OPCODES[0x62] = op_none("f64.ne")
OPCODES[0x63] = op_none("f64.lt")
OPCODES[0x64] = op_none("f64.gt")
OPCODES[0x65] = op_none("f64.le")
OPCODES[0x66] = op_none("f64.ge")

-- 0x67 - 0x78: i32 Arithmetic & Bitwise
OPCODES[0x67] = op_none("i32.clz")
OPCODES[0x68] = op_none("i32.ctz")
OPCODES[0x69] = op_none("i32.popcnt")
OPCODES[0x6A] = op_none("i32.add")
OPCODES[0x6B] = op_none("i32.sub")
OPCODES[0x6C] = op_none("i32.mul")
OPCODES[0x6D] = op_none("i32.div_s")
OPCODES[0x6E] = op_none("i32.div_u")
OPCODES[0x6F] = op_none("i32.rem_s")
OPCODES[0x70] = op_none("i32.rem_u")
OPCODES[0x71] = op_none("i32.and")
OPCODES[0x72] = op_none("i32.or")
OPCODES[0x73] = op_none("i32.xor")
OPCODES[0x74] = op_none("i32.shl")
OPCODES[0x75] = op_none("i32.shr_s")
OPCODES[0x76] = op_none("i32.shr_u")
OPCODES[0x77] = op_none("i32.rotl")
OPCODES[0x78] = op_none("i32.rotr")

-- 0x79 - 0x8A: i64 Arithmetic & Bitwise
OPCODES[0x79] = op_none("i64.clz")
OPCODES[0x7A] = op_none("i64.ctz")
OPCODES[0x7B] = op_none("i64.popcnt")
OPCODES[0x7C] = op_none("i64.add")
OPCODES[0x7D] = op_none("i64.sub")
OPCODES[0x7E] = op_none("i64.mul")
OPCODES[0x7F] = op_none("i64.div_s")
OPCODES[0x80] = op_none("i64.div_u")
OPCODES[0x81] = op_none("i64.rem_s")
OPCODES[0x82] = op_none("i64.rem_u")
OPCODES[0x83] = op_none("i64.and")
OPCODES[0x84] = op_none("i64.or")
OPCODES[0x85] = op_none("i64.xor")
OPCODES[0x86] = op_none("i64.shl")
OPCODES[0x87] = op_none("i64.shr_s")
OPCODES[0x88] = op_none("i64.shr_u")
OPCODES[0x89] = op_none("i64.rotl")
OPCODES[0x8A] = op_none("i64.rotr")

-- 0x8B - 0x98: f32 Arithmetic
OPCODES[0x8B] = op_none("f32.abs")
OPCODES[0x8C] = op_none("f32.neg")
OPCODES[0x8D] = op_none("f32.ceil")
OPCODES[0x8E] = op_none("f32.floor")
OPCODES[0x8F] = op_none("f32.trunc")
OPCODES[0x90] = op_none("f32.nearest")
OPCODES[0x91] = op_none("f32.sqrt")
OPCODES[0x92] = op_none("f32.add")
OPCODES[0x93] = op_none("f32.sub")
OPCODES[0x94] = op_none("f32.mul")
OPCODES[0x95] = op_none("f32.div")
OPCODES[0x96] = op_none("f32.min")
OPCODES[0x97] = op_none("f32.max")
OPCODES[0x98] = op_none("f32.copysign")

-- 0x99 - 0xA6: f64 Arithmetic
OPCODES[0x99] = op_none("f64.abs")
OPCODES[0x9A] = op_none("f64.neg")
OPCODES[0x9B] = op_none("f64.ceil")
OPCODES[0x9C] = op_none("f64.floor")
OPCODES[0x9D] = op_none("f64.trunc")
OPCODES[0x9E] = op_none("f64.nearest")
OPCODES[0x9F] = op_none("f64.sqrt")
OPCODES[0xA0] = op_none("f64.add")
OPCODES[0xA1] = op_none("f64.sub")
OPCODES[0xA2] = op_none("f64.mul")
OPCODES[0xA3] = op_none("f64.div")
OPCODES[0xA4] = op_none("f64.min")
OPCODES[0xA5] = op_none("f64.max")
OPCODES[0xA6] = op_none("f64.copysign")

-- 0xA7 - 0xC4: Conversions
OPCODES[0xA7] = op_none("i32.wrap_i64")
OPCODES[0xA8] = op_none("i32.trunc_f32_s")
OPCODES[0xA9] = op_none("i32.trunc_f32_u")
OPCODES[0xAA] = op_none("i32.trunc_f64_s")
OPCODES[0xAB] = op_none("i32.trunc_f64_u")
OPCODES[0xAC] = op_none("i64.extend_i32_s")
OPCODES[0xAD] = op_none("i64.extend_i32_u")
OPCODES[0xAE] = op_none("i64.trunc_f32_s")
OPCODES[0xAF] = op_none("i64.trunc_f32_u")
OPCODES[0xB0] = op_none("i64.trunc_f64_s")
OPCODES[0xB1] = op_none("i64.trunc_f64_u")
OPCODES[0xB2] = op_none("f32.convert_i32_s")
OPCODES[0xB3] = op_none("f32.convert_i32_u")
OPCODES[0xB4] = op_none("f32.convert_i64_s")
OPCODES[0xB5] = op_none("f32.convert_i64_u")
OPCODES[0xB6] = op_none("f32.demote_f64")
OPCODES[0xB7] = op_none("f64.convert_i32_s")
OPCODES[0xB8] = op_none("f64.convert_i32_u")
OPCODES[0xB9] = op_none("f64.convert_i64_s")
OPCODES[0xBA] = op_none("f64.convert_i64_u")
OPCODES[0xBB] = op_none("f64.promote_f32")
OPCODES[0xBC] = op_none("i32.reinterpret_f32")
OPCODES[0xBD] = op_none("i64.reinterpret_f64")
OPCODES[0xBE] = op_none("f32.reinterpret_i32")
OPCODES[0xBF] = op_none("f64.reinterpret_i64")
OPCODES[0xC0] = op_none("i32.extend8_s")
OPCODES[0xC1] = op_none("i32.extend16_s")
OPCODES[0xC2] = op_none("i64.extend8_s")
OPCODES[0xC3] = op_none("i64.extend16_s")
OPCODES[0xC4] = op_none("i64.extend32_s")

-- 0xD0 - 0xD6: Reference Instructions
OPCODES[0xD0] = function(bin)
	local ht = read_heap_type(bin)
	local insn = { opcode = "ref.null", heap_type = ht, operands = ht }
	return setmetatable(insn, Instruction)
end
OPCODES[0xD1] = op_none("ref.is_null")
OPCODES[0xD2] = op_index("ref.func", "index")
OPCODES[0xD3] = op_none("ref.eq")
OPCODES[0xD4] = op_none("ref.as_non_null")
OPCODES[0xD5] = op_index("br_on_null", "label_index")
OPCODES[0xD6] = op_index("br_on_non_null", "label_index")

-- 0xFC Prefix: Saturating Truncations & Bulk Memory / Tables
local FC_OPCODES = {
	[0x00] = { name = "i32.trunc_sat_f32_s", handler = op_none("i32.trunc_sat_f32_s") },
	[0x01] = { name = "i32.trunc_sat_f32_u", handler = op_none("i32.trunc_sat_f32_u") },
	[0x02] = { name = "i32.trunc_sat_f64_s", handler = op_none("i32.trunc_sat_f64_s") },
	[0x03] = { name = "i32.trunc_sat_f64_u", handler = op_none("i32.trunc_sat_f64_u") },
	[0x04] = { name = "i64.trunc_sat_f32_s", handler = op_none("i64.trunc_sat_f32_s") },
	[0x05] = { name = "i64.trunc_sat_f32_u", handler = op_none("i64.trunc_sat_f32_u") },
	[0x06] = { name = "i64.trunc_sat_f64_s", handler = op_none("i64.trunc_sat_f64_s") },
	[0x07] = { name = "i64.trunc_sat_f64_u", handler = op_none("i64.trunc_sat_f64_u") },
	[0x08] = {
		name = "memory.init",
		handler = function(bin)
			local data_idx = bin:read_u32LEB()
			local mem_idx = bin:read_u32LEB()
			local ops = mem_idx > 0 and string.format("%d %d", data_idx, mem_idx) or tostring(data_idx)
			local insn = { opcode = "memory.init", data_index = data_idx, mem_index = mem_idx, operands = ops }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x09] = { name = "data.drop", handler = op_index("data.drop", "data_index") },
	[0x0A] = {
		name = "memory.copy",
		handler = function(bin)
			local src_mem = bin:read_u32LEB()
			local dst_mem = bin:read_u32LEB()
			local ops = (src_mem > 0 or dst_mem > 0) and string.format("%d %d", src_mem, dst_mem) or ""
			local insn = { opcode = "memory.copy", src_memory = src_mem, dst_memory = dst_mem, operands = ops }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x0B] = {
		name = "memory.fill",
		handler = function(bin)
			local mem_idx = bin:read_u32LEB()
			local ops = mem_idx > 0 and tostring(mem_idx) or ""
			local insn = { opcode = "memory.fill", mem_index = mem_idx, operands = ops }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x0C] = {
		name = "table.init",
		handler = function(bin)
			local elem_idx = bin:read_u32LEB()
			local tbl_idx = bin:read_u32LEB()
			local insn = {
				opcode = "table.init",
				elem_index = elem_idx,
				table_index = tbl_idx,
				operands = string.format("%d %d", elem_idx, tbl_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x0D] = { name = "elem.drop", handler = op_index("elem.drop", "elem_index") },
	[0x0E] = {
		name = "table.copy",
		handler = function(bin)
			local dst = bin:read_u32LEB()
			local src = bin:read_u32LEB()
			local insn = { opcode = "table.copy", dst = dst, src = src, operands = string.format("%d %d", dst, src) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x0F] = { name = "table.grow", handler = op_index("table.grow", "table_index") },
	[0x10] = { name = "table.size", handler = op_index("table.size", "table_index") },
	[0x11] = { name = "table.fill", handler = op_index("table.fill", "table_index") },
	-- Wide Arithmetic proposal (0xFC 0x13 .. 0x16)
	[0x13] = { name = "i64.add128", handler = op_none("i64.add128") },
	[0x14] = { name = "i64.sub128", handler = op_none("i64.sub128") },
	[0x15] = { name = "i64.mul_wide_s", handler = op_none("i64.mul_wide_s") },
	[0x16] = { name = "i64.mul_wide_u", handler = op_none("i64.mul_wide_u") },
}

OPCODES[opcodes.PREFIX_MATH] = function(bin)
	local sub_op = bin:read_u32LEB()
	local entry = FC_OPCODES[sub_op]
	if not entry then
		error(string.format("Unknown 0xFC sub-opcode: 0x%02X (%d)", sub_op, sub_op))
	end
	local insn = entry.handler(bin)
	insn.prefix = 0xFC
	insn.sub_op = sub_op
	return insn
end

-- 0xFB Prefix: Garbage Collection (GC) & Aggregate Instructions
local FB_OPCODES = {
	[0x00] = { name = "struct.new", handler = op_index("struct.new", "type_index") },
	[0x01] = { name = "struct.new_default", handler = op_index("struct.new_default", "type_index") },
	[0x02] = {
		name = "struct.get",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local field_idx = bin:read_u32LEB()
			local insn = {
				opcode = "struct.get",
				type_index = type_idx,
				field_index = field_idx,
				operands = string.format("%d %d", type_idx, field_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x03] = {
		name = "struct.get_s",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local field_idx = bin:read_u32LEB()
			local insn = {
				opcode = "struct.get_s",
				type_index = type_idx,
				field_index = field_idx,
				operands = string.format("%d %d", type_idx, field_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x04] = {
		name = "struct.get_u",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local field_idx = bin:read_u32LEB()
			local insn = {
				opcode = "struct.get_u",
				type_index = type_idx,
				field_index = field_idx,
				operands = string.format("%d %d", type_idx, field_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x05] = {
		name = "struct.set",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local field_idx = bin:read_u32LEB()
			local insn = {
				opcode = "struct.set",
				type_index = type_idx,
				field_index = field_idx,
				operands = string.format("%d %d", type_idx, field_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x06] = { name = "array.new", handler = op_index("array.new", "type_index") },
	[0x07] = { name = "array.new_default", handler = op_index("array.new_default", "type_index") },
	[0x08] = {
		name = "array.new_fixed",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local size = bin:read_u32LEB()
			local insn = {
				opcode = "array.new_fixed",
				type_index = type_idx,
				size = size,
				operands = string.format("%d %d", type_idx, size),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x09] = {
		name = "array.new_data",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local data_idx = bin:read_u32LEB()
			local insn = {
				opcode = "array.new_data",
				type_index = type_idx,
				data_index = data_idx,
				operands = string.format("%d %d", type_idx, data_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x0A] = {
		name = "array.new_elem",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local elem_idx = bin:read_u32LEB()
			local insn = {
				opcode = "array.new_elem",
				type_index = type_idx,
				elem_index = elem_idx,
				operands = string.format("%d %d", type_idx, elem_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x0B] = { name = "array.get", handler = op_index("array.get", "type_index") },
	[0x0C] = { name = "array.get_s", handler = op_index("array.get_s", "type_index") },
	[0x0D] = { name = "array.get_u", handler = op_index("array.get_u", "type_index") },
	[0x0E] = { name = "array.set", handler = op_index("array.set", "type_index") },
	[0x0F] = { name = "array.len", handler = op_none("array.len") },
	[0x10] = { name = "array.fill", handler = op_index("array.fill", "type_index") },
	[0x11] = {
		name = "array.copy",
		handler = function(bin)
			local dst = bin:read_u32LEB()
			local src = bin:read_u32LEB()
			local insn = { opcode = "array.copy", dst = dst, src = src, operands = string.format("%d %d", dst, src) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x12] = {
		name = "array.init_data",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local data_idx = bin:read_u32LEB()
			local insn = {
				opcode = "array.init_data",
				type_index = type_idx,
				data_index = data_idx,
				operands = string.format("%d %d", type_idx, data_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x13] = {
		name = "array.init_elem",
		handler = function(bin)
			local type_idx = bin:read_u32LEB()
			local elem_idx = bin:read_u32LEB()
			local insn = {
				opcode = "array.init_elem",
				type_index = type_idx,
				elem_index = elem_idx,
				operands = string.format("%d %d", type_idx, elem_idx),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x14] = {
		name = "ref.test",
		handler = function(bin)
			local ht = read_heap_type(bin)
			local insn = { opcode = "ref.test", heap_type = ht, operands = string.format("(ref %s)", ht) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x15] = {
		name = "ref.test null",
		handler = function(bin)
			local ht = read_heap_type(bin)
			local insn = { opcode = "ref.test", heap_type = ht, operands = string.format("(ref null %s)", ht) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x16] = {
		name = "ref.cast",
		handler = function(bin)
			local ht = read_heap_type(bin)
			local insn = { opcode = "ref.cast", heap_type = ht, operands = string.format("(ref %s)", ht) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x17] = {
		name = "ref.cast null",
		handler = function(bin)
			local ht = read_heap_type(bin)
			local insn = { opcode = "ref.cast", heap_type = ht, operands = string.format("(ref null %s)", ht) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x18] = {
		name = "br_on_cast",
		handler = function(bin)
			local castop = bin:read_byte()
			local label = bin:read_u32LEB()
			local ht1 = read_heap_type(bin)
			local ht2 = read_heap_type(bin)
			local rt1 = (castop & 0x01) ~= 0 and string.format("(ref null %s)", ht1) or string.format("(ref %s)", ht1)
			local rt2 = (castop & 0x02) ~= 0 and string.format("(ref null %s)", ht2) or string.format("(ref %s)", ht2)
			local insn =
				{ opcode = "br_on_cast", label_index = label, operands = string.format("%d %s %s", label, rt1, rt2) }
			return setmetatable(insn, Instruction)
		end,
	},
	[0x19] = {
		name = "br_on_cast_fail",
		handler = function(bin)
			local castop = bin:read_byte()
			local label = bin:read_u32LEB()
			local ht1 = read_heap_type(bin)
			local ht2 = read_heap_type(bin)
			local rt1 = (castop & 0x01) ~= 0 and string.format("(ref null %s)", ht1) or string.format("(ref %s)", ht1)
			local rt2 = (castop & 0x02) ~= 0 and string.format("(ref null %s)", ht2) or string.format("(ref %s)", ht2)
			local insn = {
				opcode = "br_on_cast_fail",
				label_index = label,
				operands = string.format("%d %s %s", label, rt1, rt2),
			}
			return setmetatable(insn, Instruction)
		end,
	},
	[0x1A] = { name = "any.convert_extern", handler = op_none("any.convert_extern") },
	[0x1B] = { name = "extern.convert_any", handler = op_none("extern.convert_any") },
	[0x1C] = { name = "ref.i31", handler = op_none("ref.i31") },
	[0x1D] = { name = "i31.get_s", handler = op_none("i31.get_s") },
	[0x1E] = { name = "i31.get_u", handler = op_none("i31.get_u") },
}

OPCODES[opcodes.PREFIX_GC] = function(bin)
	local sub_op = bin:read_u32LEB()
	local entry = FB_OPCODES[sub_op]
	if not entry then
		error(string.format("Unknown 0xFB (GC) sub-opcode: 0x%02X (%d)", sub_op, sub_op))
	end
	local insn = entry.handler(bin)
	insn.prefix = 0xFB
	insn.sub_op = sub_op
	return insn
end

-- 0xFD Prefix: SIMD (128-bit vector instructions)
local FD_OPCODES = {
	[0x00] = op_mem("v128.load"),
	[0x01] = op_mem("v128.load8x8_s"),
	[0x02] = op_mem("v128.load8x8_u"),
	[0x03] = op_mem("v128.load16x4_s"),
	[0x04] = op_mem("v128.load16x4_u"),
	[0x05] = op_mem("v128.load32x2_s"),
	[0x06] = op_mem("v128.load32x2_u"),
	[0x07] = op_mem("v128.load8_splat"),
	[0x08] = op_mem("v128.load16_splat"),
	[0x09] = op_mem("v128.load32_splat"),
	[0x0A] = op_mem("v128.load64_splat"),
	[0x0B] = op_mem("v128.store"),
	[0x0C] = function(bin)
		local bytes = bin:read_bytes(16)
		local hex = {}
		for _, b in ipairs(bytes) do
			hex[#hex + 1] = string.format("0x%02x", b)
		end
		local insn = { opcode = "v128.const", value = bytes, operands = "i8x16 " .. table.concat(hex, " ") }
		return setmetatable(insn, Instruction)
	end,
	[0x0D] = function(bin)
		local lanes = bin:read_bytes(16)
		local insn = { opcode = "i8x16.shuffle", lanes = lanes, operands = table.concat(lanes, " ") }
		return setmetatable(insn, Instruction)
	end,
	[0x0E] = op_none("i8x16.swizzle"),
	[0x0F] = op_none("i8x16.splat"),
	[0x10] = op_none("i16x8.splat"),
	[0x11] = op_none("i32x4.splat"),
	[0x12] = op_none("i64x2.splat"),
	[0x13] = op_none("f32x4.splat"),
	[0x14] = op_none("f64x2.splat"),
	[0x15] = op_index("i8x16.extract_lane_s", "lane"),
	[0x16] = op_index("i8x16.extract_lane_u", "lane"),
	[0x17] = op_index("i8x16.replace_lane", "lane"),
	[0x18] = op_index("i16x8.extract_lane_s", "lane"),
	[0x19] = op_index("i16x8.extract_lane_u", "lane"),
	[0x1A] = op_index("i16x8.replace_lane", "lane"),
	[0x1B] = op_index("i32x4.extract_lane", "lane"),
	[0x1C] = op_index("i32x4.replace_lane", "lane"),
	[0x1D] = op_index("i64x2.extract_lane", "lane"),
	[0x1E] = op_index("i64x2.replace_lane", "lane"),
	[0x1F] = op_index("f32x4.extract_lane", "lane"),
	[0x20] = op_index("f32x4.replace_lane", "lane"),
	[0x21] = op_index("f64x2.extract_lane", "lane"),
	[0x22] = op_index("f64x2.replace_lane", "lane"),
	-- SIMD comparisons & logical
	[0x23] = op_none("i8x16.eq"),
	[0x24] = op_none("i8x16.ne"),
	[0x25] = op_none("i8x16.lt_s"),
	[0x26] = op_none("i8x16.lt_u"),
	[0x27] = op_none("i8x16.gt_s"),
	[0x28] = op_none("i8x16.gt_u"),
	[0x29] = op_none("i8x16.le_s"),
	[0x2A] = op_none("i8x16.le_u"),
	[0x2B] = op_none("i8x16.ge_s"),
	[0x2C] = op_none("i8x16.ge_u"),
	[0x2D] = op_none("i16x8.eq"),
	[0x2E] = op_none("i16x8.ne"),
	[0x2F] = op_none("i16x8.lt_s"),
	[0x30] = op_none("i16x8.lt_u"),
	[0x31] = op_none("i16x8.gt_s"),
	[0x32] = op_none("i16x8.gt_u"),
	[0x33] = op_none("i16x8.le_s"),
	[0x34] = op_none("i16x8.le_u"),
	[0x35] = op_none("i16x8.ge_s"),
	[0x36] = op_none("i16x8.ge_u"),
	[0x37] = op_none("i32x4.eq"),
	[0x38] = op_none("i32x4.ne"),
	[0x39] = op_none("i32x4.lt_s"),
	[0x3A] = op_none("i32x4.lt_u"),
	[0x3B] = op_none("i32x4.gt_s"),
	[0x3C] = op_none("i32x4.gt_u"),
	[0x3D] = op_none("i32x4.le_s"),
	[0x3E] = op_none("i32x4.le_u"),
	[0x3F] = op_none("i32x4.ge_s"),
	[0x40] = op_none("i32x4.ge_u"),
	[0x41] = op_none("f32x4.eq"),
	[0x42] = op_none("f32x4.ne"),
	[0x43] = op_none("f32x4.lt"),
	[0x44] = op_none("f32x4.gt"),
	[0x45] = op_none("f32x4.le"),
	[0x46] = op_none("f32x4.ge"),
	[0x47] = op_none("f64x2.eq"),
	[0x48] = op_none("f64x2.ne"),
	[0x49] = op_none("f64x2.lt"),
	[0x4A] = op_none("f64x2.gt"),
	[0x4B] = op_none("f64x2.le"),
	[0x4C] = op_none("f64x2.ge"),
	[0x4D] = op_none("v128.not"),
	[0x4E] = op_none("v128.and"),
	[0x4F] = op_none("v128.andnot"),
	[0x50] = op_none("v128.or"),
	[0x51] = op_none("v128.xor"),
	[0x52] = op_none("v128.bitselect"),
	[0x53] = op_none("v128.any_true"),
	[0x54] = op_mem_lane("v128.load8_lane"),
	[0x55] = op_mem_lane("v128.load16_lane"),
	[0x56] = op_mem_lane("v128.load32_lane"),
	[0x57] = op_mem_lane("v128.load64_lane"),
	[0x58] = op_mem_lane("v128.store8_lane"),
	[0x59] = op_mem_lane("v128.store16_lane"),
	[0x5A] = op_mem_lane("v128.store32_lane"),
	[0x5B] = op_mem_lane("v128.store64_lane"),
	[0x5C] = op_mem("v128.load32_zero"),
	[0x5D] = op_mem("v128.load64_zero"),
	[0x5E] = op_none("f32x4.demote_f64x2_zero"),
	[0x5F] = op_none("f64x2.promote_low_f32x4"),
	-- i8x16 ops
	[0x60] = op_none("i8x16.abs"),
	[0x61] = op_none("i8x16.neg"),
	[0x62] = op_none("i8x16.popcnt"),
	[0x63] = op_none("i8x16.all_true"),
	[0x64] = op_none("i8x16.bitmask"),
	[0x65] = op_none("i8x16.narrow_i16x8_s"),
	[0x66] = op_none("i8x16.narrow_i16x8_u"),
	[0x67] = op_none("f32x4.ceil"),
	[0x68] = op_none("f32x4.floor"),
	[0x69] = op_none("f32x4.trunc"),
	[0x6A] = op_none("f32x4.nearest"),
	[0x6B] = op_none("i8x16.shl"),
	[0x6C] = op_none("i8x16.shr_s"),
	[0x6D] = op_none("i8x16.shr_u"),
	[0x6E] = op_none("i8x16.add"),
	[0x6F] = op_none("i8x16.add_sat_s"),
	[0x70] = op_none("i8x16.add_sat_u"),
	[0x71] = op_none("i8x16.sub"),
	[0x72] = op_none("i8x16.sub_sat_s"),
	[0x73] = op_none("i8x16.sub_sat_u"),
	[0x74] = op_none("f64x2.ceil"),
	[0x75] = op_none("f64x2.floor"),
	[0x76] = op_none("i8x16.min_s"),
	[0x77] = op_none("i8x16.min_u"),
	[0x78] = op_none("i8x16.max_s"),
	[0x79] = op_none("i8x16.max_u"),
	[0x7A] = op_none("f64x2.trunc"),
	[0x7B] = op_none("i8x16.avgr_u"),
	[0x7C] = op_none("i16x8.extadd_pairwise_i8x16_s"),
	[0x7D] = op_none("i16x8.extadd_pairwise_i8x16_u"),
	[0x7E] = op_none("i32x4.extadd_pairwise_i16x8_s"),
	[0x7F] = op_none("i32x4.extadd_pairwise_i16x8_u"),
	-- i16x8 ops
	[0x80] = op_none("i16x8.abs"),
	[0x81] = op_none("i16x8.neg"),
	[0x82] = op_none("i16x8.q15mulr_sat_s"),
	[0x83] = op_none("i16x8.all_true"),
	[0x84] = op_none("i16x8.bitmask"),
	[0x85] = op_none("i16x8.narrow_i32x4_s"),
	[0x86] = op_none("i16x8.narrow_i32x4_u"),
	[0x87] = op_none("i16x8.extend_low_i8x16_s"),
	[0x88] = op_none("i16x8.extend_high_i8x16_s"),
	[0x89] = op_none("i16x8.extend_low_i8x16_u"),
	[0x8A] = op_none("i16x8.extend_high_i8x16_u"),
	[0x8B] = op_none("i16x8.shl"),
	[0x8C] = op_none("i16x8.shr_s"),
	[0x8D] = op_none("i16x8.shr_u"),
	[0x8E] = op_none("i16x8.add"),
	[0x8F] = op_none("i16x8.add_sat_s"),
	[0x90] = op_none("i16x8.add_sat_u"),
	[0x91] = op_none("i16x8.sub"),
	[0x92] = op_none("i16x8.sub_sat_s"),
	[0x93] = op_none("i16x8.sub_sat_u"),
	[0x94] = op_none("f64x2.nearest"),
	[0x95] = op_none("i16x8.mul"),
	[0x96] = op_none("i16x8.min_s"),
	[0x97] = op_none("i16x8.min_u"),
	[0x98] = op_none("i16x8.max_s"),
	[0x99] = op_none("i16x8.max_u"),
	[0x9B] = op_none("i16x8.avgr_u"),
	[0x9C] = op_none("i16x8.extmul_low_i8x16_s"),
	[0x9D] = op_none("i16x8.extmul_high_i8x16_s"),
	[0x9E] = op_none("i16x8.extmul_low_i8x16_u"),
	[0x9F] = op_none("i16x8.extmul_high_i8x16_u"),
	-- i32x4 ops
	[0xA0] = op_none("i32x4.abs"),
	[0xA1] = op_none("i32x4.neg"),
	[0xA3] = op_none("i32x4.all_true"),
	[0xA4] = op_none("i32x4.bitmask"),
	[0xA7] = op_none("i32x4.extend_low_i16x8_s"),
	[0xA8] = op_none("i32x4.extend_high_i16x8_s"),
	[0xA9] = op_none("i32x4.extend_low_i16x8_u"),
	[0xAA] = op_none("i32x4.extend_high_i16x8_u"),
	[0xAB] = op_none("i32x4.shl"),
	[0xAC] = op_none("i32x4.shr_s"),
	[0xAD] = op_none("i32x4.shr_u"),
	[0xAE] = op_none("i32x4.add"),
	[0xB1] = op_none("i32x4.sub"),
	[0xB5] = op_none("i32x4.mul"),
	[0xB6] = op_none("i32x4.min_s"),
	[0xB7] = op_none("i32x4.min_u"),
	[0xB8] = op_none("i32x4.max_s"),
	[0xB9] = op_none("i32x4.max_u"),
	[0xBA] = op_none("i32x4.dot_i16x8_s"),
	[0xBC] = op_none("i32x4.extmul_low_i16x8_s"),
	[0xBD] = op_none("i32x4.extmul_high_i16x8_s"),
	[0xBE] = op_none("i32x4.extmul_low_i16x8_u"),
	[0xBF] = op_none("i32x4.extmul_high_i16x8_u"),
	-- i64x2 ops
	[0xC0] = op_none("i64x2.abs"),
	[0xC1] = op_none("i64x2.neg"),
	[0xC3] = op_none("i64x2.all_true"),
	[0xC4] = op_none("i64x2.bitmask"),
	[0xC7] = op_none("i64x2.extend_low_i32x4_s"),
	[0xC8] = op_none("i64x2.extend_high_i32x4_s"),
	[0xC9] = op_none("i64x2.extend_low_i32x4_u"),
	[0xCA] = op_none("i64x2.extend_high_i32x4_u"),
	[0xCB] = op_none("i64x2.shl"),
	[0xCC] = op_none("i64x2.shr_s"),
	[0xCD] = op_none("i64x2.shr_u"),
	[0xCE] = op_none("i64x2.add"),
	[0xD1] = op_none("i64x2.sub"),
	[0xD5] = op_none("i64x2.mul"),
	[0xD6] = op_none("i64x2.eq"),
	[0xD7] = op_none("i64x2.ne"),
	[0xD8] = op_none("i64x2.lt_s"),
	[0xD9] = op_none("i64x2.gt_s"),
	[0xDA] = op_none("i64x2.le_s"),
	[0xDB] = op_none("i64x2.ge_s"),
	[0xDC] = op_none("i64x2.extmul_low_i32x4_s"),
	[0xDD] = op_none("i64x2.extmul_high_i32x4_s"),
	[0xDE] = op_none("i64x2.extmul_low_i32x4_u"),
	[0xDF] = op_none("i64x2.extmul_high_i32x4_u"),
	-- f32x4 ops
	[0xE0] = op_none("f32x4.ceil"),
	[0xE1] = op_none("f32x4.floor"),
	[0xE2] = op_none("f32x4.trunc"),
	[0xE3] = op_none("f32x4.nearest"),
	[0xE4] = op_none("f32x4.abs"),
	[0xE5] = op_none("f32x4.neg"),
	[0xE6] = op_none("f32x4.sqrt"),
	[0xE7] = op_none("f32x4.add"),
	[0xE8] = op_none("f32x4.sub"),
	[0xE9] = op_none("f32x4.mul"),
	[0xEA] = op_none("f32x4.div"),
	[0xEB] = op_none("f32x4.min"),
	[0xEC] = op_none("f32x4.max"),
	[0xED] = op_none("f32x4.pmin"),
	[0xEE] = op_none("f32x4.pmax"),
	-- f64x2 ops
	[0xEF] = op_none("f64x2.ceil"),
	[0xF0] = op_none("f64x2.floor"),
	[0xF1] = op_none("f64x2.trunc"),
	[0xF2] = op_none("f64x2.nearest"),
	[0xF3] = op_none("f64x2.abs"),
	[0xF4] = op_none("f64x2.neg"),
	[0xF5] = op_none("f64x2.sqrt"),
	[0xF6] = op_none("f64x2.add"),
	[0xF7] = op_none("f64x2.sub"),
	[0xF8] = op_none("i32x4.trunc_sat_f32x4_s"),
	[0xF9] = op_none("i32x4.trunc_sat_f32x4_u"),
	[0xFA] = op_none("f32x4.convert_i32x4_s"),
	[0xFB] = op_none("f32x4.convert_i32x4_u"),
	[0xFC] = op_none("i32x4.trunc_sat_f64x2_s_zero"),
	[0xFD] = op_none("i32x4.trunc_sat_f64x2_u_zero"),
	[0xFE] = op_none("f64x2.convert_low_i32x4_s"),
	[0xFF] = op_none("f64x2.convert_low_i32x4_u"),
	-- Relaxed SIMD
	[0x100] = op_none("i8x16.relaxed_swizzle"),
	[0x101] = op_none("i32x4.relaxed_trunc_f32x4_s"),
	[0x102] = op_none("i32x4.relaxed_trunc_f32x4_u"),
	[0x103] = op_none("i32x4.relaxed_trunc_f64x2_s_zero"),
	[0x104] = op_none("i32x4.relaxed_trunc_f64x2_u_zero"),
	[0x105] = op_none("f32x4.relaxed_madd"),
	[0x106] = op_none("f32x4.relaxed_nmadd"),
	[0x107] = op_none("f64x2.relaxed_madd"),
	[0x108] = op_none("f64x2.relaxed_nmadd"),
	[0x109] = op_none("i8x16.relaxed_laneselect"),
	[0x10A] = op_none("i16x8.relaxed_laneselect"),
	[0x10B] = op_none("i32x4.relaxed_laneselect"),
	[0x10C] = op_none("i64x2.relaxed_laneselect"),
	[0x10D] = op_none("f32x4.relaxed_min"),
	[0x10E] = op_none("f32x4.relaxed_max"),
	[0x10F] = op_none("f64x2.relaxed_min"),
	[0x110] = op_none("f64x2.relaxed_max"),
	[0x111] = op_none("i16x8.relaxed_q15mulr_s"),
	[0x112] = op_none("i16x8.relaxed_dot_i8x16_i7x16_s"),
	[0x113] = op_none("i32x4.relaxed_dot_i8x16_i7x16_add_s"),
}

OPCODES[opcodes.PREFIX_SIMD] = function(bin)
	local sub_op = bin:read_u32LEB()
	local handler = FD_OPCODES[sub_op]
	if not handler then
		error(string.format("Unknown 0xFD (SIMD) sub-opcode: 0x%02X (%d)", sub_op, sub_op))
	end
	local insn = handler(bin)
	insn.prefix = 0xFD
	insn.sub_op = sub_op
	return insn
end

-- 0xFE Prefix: Atomic Instructions (Threads)
local FE_OPCODES = {
	[0x00] = op_mem("memory.atomic.notify"),
	[0x01] = op_mem("memory.atomic.wait32"),
	[0x02] = op_mem("memory.atomic.wait64"),
	[0x03] = function(bin)
		bin:read_byte()
		local insn = { opcode = "atomic.fence", operands = "" }
		return setmetatable(insn, Instruction)
	end,
	-- loads
	[0x10] = op_mem("i32.atomic.load"),
	[0x11] = op_mem("i64.atomic.load"),
	[0x12] = op_mem("i32.atomic.load8_u"),
	[0x13] = op_mem("i32.atomic.load16_u"),
	[0x14] = op_mem("i64.atomic.load8_u"),
	[0x15] = op_mem("i64.atomic.load16_u"),
	[0x16] = op_mem("i64.atomic.load32_u"),
	-- stores
	[0x17] = op_mem("i32.atomic.store"),
	[0x18] = op_mem("i64.atomic.store"),
	[0x19] = op_mem("i32.atomic.store8"),
	[0x1A] = op_mem("i32.atomic.store16"),
	[0x1B] = op_mem("i64.atomic.store8"),
	[0x1C] = op_mem("i64.atomic.store16"),
	[0x1D] = op_mem("i64.atomic.store32"),
	-- rmw.add
	[0x1E] = op_mem("i32.atomic.rmw.add"),
	[0x1F] = op_mem("i64.atomic.rmw.add"),
	[0x20] = op_mem("i32.atomic.rmw8.add_u"),
	[0x21] = op_mem("i32.atomic.rmw16.add_u"),
	[0x22] = op_mem("i64.atomic.rmw8.add_u"),
	[0x23] = op_mem("i64.atomic.rmw16.add_u"),
	[0x24] = op_mem("i64.atomic.rmw32.add_u"),
	-- rmw.sub
	[0x25] = op_mem("i32.atomic.rmw.sub"),
	[0x26] = op_mem("i64.atomic.rmw.sub"),
	[0x27] = op_mem("i32.atomic.rmw8.sub_u"),
	[0x28] = op_mem("i32.atomic.rmw16.sub_u"),
	[0x29] = op_mem("i64.atomic.rmw8.sub_u"),
	[0x2A] = op_mem("i64.atomic.rmw16.sub_u"),
	[0x2B] = op_mem("i64.atomic.rmw32.sub_u"),
	-- rmw.and
	[0x2C] = op_mem("i32.atomic.rmw.and"),
	[0x2D] = op_mem("i64.atomic.rmw.and"),
	[0x2E] = op_mem("i32.atomic.rmw8.and_u"),
	[0x2F] = op_mem("i32.atomic.rmw16.and_u"),
	[0x30] = op_mem("i64.atomic.rmw8.and_u"),
	[0x31] = op_mem("i64.atomic.rmw16.and_u"),
	[0x32] = op_mem("i64.atomic.rmw32.and_u"),
	-- rmw.or
	[0x33] = op_mem("i32.atomic.rmw.or"),
	[0x34] = op_mem("i64.atomic.rmw.or"),
	[0x35] = op_mem("i32.atomic.rmw8.or_u"),
	[0x36] = op_mem("i32.atomic.rmw16.or_u"),
	[0x37] = op_mem("i64.atomic.rmw8.or_u"),
	[0x38] = op_mem("i64.atomic.rmw16.or_u"),
	[0x39] = op_mem("i64.atomic.rmw32.or_u"),
	-- rmw.xor
	[0x3A] = op_mem("i32.atomic.rmw.xor"),
	[0x3B] = op_mem("i64.atomic.rmw.xor"),
	[0x3C] = op_mem("i32.atomic.rmw8.xor_u"),
	[0x3D] = op_mem("i32.atomic.rmw16.xor_u"),
	[0x3E] = op_mem("i64.atomic.rmw8.xor_u"),
	[0x3F] = op_mem("i64.atomic.rmw16.xor_u"),
	[0x40] = op_mem("i64.atomic.rmw32.xor_u"),
	-- rmw.xchg
	[0x41] = op_mem("i32.atomic.rmw.xchg"),
	[0x42] = op_mem("i64.atomic.rmw.xchg"),
	[0x43] = op_mem("i32.atomic.rmw8.xchg_u"),
	[0x44] = op_mem("i32.atomic.rmw16.xchg_u"),
	[0x45] = op_mem("i64.atomic.rmw8.xchg_u"),
	[0x46] = op_mem("i64.atomic.rmw16.xchg_u"),
	[0x47] = op_mem("i64.atomic.rmw32.xchg_u"),
	-- rmw.cmpxchg
	[0x48] = op_mem("i32.atomic.rmw.cmpxchg"),
	[0x49] = op_mem("i64.atomic.rmw.cmpxchg"),
	[0x4A] = op_mem("i32.atomic.rmw8.cmpxchg_u"),
	[0x4B] = op_mem("i32.atomic.rmw16.cmpxchg_u"),
	[0x4C] = op_mem("i64.atomic.rmw8.cmpxchg_u"),
	[0x4D] = op_mem("i64.atomic.rmw16.cmpxchg_u"),
	[0x4E] = op_mem("i64.atomic.rmw32.cmpxchg_u"),
}

OPCODES[opcodes.PREFIX_THREADS] = function(bin)
	local sub_op = bin:read_u32LEB()
	local handler = FE_OPCODES[sub_op]
	if not handler then
		error(string.format("Unknown 0xFE (Atomic) sub-opcode: 0x%02X (%d)", sub_op, sub_op))
	end
	local insn = handler(bin)
	insn.prefix = 0xFE
	insn.sub_op = sub_op
	return insn
end

--- Convert an input (either a binary string or a table of byte integers) into a binary string.
--- @param code string|integer[]
--- @return string
local function normalize_bytecode(code)
	if type(code) == "string" then
		return code
	elseif type(code) == "table" then
		local chunks = {}
		for i = 1, #code, 2048 do
			local chunk_end = math.min(i + 2047, #code)
			chunks[#chunks + 1] = string.char(table.unpack(code, i, chunk_end))
		end
		return table.concat(chunks)
	else
		error("Expected string or table of byte integers, got " .. type(code))
	end
end

--- Disassemble WebAssembly bytecode into an array of instruction tables.
--- Each instruction includes opcode, operands, raw_bytes, and pc offset.
--- @param code string|integer[] Raw bytecode string or array of byte integers.
--- @param base_offset? integer Optional starting offset for instruction position tracking.
--- @return table[] instructions Array of decoded instruction tables.
function WASM_disassembler.disasm(code, base_offset)
	local raw_data = normalize_bytecode(code)
	local bin = Binary:new(raw_data)
	local base = base_offset or 0
	local instructions = {}

	while not bin:is_EOF() do
		local start_pos = bin.cursor
		local offset = base + start_pos
		local opcode = bin:read_byte()
		local handler = OPCODES[opcode]

		if not handler then
			error(
				string.format(
					"Unknown or unsupported opcode: 0x%02X (%d) at offset 0x%X (%d)",
					opcode,
					opcode,
					offset,
					offset
				)
			)
		end

		local insn = handler(bin)
		local end_pos = bin.cursor
		insn.op = opcode
		insn.pc = offset
		insn.raw_bytes = bin.data:sub(start_pos, end_pos - 1)
		instructions[#instructions + 1] = insn
	end

	return instructions
end

--- Disassemble bytecode and format as indented WebAssembly text (WAT format).
--- @param code string|integer[] Raw bytecode or byte array.
--- @param initial_indent? integer Starting indentation level.
--- @return string Formatted assembly string.
function WASM_disassembler.disasm_to_string(code, initial_indent)
	local instructions = WASM_disassembler.disasm(code)
	local lines = {}
	local indent = initial_indent or 0

	for _, insn in ipairs(instructions) do
		if insn.opcode == "end" or insn.opcode == "else" or insn.opcode == "catch" or insn.opcode == "catch_all" then
			indent = math.max(0, indent - 1)
		end

		local indent_str = string.rep("  ", indent)
		lines[#lines + 1] = indent_str .. insn:to_string()

		if
			insn.opcode == "block"
			or insn.opcode == "loop"
			or insn.opcode == "if"
			or insn.opcode == "try"
			or insn.opcode == "else"
			or insn.opcode == "catch"
			or insn.opcode == "catch_all"
		then
			indent = indent + 1
		end
	end

	return table.concat(lines, "\n")
end

--- Disassemble a function code entry decoded by decoder.lua.
--- @param code_entry table A code entry from module.sections.code_section.code[i].
--- @return table[] instructions Decoded instruction tables.
function WASM_disassembler.disasm_function(code_entry)
	assert(code_entry, "Invalid code_entry: expected table")
	local body = code_entry.body
	if not body and code_entry.source and code_entry.code_start and code_entry.body_size then
		body = code_entry.source:sub(code_entry.code_start, code_entry.code_start + code_entry.body_size - 1)
	end
	assert(body, "Invalid code_entry: expected .body or lazy source metadata")
	return WASM_disassembler.disasm(body, code_entry.code_start or 0)
end

local valtype_to_string = opcodes.valtype_to_string

--- Decode the custom 'name' section if present in the module.
--- @param custom_sec table|nil Custom section containing name data.
--- @return table<integer, string> func_names Function index to name mapping.
local function parse_name_section(custom_sec)
	local func_names = {}
	if not custom_sec or not custom_sec.data or #custom_sec.data == 0 then
		return func_names
	end
	local bin = Binary:new(custom_sec.data)
	while not bin:is_EOF() do
		local sub_id = bin:read_byte()
		local sub_size = bin:read_u32LEB()
		local sub = bin:sub_reader(sub_size)
		if sub_id == 1 then
			local count = sub:read_u32LEB()
			for _ = 1, count do
				local f_idx = sub:read_u32LEB()
				local f_name = sub:read_name()
				func_names[f_idx] = f_name
			end
		end
	end
	return func_names
end

--- Helper to ensure we have a decoded module object.
--- @param mod_or_path table|string
--- @return table
local function ensure_module(mod_or_path)
	if type(mod_or_path) == "string" then
		local decoder = require("decoder")
		return decoder.decode_file(mod_or_path)
	elseif type(mod_or_path) == "table" and mod_or_path.sections then
		return mod_or_path
	else
		error("Expected decoded module table or file path string, got " .. type(mod_or_path))
	end
end

local function escape_bytes_for_wat(bytes_str)
	local parts = {}
	for i = 1, #bytes_str do
		local b = string.byte(bytes_str, i)
		if b == 34 then
			parts[#parts + 1] = '\\"'
		elseif b == 92 then
			parts[#parts + 1] = "\\\\"
		elseif b >= 32 and b <= 126 then
			parts[#parts + 1] = string.char(b)
		else
			parts[#parts + 1] = string.format("\\%02x", b)
		end
	end
	return table.concat(parts)
end

--- Disassemble an entire decoded WebAssembly module into complete, valid WAT text.
--- @param mod_or_path table|string Decoded module or path to .wasm file.
--- @return string wat Complete WAT module text.
function WASM_disassembler.disasm_module(mod_or_path)
	local mod = ensure_module(mod_or_path)
	local lines = { "(module" }

	-- Parse custom 'name' section if present
	local name_sec = mod:get_custom_section("name")
	local func_names = parse_name_section(name_sec)

	-- Map export function names
	local export_sec = mod:get_section("export_section")
	if export_sec and export_sec.exports then
		for _, exp in ipairs(export_sec.exports) do
			if exp.desc == 0 and not func_names[exp.index] then
				func_names[exp.index] = exp.name
			end
		end
	end

	-- 1. Types
	local type_sec = mod:get_section("type_section")
	if type_sec and type_sec.types then
		for i, t in ipairs(type_sec.types) do
			local params = {}
			for _, p in ipairs(t.params or {}) do
				params[#params + 1] = valtype_to_string(p)
			end
			local results = {}
			for _, r in ipairs(t.results or {}) do
				results[#results + 1] = valtype_to_string(r)
			end

			local param_str = #params > 0 and (" (param " .. table.concat(params, " ") .. ")") or ""
			local result_str = #results > 0 and (" (result " .. table.concat(results, " ") .. ")") or ""
			lines[#lines + 1] = string.format("  (type (;%d;) (func%s%s))", i - 1, param_str, result_str)
		end
	end

	-- 2. Imports
	local import_sec = mod:get_section("import_section")
	local imported_func_count = 0
	if import_sec and import_sec.imports then
		for _, imp in ipairs(import_sec.imports) do
			if imp.desc == 0 then -- DESC_FUNC
				local f_idx = imported_func_count
				imported_func_count = imported_func_count + 1
				local name_display = func_names[f_idx] and (" $" .. func_names[f_idx]) or ""
				lines[#lines + 1] = string.format(
					'  (import "%s" "%s" (func%s (type %d)))',
					imp.module,
					imp.field,
					name_display,
					imp.index - 1
				)
			elseif imp.desc == 1 then -- DESC_TABLE
				lines[#lines + 1] = string.format(
					'  (import "%s" "%s" (table %d%s %s))',
					imp.module,
					imp.field,
					imp.min,
					imp.max and (" " .. imp.max) or "",
					valtype_to_string(imp.type)
				)
			elseif imp.desc == 2 then -- DESC_MEM
				lines[#lines + 1] = string.format(
					'  (import "%s" "%s" (memory %d%s))',
					imp.module,
					imp.field,
					imp.min,
					imp.max and (" " .. imp.max) or ""
				)
			elseif imp.desc == 3 then -- DESC_GLOBAL
				local type_str = valtype_to_string(imp.type)
				local glob_str = imp.mutable and ("(mut " .. type_str .. ")") or type_str
				lines[#lines + 1] = string.format('  (import "%s" "%s" (global %s))', imp.module, imp.field, glob_str)
			end
		end
	end

	-- 3. Tables
	local table_sec = mod:get_section("table_section")
	if table_sec and table_sec.tables then
		for i, tbl in ipairs(table_sec.tables) do
			local max_str = tbl.max and (" " .. tbl.max) or ""
			lines[#lines + 1] =
				string.format("  (table (;%d;) %d%s %s)", i - 1, tbl.min, max_str, valtype_to_string(tbl.type))
		end
	end

	-- 4. Memories
	local mem_sec = mod:get_section("mem_section")
	if mem_sec and mem_sec.memory then
		for i, m in ipairs(mem_sec.memory) do
			local max_str = m.max and (" " .. m.max) or ""
			lines[#lines + 1] = string.format("  (memory (;%d;) %d%s)", i - 1, m.min, max_str)
		end
	end

	-- 5. Globals
	local glob_sec = mod:get_section("global_section")
	if glob_sec and glob_sec.globals then
		for i, g in ipairs(glob_sec.globals) do
			if g.op then
				local type_str = valtype_to_string(g.type)
				local mut_str = g.mutable and ("(mut " .. type_str .. ")") or type_str
				local init_expr
				if g.op == opcodes.INSTR_I32_CONST or g.op == 0x41 then
					init_expr = string.format("(i32.const %s)", tostring(g.value or 0))
				elseif g.op == opcodes.INSTR_I64_CONST or g.op == 0x42 then
					init_expr = string.format("(i64.const %s)", tostring(g.value or 0))
				elseif g.op == opcodes.INSTR_F32_CONST or g.op == 0x43 then
					init_expr = string.format("(f32.const %s)", tostring(g.value or 0))
				elseif g.op == opcodes.INSTR_F64_CONST or g.op == 0x44 then
					init_expr = string.format("(f64.const %s)", tostring(g.value or 0))
				elseif g.op == opcodes.INSTR_GLOBAL_GET or g.op == 0x23 then
					init_expr = string.format("(global.get %d)", (g.global_index and g.global_index - 1) or 0)
				elseif g.op == opcodes.INSTR_REF_NULL or g.op == 0xD0 then
					local ht_name = opcodes.heap_type_name(g.ref_type or 0x70)
					if ht_name == "externref" then
						ht_name = "extern"
					elseif ht_name == "funcref" then
						ht_name = "func"
					end
					init_expr = string.format("(ref.null %s)", ht_name)
				elseif g.op == opcodes.INSTR_REF_FUNC or g.op == 0xD2 then
					init_expr = string.format("(ref.func %d)", (g.function_index and g.function_index - 1) or 0)
				else
					local init_val = g.value ~= nil and tostring(g.value) or "0"
					init_expr = string.format("(%s.const %s)", type_str, init_val)
				end
				lines[#lines + 1] = string.format("  (global (;%d;) %s %s)", i - 1, mut_str, init_expr)
			end
		end
	end

	-- 6. Exports
	if export_sec and export_sec.exports then
		local desc_names = { [0] = "func", [1] = "table", [2] = "memory", [3] = "global" }
		for _, exp in ipairs(export_sec.exports) do
			local dname = desc_names[exp.desc] or "unknown"
			lines[#lines + 1] = string.format('  (export "%s" (%s %d))', exp.name, dname, exp.index)
		end
	end

	-- 7. Functions
	local func_sec = mod:get_section("func_section")
	local code_sec = mod:get_section("code_section")
	if func_sec and code_sec and code_sec.code then
		for i, code_entry in ipairs(code_sec.code) do
			local func_idx = imported_func_count + (i - 1)
			local type_idx = func_sec.indices[i]
			local name_display = func_names[func_idx] and (" $" .. func_names[func_idx]) or ""

			lines[#lines + 1] = string.format("  (func (;%d;)%s (type %d)", func_idx, name_display, type_idx or 0)

			-- Locals
			if code_entry.locals and #code_entry.locals > 0 then
				local local_strs = {}
				for _, loc in ipairs(code_entry.locals) do
					for _ = 1, loc.count do
						local_strs[#local_strs + 1] = valtype_to_string(loc.type)
					end
				end
				if #local_strs > 0 then
					lines[#lines + 1] = "    (local " .. table.concat(local_strs, " ") .. ")"
				end
			end

			-- Disassemble function instructions
			local insns = WASM_disassembler.disasm_function(code_entry)
			local indent = 2
			for j, insn in ipairs(insns) do
				-- In binary format, function ends with 0x0B (end). In WAT, the closing ')' closes the func.
				if j == #insns and insn.opcode == "end" then
					break
				end
				if insn.opcode == "end" or insn.opcode == "else" then
					indent = math.max(2, indent - 1)
				end
				lines[#lines + 1] = string.rep("  ", indent) .. insn:to_string()
				if insn.opcode == "block" or insn.opcode == "loop" or insn.opcode == "if" or insn.opcode == "else" then
					indent = indent + 1
				end
			end

			lines[#lines + 1] = "  )"
		end
	end

	-- 8. Elements
	local elem_sec = mod:get_section("element_section")
	if elem_sec and elem_sec.elements then
		for i, el in ipairs(elem_sec.elements) do
			local offset_str
			if (el.flag & 1) == 0 then -- active
				local off_val = type(el.offset) == "number" and el.offset or (el.offset and el.offset.value) or 0
				offset_str = string.format("(i32.const %d)", off_val)
			end
			local table_str = (el.table_index and el.table_index > 0) and string.format("(table %d) ", el.table_index)
				or ""
			local func_strs = {}
			if el.functions then
				for _, f_idx in ipairs(el.functions) do
					func_strs[#func_strs + 1] = tostring(f_idx - 1)
				end
			end
			if offset_str then
				lines[#lines + 1] = string.format(
					"  (elem (;%d;) %s%s func %s)",
					i - 1,
					table_str,
					offset_str,
					table.concat(func_strs, " ")
				)
			else
				lines[#lines + 1] = string.format("  (elem (;%d;) func %s)", i - 1, table.concat(func_strs, " "))
			end
		end
	end

	-- 9. Data
	local data_sec = mod:get_section("data_section")
	if data_sec and data_sec.entries then
		for i, d in ipairs(data_sec.entries) do
			local escaped = escape_bytes_for_wat(d.data or "")
			if (d.flag & 1) == 1 then -- passive
				lines[#lines + 1] = string.format('  (data (;%d;) "%s")', i - 1, escaped)
			else -- active
				local mem_str = (d.memory_index and d.memory_index > 0)
						and string.format("(memory %d) ", d.memory_index)
					or ""
				local off_val = type(d.offset) == "number" and d.offset or (d.offset and d.offset.value) or 0
				lines[#lines + 1] =
					string.format('  (data (;%d;) %s(i32.const %d) "%s")', i - 1, mem_str, off_val, escaped)
			end
		end
	end

	lines[#lines + 1] = ")"
	return table.concat(lines, "\n")
end

--- Generate an objdump-style disassembly dump with byte offsets and hex columns.
--- @param mod_or_path table|string Decoded module or path to .wasm file.
--- @return string dump Text output resembling wasm-objdump -d.
function WASM_disassembler.dump(mod_or_path)
	local mod = ensure_module(mod_or_path)
	local lines = {}
	lines[#lines + 1] = string.format("Disassembly of module (version %d):", mod.version)

	local func_sec = mod:get_section("func_section")
	local code_sec = mod:get_section("code_section")
	local export_sec = mod:get_section("export_section")

	local export_names = {}
	if export_sec and export_sec.exports then
		for _, exp in ipairs(export_sec.exports) do
			if exp.desc == 0 then
				export_names[exp.index] = exp.name
			end
		end
	end

	local import_sec = mod:get_section("import_section")
	local imported_func_count = 0
	if import_sec and import_sec.imports then
		for _, imp in ipairs(import_sec.imports) do
			if imp.desc == 0 then
				imported_func_count = imported_func_count + 1
			end
		end
	end

	if code_sec and code_sec.code then
		for i, code_entry in ipairs(code_sec.code) do
			local func_idx = imported_func_count + (i - 1)
			local type_idx = func_sec and func_sec.indices[i] or "?"
			local exp_name = export_names[func_idx] and (" <" .. export_names[func_idx] .. ">") or ""

			lines[#lines + 1] = string.format(
				"\n%06x func[%d]%s (type %s, size %d):",
				code_entry.code_start or 0,
				func_idx,
				exp_name,
				tostring(type_idx),
				code_entry.size
			)

			local insns = WASM_disassembler.disasm_function(code_entry)
			for _, insn in ipairs(insns) do
				lines[#lines + 1] = insn:to_dump_line()
			end
		end
	end

	return table.concat(lines, "\n")
end

-- Run self-test if executed directly as the main script
if pcall(debug.getlocal, 4, 1) == false then
	local test_bytes = "\x20\x00\x20\x01\x41\x20\x10\xc9\x01\x45\x0b"
	print("Disassembling test bytecode:")
	local insns = WASM_disassembler.disasm(test_bytes)
	for i, insn in ipairs(insns) do
		print(string.format("  [%02d] (0x%02X) %-15s %s", i, insn.op, insn.opcode, tostring(insn.operands or "")))
	end

	print("\nObjdump-style dump:")
	for _, insn in ipairs(insns) do
		print(insn:to_dump_line())
	end

	print("\nFormatted WAT representation:")
	print(WASM_disassembler.disasm_to_string(test_bytes))
end

return WASM_disassembler
