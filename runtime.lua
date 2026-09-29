--- WebAssembly Runtime & Execution Engine for lwasm
--- Implements a standards-compliant Wasm interpreter, memory manager,
--- store, table dispatcher, host function binding, and execution virtual machine.
---@diagnostic disable: undefined-global

local decoder = require("decoder")
local disassembler = require("disassembler")
local opcodes = require("opcodes")

local Runtime = {}
Runtime.__index = Runtime

local PAGE_SIZE = 65536
local MAX_PAGES = 65536

--------------------------------------------------------------------------------
-- Bitwise & Numeric Helpers
--------------------------------------------------------------------------------

local function to_i32(v)
	v = v & 0xFFFFFFFF
	if (v & 0x80000000) ~= 0 then
		return v | (~0 << 31)
	end
	return v
end

local function to_u32(v)
	return v & 0xFFFFFFFF
end

local function clz32(v)
	v = v & 0xFFFFFFFF
	if v == 0 then
		return 32
	end
	local n = 0
	if (v & 0xFFFF0000) == 0 then
		n = n + 16
		v = v << 16
	end
	if (v & 0xFF000000) == 0 then
		n = n + 8
		v = v << 8
	end
	if (v & 0xF0000000) == 0 then
		n = n + 4
		v = v << 4
	end
	if (v & 0xC0000000) == 0 then
		n = n + 2
		v = v << 2
	end
	if (v & 0x80000000) == 0 then
		n = n + 1
	end
	return n
end

local function ctz32(v)
	v = v & 0xFFFFFFFF
	if v == 0 then
		return 32
	end
	local n = 0
	if (v & 0x0000FFFF) == 0 then
		n = n + 16
		v = v >> 16
	end
	if (v & 0x000000FF) == 0 then
		n = n + 8
		v = v >> 8
	end
	if (v & 0x0000000F) == 0 then
		n = n + 4
		v = v >> 4
	end
	if (v & 0x00000003) == 0 then
		n = n + 2
		v = v >> 2
	end
	if (v & 0x00000001) == 0 then
		n = n + 1
	end
	return n
end

local function popcnt32(v)
	local count = 0
	v = v & 0xFFFFFFFF
	while v ~= 0 do
		v = v & (v - 1)
		count = count + 1
	end
	return count
end

local function clz64(v)
	if v == 0 then
		return 64
	end
	local hi = (v >> 32) & 0xFFFFFFFF
	if hi ~= 0 then
		return clz32(hi)
	else
		return 32 + clz32(v & 0xFFFFFFFF)
	end
end

local function ctz64(v)
	if v == 0 then
		return 64
	end
	local lo = v & 0xFFFFFFFF
	if lo ~= 0 then
		return ctz32(lo)
	else
		return 32 + ctz32((v >> 32) & 0xFFFFFFFF)
	end
end

local function popcnt64(v)
	local count = 0
	while v ~= 0 do
		v = v & (v - 1)
		count = count + 1
	end
	return count
end

local function rotl32(v, k)
	v = v & 0xFFFFFFFF
	k = k & 31
	return to_i32(((v << k) | (v >> (32 - k))) & 0xFFFFFFFF)
end

local function rotr32(v, k)
	v = v & 0xFFFFFFFF
	k = k & 31
	return to_i32(((v >> k) | (v << (32 - k))) & 0xFFFFFFFF)
end

local function rotl64(v, k)
	k = k & 63
	if k == 0 then
		return v
	end
	return (v << k) | ((v >> (64 - k)) & ((1 << k) - 1))
end

local function rotr64(v, k)
	k = k & 63
	if k == 0 then
		return v
	end
	return ((v >> k) & ((1 << (64 - k)) - 1)) | (v << (64 - k))
end

local function div_s32(a, b)
	if b == 0 then
		error("integer divide by zero")
	end
	a = to_i32(a)
	b = to_i32(b)
	if a == -2147483648 and b == -1 then
		error("integer overflow")
	end
	local q = a // b
	if (a < 0) ~= (b < 0) and (a % b) ~= 0 then
		q = q + 1
	end
	return to_i32(q)
end

local function rem_s32(a, b)
	if b == 0 then
		error("integer divide by zero")
	end
	a = to_i32(a)
	b = to_i32(b)
	return to_i32(a - div_s32(a, b) * b)
end

local function div_u32(a, b)
	a = a & 0xFFFFFFFF
	b = b & 0xFFFFFFFF
	if b == 0 then
		error("integer divide by zero")
	end
	return to_i32(a // b)
end

local function rem_u32(a, b)
	a = a & 0xFFFFFFFF
	b = b & 0xFFFFFFFF
	if b == 0 then
		error("integer divide by zero")
	end
	return to_i32(a % b)
end

local function ucmp64(a, b)
	if a == b then
		return 0
	end
	if (a >= 0 and b >= 0) or (a < 0 and b < 0) then
		return a < b and -1 or 1
	else
		return a < 0 and 1 or -1
	end
end

local function div_u64(a, b)
	if b == 0 then
		error("integer divide by zero")
	end
	if a >= 0 and b > 0 then
		return a // b
	end
	local cmp = ucmp64(a, b)
	if cmp < 0 then
		return 0
	end
	if cmp == 0 then
		return 1
	end
	local q = 0
	local r = 0
	for i = 63, 0, -1 do
		r = (r << 1) | ((a >> i) & 1)
		if ucmp64(r, b) >= 0 then
			r = r - b
			q = q | (1 << i)
		end
	end
	return q
end

local function rem_u64(a, b)
	if b == 0 then
		error("integer divide by zero")
	end
	if a >= 0 and b > 0 then
		return a % b
	end
	return a - div_u64(a, b) * b
end

local function div_s64(a, b)
	if b == 0 then
		error("integer divide by zero")
	end
	if a == -9223372036854775808 and b == -1 then
		error("integer overflow")
	end
	local q = a // b
	if (a < 0) ~= (b < 0) and (a % b) ~= 0 then
		q = q + 1
	end
	return q
end

local function rem_s64(a, b)
	if b == 0 then
		error("integer divide by zero")
	end
	return a - div_s64(a, b) * b
end

local function f32_to_bits(v)
	return string.unpack("<i4", string.pack("<f", v))
end

local function bits_to_f32(i)
	return string.unpack("<f", string.pack("<i4", i))
end

local function f64_to_bits(v)
	return string.unpack("<i8", string.pack("<d", v))
end

local function bits_to_f64(i)
	return string.unpack("<d", string.pack("<i8", i))
end

-- Convert signed i64 to its unsigned float interpretation
-- Lua integers are 2's complement 64-bit; negative values are > 2^63 when unsigned.
local function to_u64_float(v)
	if v >= 0 then
		return v * 1.0
	end
	-- v is negative = unsigned value is v + 2^64
	return (v + 18446744073709551616.0)
end

--------------------------------------------------------------------------------
-- GC Type Matching
--------------------------------------------------------------------------------

local function gc_type_matches(val, heap_type)
	if val == nil then
		return true
	end
	if heap_type == "i31" or heap_type == 0x6C then
		return type(val) == "table" and val.__i31 == true
	elseif heap_type == "struct" or heap_type == 0x6B then
		return type(val) == "table" and val.__struct == true
	elseif heap_type == "array" or heap_type == 0x6A then
		return type(val) == "table" and val.__array == true
	elseif heap_type == "func" or heap_type == 0x70 then
		return type(val) == "table" and (val.is_host ~= nil or val.instructions ~= nil or val.func_index ~= nil)
	elseif heap_type == "eq" or heap_type == 0x6D then
		return type(val) == "table" and (val.__i31 or val.__struct or val.__array)
	elseif heap_type == "any" or heap_type == 0x6E then
		return true
	elseif type(heap_type) == "number" and heap_type >= 0 then
		if type(val) == "table" and val.type_index ~= nil then
			return val.type_index == heap_type
		end
	end
	return false
end

--------------------------------------------------------------------------------
-- SIMD v128 Helpers
--------------------------------------------------------------------------------

local function v128_zero()
	return "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
end

local function v128_from_bytes(b)
	if type(b) == "string" and #b == 16 then
		return b
	end
	if type(b) == "table" then
		local s = {}
		for i = 1, 16 do
			s[i] = string.char((b[i] or 0) & 0xFF)
		end
		return table.concat(s)
	end
	return v128_zero()
end

local function v128_and(a, b)
	local a1, a2 = string.unpack("<I8<I8", a)
	local b1, b2 = string.unpack("<I8<I8", b)
	return string.pack("<I8<I8", a1 & b1, a2 & b2)
end

local function v128_or(a, b)
	local a1, a2 = string.unpack("<I8<I8", a)
	local b1, b2 = string.unpack("<I8<I8", b)
	return string.pack("<I8<I8", a1 | b1, a2 | b2)
end

local function v128_xor(a, b)
	local a1, a2 = string.unpack("<I8<I8", a)
	local b1, b2 = string.unpack("<I8<I8", b)
	return string.pack("<I8<I8", a1 ~ b1, a2 ~ b2)
end

local function v128_not(a)
	local a1, a2 = string.unpack("<I8<I8", a)
	return string.pack("<I8<I8", ~a1, ~a2)
end

local function v128_andnot(a, b)
	local a1, a2 = string.unpack("<I8<I8", a)
	local b1, b2 = string.unpack("<I8<I8", b)
	return string.pack("<I8<I8", a1 & ~b1, a2 & ~b2)
end

local function v128_bitselect(v1, v2, c)
	local a1, a2 = string.unpack("<I8<I8", v1)
	local b1, b2 = string.unpack("<I8<I8", v2)
	local c1, c2 = string.unpack("<I8<I8", c)
	return string.pack("<I8<I8", (a1 & c1) | (b1 & ~c1), (a2 & c2) | (b2 & ~c2))
end

local function v128_any_true(a)
	local a1, a2 = string.unpack("<I8<I8", a)
	return (a1 ~= 0 or a2 ~= 0) and 1 or 0
end

-- i8x16
local function i8x16_splat(x)
	return string.char(x & 0xFF):rep(16)
end
local function i8x16_extract_lane_u(v, lane)
	return string.byte(v, lane + 1)
end
local function i8x16_extract_lane_s(v, lane)
	local b = string.byte(v, lane + 1)
	return (b & 0x80) ~= 0 and (b | (~0 << 7)) or b
end
local function i8x16_replace_lane(v, lane, val)
	local s = { string.byte(v, 1, 16) }
	s[lane + 1] = val & 0xFF
	local t = {}
	for i = 1, 16 do
		t[i] = string.char(s[i])
	end
	return table.concat(t)
end
local function i8x16_binop(va, vb, fn)
	local a = { string.byte(va, 1, 16) }
	local b = { string.byte(vb, 1, 16) }
	local t = {}
	for i = 1, 16 do
		t[i] = string.char(fn(a[i], b[i]) & 0xFF)
	end
	return table.concat(t)
end
local function i8x16_bitmask(v)
	local mask = 0
	for i = 1, 16 do
		if string.byte(v, i) >= 128 then
			mask = mask | (1 << (i - 1))
		end
	end
	return mask
end
local function i8x16_all_true(v)
	for i = 1, 16 do
		if string.byte(v, i) == 0 then
			return 0
		end
	end
	return 1
end

-- i16x8
local function i16x8_splat(x)
	return string.pack("<I2", x & 0xFFFF):rep(8)
end
local function i16x8_extract_lane_s(v, lane)
	local lanes = { string.unpack("<i2<i2<i2<i2<i2<i2<i2<i2", v) }
	return lanes[lane + 1]
end
local function i16x8_extract_lane_u(v, lane)
	local lanes = { string.unpack("<I2<I2<I2<I2<I2<I2<I2<I2", v) }
	return lanes[lane + 1]
end
local function i16x8_replace_lane(v, lane, val)
	local lanes = { string.unpack("<I2<I2<I2<I2<I2<I2<I2<I2", v) }
	lanes[lane + 1] = val & 0xFFFF
	return string.pack("<I2<I2<I2<I2<I2<I2<I2<I2", table.unpack(lanes, 1, 8))
end
local function i16x8_binop(va, vb, fn)
	local a = { string.unpack("<i2<i2<i2<i2<i2<i2<i2<i2", va) }
	local b = { string.unpack("<i2<i2<i2<i2<i2<i2<i2<i2", vb) }
	local t = {}
	for i = 1, 8 do
		t[i] = fn(a[i], b[i]) & 0xFFFF
	end
	return string.pack("<I2<I2<I2<I2<I2<I2<I2<I2", table.unpack(t, 1, 8))
end
local function i16x8_bitmask(v)
	local l = { string.unpack("<i2<i2<i2<i2<i2<i2<i2<i2", v) }
	local mask = 0
	for i = 1, 8 do
		if l[i] < 0 then
			mask = mask | (1 << (i - 1))
		end
	end
	return mask
end
local function i16x8_all_true(v)
	local l = { string.unpack("<I2<I2<I2<I2<I2<I2<I2<I2", v) }
	for i = 1, 8 do
		if l[i] == 0 then
			return 0
		end
	end
	return 1
end

-- i32x4
local function i32x4_splat(x)
	return string.pack("<I4", x & 0xFFFFFFFF):rep(4)
end
local function i32x4_extract_lane(v, lane)
	local lanes = { string.unpack("<i4<i4<i4<i4", v) }
	return lanes[lane + 1]
end
local function i32x4_replace_lane(v, lane, val)
	local lanes = { string.unpack("<i4<i4<i4<i4", v) }
	lanes[lane + 1] = to_i32(val)
	return string.pack("<i4<i4<i4<i4", table.unpack(lanes, 1, 4))
end
local function i32x4_binop(va, vb, fn)
	local a = { string.unpack("<i4<i4<i4<i4", va) }
	local b = { string.unpack("<i4<i4<i4<i4", vb) }
	local t = {}
	for i = 1, 4 do
		t[i] = to_i32(fn(a[i], b[i]))
	end
	return string.pack("<i4<i4<i4<i4", table.unpack(t, 1, 4))
end
local function i32x4_bitmask(v)
	local l = { string.unpack("<i4<i4<i4<i4", v) }
	local mask = 0
	for i = 1, 4 do
		if l[i] < 0 then
			mask = mask | (1 << (i - 1))
		end
	end
	return mask
end
local function i32x4_all_true(v)
	local l = { string.unpack("<I4<I4<I4<I4", v) }
	for i = 1, 4 do
		if l[i] == 0 then
			return 0
		end
	end
	return 1
end

-- i64x2
local function i64x2_splat(x)
	return string.pack("<I8", x):rep(2)
end
local function i64x2_extract_lane(v, lane)
	local lanes = { string.unpack("<i8<i8", v) }
	return lanes[lane + 1]
end
local function i64x2_replace_lane(v, lane, val)
	local lanes = { string.unpack("<i8<i8", v) }
	lanes[lane + 1] = val
	return string.pack("<i8<i8", table.unpack(lanes, 1, 2))
end
local function i64x2_binop(va, vb, fn)
	local a = { string.unpack("<i8<i8", va) }
	local b = { string.unpack("<i8<i8", vb) }
	return string.pack("<i8<i8", fn(a[1], b[1]), fn(a[2], b[2]))
end
local function i64x2_bitmask(v)
	local l = { string.unpack("<i8<i8", v) }
	local mask = 0
	for i = 1, 2 do
		if l[i] < 0 then
			mask = mask | (1 << (i - 1))
		end
	end
	return mask
end
local function i64x2_all_true(v)
	local l = { string.unpack("<I8<I8", v) }
	for i = 1, 2 do
		if l[i] == 0 then
			return 0
		end
	end
	return 1
end

-- f32x4
local function f32x4_splat(x)
	return string.pack("<f", x):rep(4)
end
local function f32x4_extract_lane(v, lane)
	local lanes = { string.unpack("<f<f<f<f", v) }
	return lanes[lane + 1]
end
local function f32x4_replace_lane(v, lane, val)
	local lanes = { string.unpack("<f<f<f<f", v) }
	lanes[lane + 1] = val
	return string.pack("<f<f<f<f", table.unpack(lanes, 1, 4))
end
local function f32x4_binop(va, vb, fn)
	local a = { string.unpack("<f<f<f<f", va) }
	local b = { string.unpack("<f<f<f<f", vb) }
	return string.pack("<f<f<f<f", fn(a[1], b[1]), fn(a[2], b[2]), fn(a[3], b[3]), fn(a[4], b[4]))
end

-- f64x2
local function f64x2_splat(x)
	return string.pack("<d", x):rep(2)
end
local function f64x2_extract_lane(v, lane)
	local lanes = { string.unpack("<d<d", v) }
	return lanes[lane + 1]
end
local function f64x2_replace_lane(v, lane, val)
	local lanes = { string.unpack("<d<d", v) }
	lanes[lane + 1] = val
	return string.pack("<d<d", table.unpack(lanes, 1, 2))
end
local function f64x2_binop(va, vb, fn)
	local a = { string.unpack("<d<d", va) }
	local b = { string.unpack("<d<d", vb) }
	return string.pack("<d<d", fn(a[1], b[1]), fn(a[2], b[2]))
end

--------------------------------------------------------------------------------
-- Linear Memory Implementation
--------------------------------------------------------------------------------

local Memory = {}
Memory.__index = Memory

function Memory:new(min_pages, max_pages, page_size)
	local ps = page_size or PAGE_SIZE
	local obj = {
		min_pages = min_pages or 0,
		max_pages = max_pages or MAX_PAGES,
		page_size = ps,
		current_pages = min_pages or 0,
		pages = {},
	}
	setmetatable(obj, Memory)
	for i = 0, (min_pages or 0) - 1 do
		local page = {}
		for j = 0, ps - 1 do
			page[j] = 0
		end
		obj.pages[i] = page
	end
	return obj
end

function Memory:size()
	return self.current_pages
end

function Memory:total_bytes()
	return self.current_pages * self.page_size
end

function Memory:grow(delta)
	local current = self.current_pages
	if delta == 0 then
		return current
	end
	local new_total = current + delta
	if new_total > self.max_pages then
		return -1
	end
	for i = current, new_total - 1 do
		local page = {}
		for j = 0, self.page_size - 1 do
			page[j] = 0
		end
		self.pages[i] = page
	end
	self.current_pages = new_total
	return current
end

function Memory:check_bounds(addr, size)
	if addr < 0 or (addr + size) > self:total_bytes() then
		error("out of bounds memory access")
	end
end

function Memory:read_byte(addr)
	self:check_bounds(addr, 1)
	local p = addr // self.page_size
	local off = addr % self.page_size
	return self.pages[p][off]
end

function Memory:write_byte(addr, b)
	self:check_bounds(addr, 1)
	local p = addr // self.page_size
	local off = addr % self.page_size
	self.pages[p][off] = b & 0xFF
end

function Memory:load_u8(addr)
	return self:read_byte(addr)
end

function Memory:load_i8(addr)
	local b = self:read_byte(addr)
	if (b & 0x80) ~= 0 then
		return b | (~0 << 7)
	end
	return b
end

function Memory:load_u16(addr)
	self:check_bounds(addr, 2)
	local b0 = self:read_byte(addr)
	local b1 = self:read_byte(addr + 1)
	return b0 | (b1 << 8)
end

function Memory:load_i16(addr)
	local v = self:load_u16(addr)
	if (v & 0x8000) ~= 0 then
		return v | (~0 << 15)
	end
	return v
end

function Memory:load_i32(addr)
	self:check_bounds(addr, 4)
	local b0 = self:read_byte(addr)
	local b1 = self:read_byte(addr + 1)
	local b2 = self:read_byte(addr + 2)
	local b3 = self:read_byte(addr + 3)
	local val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
	return to_i32(val)
end

function Memory:load_u32(addr)
	self:check_bounds(addr, 4)
	local b0 = self:read_byte(addr)
	local b1 = self:read_byte(addr + 1)
	local b2 = self:read_byte(addr + 2)
	local b3 = self:read_byte(addr + 3)
	return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
end

function Memory:load_i64(addr)
	self:check_bounds(addr, 8)
	local lo = self:load_u32(addr)
	local hi = self:load_u32(addr + 4)
	return lo | (hi << 32)
end

function Memory:load_f32(addr)
	self:check_bounds(addr, 4)
	local b0 = self:read_byte(addr)
	local b1 = self:read_byte(addr + 1)
	local b2 = self:read_byte(addr + 2)
	local b3 = self:read_byte(addr + 3)
	return string.unpack("<f", string.char(b0, b1, b2, b3))
end

function Memory:load_f64(addr)
	self:check_bounds(addr, 8)
	local bytes = {}
	for i = 0, 7 do
		bytes[i + 1] = string.char(self:read_byte(addr + i))
	end
	return string.unpack("<d", table.concat(bytes))
end

function Memory:store_i8(addr, v)
	self:write_byte(addr, v)
end

function Memory:store_i16(addr, v)
	self:check_bounds(addr, 2)
	self:write_byte(addr, v & 0xFF)
	self:write_byte(addr + 1, (v >> 8) & 0xFF)
end

function Memory:store_i32(addr, v)
	self:check_bounds(addr, 4)
	self:write_byte(addr, v & 0xFF)
	self:write_byte(addr + 1, (v >> 8) & 0xFF)
	self:write_byte(addr + 2, (v >> 16) & 0xFF)
	self:write_byte(addr + 3, (v >> 24) & 0xFF)
end

function Memory:store_i64(addr, v)
	self:check_bounds(addr, 8)
	for i = 0, 7 do
		self:write_byte(addr + i, (v >> (i * 8)) & 0xFF)
	end
end

function Memory:store_f32(addr, v)
	self:check_bounds(addr, 4)
	local s = string.pack("<f", v)
	for i = 0, 3 do
		self:write_byte(addr + i, string.byte(s, i + 1))
	end
end

function Memory:store_f64(addr, v)
	self:check_bounds(addr, 8)
	local s = string.pack("<d", v)
	for i = 0, 7 do
		self:write_byte(addr + i, string.byte(s, i + 1))
	end
end

function Memory:copy(dst, src, len)
	if len == 0 then
		return
	end
	self:check_bounds(dst, len)
	self:check_bounds(src, len)
	if dst <= src then
		for i = 0, len - 1 do
			self:write_byte(dst + i, self:read_byte(src + i))
		end
	else
		for i = len - 1, 0, -1 do
			self:write_byte(dst + i, self:read_byte(src + i))
		end
	end
end

function Memory:fill(dst, val, len)
	if len == 0 then
		return
	end
	self:check_bounds(dst, len)
	local b = val & 0xFF
	for i = 0, len - 1 do
		self:write_byte(dst + i, b)
	end
end

function Memory:init_from_string(dst, str, src_off, len)
	if len == 0 then
		return
	end
	self:check_bounds(dst, len)
	for i = 0, len - 1 do
		local b = string.byte(str, src_off + i + 1) or 0
		self:write_byte(dst + i, b)
	end
end

function Memory:read_string(addr, len)
	self:check_bounds(addr, len)
	local parts = {}
	for i = 0, len - 1 do
		parts[#parts + 1] = string.char(self:read_byte(addr + i))
	end
	return table.concat(parts)
end

function Memory:read_cstring(addr)
	local parts = {}
	local i = 0
	while true do
		local b = self:read_byte(addr + i)
		if b == 0 then
			break
		end
		parts[#parts + 1] = string.char(b)
		i = i + 1
	end
	return table.concat(parts)
end

function Memory:write_string(addr, str)
	local len = #str
	self:check_bounds(addr, len)
	for i = 0, len - 1 do
		self:write_byte(addr + i, string.byte(str, i + 1))
	end
end

Memory.store_u8 = Memory.store_i8
Memory.store_u16 = Memory.store_i16
Memory.store_u32 = Memory.store_i32
Memory.store_u64 = Memory.store_i64
Memory.load_u64 = Memory.load_i64

function Memory:read_struct(struct_def, addr)
	return struct_def:read(self, addr)
end

function Memory:write_struct(struct_def, addr, data)
	return struct_def:write(self, addr, data)
end

function Memory:read_struct_array(struct_def, addr, count)
	return struct_def:read_array(self, addr, count)
end

function Memory:write_struct_array(struct_def, addr, data_list)
	return struct_def:write_array(self, addr, data_list)
end

function Memory:struct_view(struct_def, addr)
	return struct_def:view(self, addr)
end

function Memory:struct_view_array(struct_def, addr, count)
	return struct_def:view_array(self, addr, count)
end

--------------------------------------------------------------------------------
-- Table Implementation
--------------------------------------------------------------------------------

local Table = {}
Table.__index = Table

function Table:new(min, max, ref_type)
	local obj = {
		min = min or 0,
		max = max or 1000000,
		ref_type = ref_type or opcodes.TYPE_FUNCREF,
		current_size = min or 0,
		elements = {},
	}
	return setmetatable(obj, Table)
end

function Table:size()
	return self.current_size
end

function Table:get(idx)
	if idx < 0 or idx >= self.current_size then
		error("out of bounds table access")
	end
	return self.elements[idx]
end

function Table:set(idx, ref)
	if idx < 0 or idx >= self.current_size then
		error("out of bounds table access")
	end
	self.elements[idx] = ref
end

function Table:grow(delta, init_val)
	local current = self.current_size
	if delta == 0 then
		return current
	end
	local new_total = current + delta
	if new_total > self.max then
		return -1
	end
	if init_val ~= nil then
		for i = current, new_total - 1 do
			self.elements[i] = init_val
		end
	end
	self.current_size = new_total
	return current
end

function Table:copy(dst, src, len)
	if len == 0 then
		return
	end
	if dst < 0 or dst + len > self:size() or src < 0 or src + len > self:size() then
		error("out of bounds table access")
	end
	if dst <= src then
		for i = 0, len - 1 do
			self.elements[dst + i] = self.elements[src + i]
		end
	else
		for i = len - 1, 0, -1 do
			self.elements[dst + i] = self.elements[src + i]
		end
	end
end

function Table:fill(dst, val, len)
	if len == 0 then
		return
	end
	if dst < 0 or dst + len > self:size() then
		error("out of bounds table access")
	end
	for i = 0, len - 1 do
		self.elements[dst + i] = val
	end
end

--------------------------------------------------------------------------------
-- Global Implementation
--------------------------------------------------------------------------------

local Global = {}
Global.__index = Global

function Global:new(val, valtype, mutable)
	local obj = {
		value = val or 0,
		type = valtype,
		mutable = mutable or false,
	}
	return setmetatable(obj, Global)
end

function Global:get()
	return self.value
end

function Global:set(val)
	if not self.mutable then
		error("cannot mutate immutable global")
	end
	self.value = val
end

--------------------------------------------------------------------------------
-- Function & Control Flow Pre-processing
--------------------------------------------------------------------------------

local function precompute_control_flow(instructions)
	local ctrl_stack = {}
	for pc, insn in ipairs(instructions) do
		local op = insn.opcode
		if op == "block" or op == "loop" or op == "if" or op == "try_table" then
			ctrl_stack[#ctrl_stack + 1] = {
				op = op,
				pc = pc,
				else_pc = nil,
				end_pc = nil,
			}
		elseif op == "else" then
			local top = ctrl_stack[#ctrl_stack]
			if top and top.op == "if" then
				top.else_pc = pc
			end
		elseif op == "end" then
			local top = table.remove(ctrl_stack)
			if top then
				top.end_pc = pc
				insn.block_entry = top
				if top.op == "if" then
					instructions[top.pc].else_pc = top.else_pc or pc
					instructions[top.pc].end_pc = pc
					if top.else_pc then
						instructions[top.else_pc].end_pc = pc
					end
				elseif top.op == "block" or top.op == "try_table" then
					instructions[top.pc].end_pc = pc
				end
			end
		end
	end

	-- Second pass: resolve br and br_table targets
	-- Each entry on depth_stack is { insn = instruction, insn_pc = array_index }
	local depth_stack = {}
	for pc, insn in ipairs(instructions) do
		local op = insn.opcode
		if op == "block" or op == "loop" or op == "if" or op == "try_table" then
			depth_stack[#depth_stack + 1] = { insn = insn, insn_pc = pc }
			if op == "try_table" and insn.catches then
				for _, c in ipairs(insn.catches) do
					local depth = c.label or 0
					local entry = depth_stack[#depth_stack - 1 - depth]
					if entry then
						c.target_pc = entry.insn.opcode == "loop" and entry.insn_pc or entry.insn.end_pc
					else
						c.target_pc = #instructions + 1
					end
				end
			end
		elseif op == "end" then
			table.remove(depth_stack)
		elseif
			op == "br"
			or op == "br_if"
			or op == "br_on_null"
			or op == "br_on_non_null"
			or op == "br_on_cast"
			or op == "br_on_cast_fail"
		then
			local depth = insn.label_index or 0
			local entry = depth_stack[#depth_stack - depth]
			if entry then
				if entry.insn.opcode == "loop" then
					insn.target_pc = entry.insn_pc
				else
					insn.target_pc = entry.insn.end_pc
				end
			end
		elseif op == "br_table" then
			insn.resolved_targets = {}
			if insn.targets then
				for i, depth in ipairs(insn.targets) do
					local entry = depth_stack[#depth_stack - depth]
					if entry then
						insn.resolved_targets[i] = entry.insn.opcode == "loop" and entry.insn_pc or entry.insn.end_pc
					end
				end
			end
			local def_depth = insn.default_target or 0
			local def_entry = depth_stack[#depth_stack - def_depth]
			if def_entry then
				insn.resolved_default = def_entry.insn.opcode == "loop" and def_entry.insn_pc or def_entry.insn.end_pc
			end
		end
	end
end

--------------------------------------------------------------------------------
-- Virtual Machine Interpreter
--------------------------------------------------------------------------------

local Instance = {}
Instance.__index = Instance

function Instance:get_export(name)
	return self.exports[name]
end

function Instance:invoke(name, ...)
	local fn = self.exports[name]
	if type(fn) ~= "function" then
		return nil, { kind = "missing_export", message = "No callable export: " .. tostring(name), export = name }
	end
	local result = table.pack(pcall(fn, ...))
	if not result[1] then
		return nil, { kind = "trap", message = tostring(result[2]), export = name }
	end
	return table.unpack(result, 2, result.n)
end

function Instance:set_breakpoint(address)
	self.breakpoints = self.breakpoints or {}
	self.breakpoints[address] = true
	return self
end

function Instance:clear_breakpoint(address)
	if self.breakpoints then
		self.breakpoints[address] = nil
	end
	return self
end

function Instance:trace(options)
	options = options or {}
	local events = options.events or {}
	local callback = options.callback
	self.trace_hook = function(event)
		events[#events + 1] = event
		if callback then
			callback(event)
		end
	end
	return events
end

function Instance:stop_trace()
	self.trace_hook = nil
end

function Instance:snapshot()
	local snapshot = { memories = {}, globals = {}, tables = {} }
	for index, memory in ipairs(self.memories) do
		snapshot.memories[index] = { pages = memory:size(), bytes = memory:read_string(0, memory:total_bytes()) }
	end
	for index, global in ipairs(self.globals) do
		snapshot.globals[index] = global:get()
	end
	for index, wasm_table in ipairs(self.tables) do
		snapshot.tables[index] = {}
		for key, value in pairs(wasm_table.elements or {}) do
			snapshot.tables[index][key] = value
		end
	end
	return snapshot
end

function Instance:restore(snapshot)
	for index, saved in ipairs(snapshot.memories or {}) do
		local memory = assert(self.memories[index], "snapshot memory is missing")
		if memory:size() < saved.pages then
			memory:grow(saved.pages - memory:size())
		end
		memory:write_string(0, saved.bytes)
	end
	for index, value in ipairs(snapshot.globals or {}) do
		local global = self.globals[index]
		if global then
			global.value = value
		end
	end
	for index, elements in ipairs(snapshot.tables or {}) do
		local wasm_table = self.tables[index]
		if wasm_table then
			wasm_table.elements = elements
		end
	end
	return self
end

--- Execute a function within the module instance.
--- @param func table Function entry
--- @param args any[] Arguments passed to function
--- @return any ... Return values
function Instance:invoke_function(func, args)
	if func.is_host then
		return func.host_fn(table.unpack(args))
	end

	-- Prepare locals: [params..., local variables...]
	local locals = {}
	local sig = func.type
	local param_count = sig and #sig.params or 0
	for i = 1, param_count do
		locals[i] = args[i] or 0
	end

	local local_idx = param_count + 1
	if func.locals then
		for _, loc in ipairs(func.locals) do
			local default_val = 0
			if loc.type == opcodes.TYPE_F32 or loc.type == opcodes.TYPE_F64 then
				default_val = 0.0
			end
			for _ = 1, loc.count do
				locals[local_idx] = default_val
				local_idx = local_idx + 1
			end
		end
	end

	local instructions = func.instructions
	local stack = {}
	local sp = 0
	local try_stack = {}

	local function push(val)
		sp = sp + 1
		stack[sp] = val
	end

	local function pop()
		local val = stack[sp]
		stack[sp] = nil
		sp = sp - 1
		return val
	end

	local function peek()
		return stack[sp]
	end

	local default_mem = self.memories[1]
	local default_tbl = self.tables[1]

	local pc = 1
	local num_insns = #instructions

	while pc <= num_insns do
		if self.fuel then
			if self.fuel <= 0 then
				error("execution fuel exhausted")
			end
			self.fuel = self.fuel - 1
		end
		if self.deadline and os.clock() > self.deadline then
			error("execution timeout exceeded")
		end
		local insn = instructions[pc]
		local op = insn.opcode
		if self.trace_hook then
			self.trace_hook({ instruction = insn, pc = pc, function_entry = func, stack_depth = sp })
		end
		if self.breakpoints and (self.breakpoints[insn.pc] or self.breakpoints[pc]) then
			error("breakpoint reached at " .. tostring(insn.pc or pc))
		end

		-- Fast numeric constants
		if op == "i32.const" then
			push(insn.value)
		elseif op == "i64.const" then
			push(insn.value)
		elseif op == "f32.const" then
			push(insn.value)
		elseif op == "f64.const" then
			push(insn.value)

		-- Local variables
		elseif op == "local.get" then
			push(locals[insn.index + 1])
		elseif op == "local.set" then
			locals[insn.index + 1] = pop()
		elseif op == "local.tee" then
			locals[insn.index + 1] = peek()

		-- Global variables
		elseif op == "global.get" then
			push(self.globals[insn.index + 1]:get())
		elseif op == "global.set" then
			self.globals[insn.index + 1]:set(pop())

		-- Control Flow
		elseif op == "block" or op == "loop" then
			-- No-op during forward execution; targets are precomputed
		elseif op == "try_table" then
			try_stack[#try_stack + 1] = { insn = insn, sp = sp }
		elseif op == "if" then
			local cond = pop()
			if cond == 0 then
				pc = insn.else_pc
			end
		elseif op == "else" then
			pc = insn.end_pc
		elseif op == "end" then
			if insn.block_entry and insn.block_entry.op == "try_table" then
				table.remove(try_stack)
			end
			-- Normal exit of block
		elseif op == "br" then
			pc = insn.target_pc
			if not pc then
				break
			end
		elseif op == "br_if" then
			local cond = pop()
			if cond ~= 0 then
				pc = insn.target_pc
				if not pc then
					break
				end
			end
		elseif op == "br_table" then
			local idx = pop()
			local target = insn.resolved_targets[idx + 1] or insn.resolved_default
			pc = target
			if not pc then
				break
			end
		elseif op == "return" then
			break
		elseif op == "unreachable" then
			error("unreachable executed")
		elseif op == "nop" then
			-- No operation
		elseif op == "drop" then
			pop()
		elseif op == "select" then
			local c = pop()
			local v2 = pop()
			local v1 = pop()
			push(c ~= 0 and v1 or v2)

		-- Function Calls
		elseif op == "call" then
			local target_func = self.funcs[insn.index + 1]
			if not target_func then
				error("call to unknown function " .. tostring(insn.index))
			end
			local call_param_count = target_func.type and #target_func.type.params or 0
			local call_args = {}
			for i = call_param_count, 1, -1 do
				call_args[i] = pop()
			end
			local results = { self:invoke_function(target_func, call_args) }
			for _, res in ipairs(results) do
				push(res)
			end
		elseif op == "call_indirect" then
			local tbl_idx = insn.table_index or 0
			local tbl = self.tables[tbl_idx + 1] or default_tbl
			local elem_idx = pop()
			local target_func = tbl:get(elem_idx)
			if not target_func then
				error("uninitialized element " .. tostring(elem_idx))
			end
			-- Type verification
			local expected_type = self.types[insn.type_index + 1]
			if expected_type and target_func.type_index and target_func.type_index ~= insn.type_index then
				error("indirect call type mismatch")
			end
			local call_param_count = target_func.type and #target_func.type.params or 0
			local call_args = {}
			for i = call_param_count, 1, -1 do
				call_args[i] = pop()
			end
			local results = { self:invoke_function(target_func, call_args) }
			for _, res in ipairs(results) do
				push(res)
			end

		-- Reference Instructions
		elseif op == "ref.null" then
			push(nil)
		elseif op == "ref.is_null" then
			push(pop() == nil and 1 or 0)
		elseif op == "ref.func" then
			push(self.funcs[insn.index + 1])

		-- 32-bit Integer Arithmetic
		elseif op == "i32.add" then
			local b = pop()
			local a = pop()
			push(to_i32(a + b))
		elseif op == "i32.sub" then
			local b = pop()
			local a = pop()
			push(to_i32(a - b))
		elseif op == "i32.mul" then
			local b = pop()
			local a = pop()
			push(to_i32(a * b))
		elseif op == "i32.div_s" then
			local b = pop()
			local a = pop()
			push(div_s32(a, b))
		elseif op == "i32.div_u" then
			local b = pop()
			local a = pop()
			push(div_u32(a, b))
		elseif op == "i32.rem_s" then
			local b = pop()
			local a = pop()
			push(rem_s32(a, b))
		elseif op == "i32.rem_u" then
			local b = pop()
			local a = pop()
			push(rem_u32(a, b))
		elseif op == "i32.and" then
			push(to_i32(pop() & pop()))
		elseif op == "i32.or" then
			push(to_i32(pop() | pop()))
		elseif op == "i32.xor" then
			push(to_i32(pop() ~ pop()))
		elseif op == "i32.shl" then
			local b = pop()
			local a = pop()
			push(to_i32(a << (b & 31)))
		elseif op == "i32.shr_s" then
			local b = pop()
			local a = pop()
			push(to_i32(to_i32(a) >> (b & 31)))
		elseif op == "i32.shr_u" then
			local b = pop()
			local a = pop()
			push(to_i32((a & 0xFFFFFFFF) >> (b & 31)))
		elseif op == "i32.rotl" then
			local b = pop()
			local a = pop()
			push(rotl32(a, b))
		elseif op == "i32.rotr" then
			local b = pop()
			local a = pop()
			push(rotr32(a, b))
		elseif op == "i32.clz" then
			push(clz32(pop()))
		elseif op == "i32.ctz" then
			push(ctz32(pop()))
		elseif op == "i32.popcnt" then
			push(popcnt32(pop()))

		-- 32-bit Integer Comparisons
		elseif op == "i32.eqz" then
			push((pop() & 0xFFFFFFFF) == 0 and 1 or 0)
		elseif op == "i32.eq" then
			push((pop() & 0xFFFFFFFF) == (pop() & 0xFFFFFFFF) and 1 or 0)
		elseif op == "i32.ne" then
			push((pop() & 0xFFFFFFFF) ~= (pop() & 0xFFFFFFFF) and 1 or 0)
		elseif op == "i32.lt_s" then
			local b = to_i32(pop())
			local a = to_i32(pop())
			push(a < b and 1 or 0)
		elseif op == "i32.lt_u" then
			local b = to_u32(pop())
			local a = to_u32(pop())
			push(a < b and 1 or 0)
		elseif op == "i32.gt_s" then
			local b = to_i32(pop())
			local a = to_i32(pop())
			push(a > b and 1 or 0)
		elseif op == "i32.gt_u" then
			local b = to_u32(pop())
			local a = to_u32(pop())
			push(a > b and 1 or 0)
		elseif op == "i32.le_s" then
			local b = to_i32(pop())
			local a = to_i32(pop())
			push(a <= b and 1 or 0)
		elseif op == "i32.le_u" then
			local b = to_u32(pop())
			local a = to_u32(pop())
			push(a <= b and 1 or 0)
		elseif op == "i32.ge_s" then
			local b = to_i32(pop())
			local a = to_i32(pop())
			push(a >= b and 1 or 0)
		elseif op == "i32.ge_u" then
			local b = to_u32(pop())
			local a = to_u32(pop())
			push(a >= b and 1 or 0)

		-- 64-bit Integer Arithmetic
		elseif op == "i64.add" then
			local b = pop()
			local a = pop()
			push(a + b)
		elseif op == "i64.sub" then
			local b = pop()
			local a = pop()
			push(a - b)
		elseif op == "i64.mul" then
			local b = pop()
			local a = pop()
			push(a * b)
		elseif op == "i64.div_s" then
			local b = pop()
			local a = pop()
			push(div_s64(a, b))
		elseif op == "i64.div_u" then
			local b = pop()
			local a = pop()
			push(div_u64(a, b))
		elseif op == "i64.rem_s" then
			local b = pop()
			local a = pop()
			push(rem_s64(a, b))
		elseif op == "i64.rem_u" then
			local b = pop()
			local a = pop()
			push(rem_u64(a, b))
		elseif op == "i64.and" then
			push(pop() & pop())
		elseif op == "i64.or" then
			push(pop() | pop())
		elseif op == "i64.xor" then
			push(pop() ~ pop())
		elseif op == "i64.shl" then
			local b = pop()
			local a = pop()
			push(a << (b & 63))
		elseif op == "i64.shr_s" then
			local b = pop()
			local a = pop()
			push(a >> (b & 63))
		elseif op == "i64.shr_u" then
			local b = pop()
			local a = pop()
			local shift = b & 63
			if shift == 0 then
				push(a)
			else
				push((a >> shift) & ((1 << (64 - shift)) - 1))
			end
		elseif op == "i64.rotl" then
			local b = pop()
			local a = pop()
			push(rotl64(a, b))
		elseif op == "i64.rotr" then
			local b = pop()
			local a = pop()
			push(rotr64(a, b))
		elseif op == "i64.clz" then
			push(clz64(pop()))
		elseif op == "i64.ctz" then
			push(ctz64(pop()))
		elseif op == "i64.popcnt" then
			push(popcnt64(pop()))

		-- 64-bit Integer Comparisons
		elseif op == "i64.eqz" then
			push(pop() == 0 and 1 or 0)
		elseif op == "i64.eq" then
			push(pop() == pop() and 1 or 0)
		elseif op == "i64.ne" then
			push(pop() ~= pop() and 1 or 0)
		elseif op == "i64.lt_s" then
			local b = pop()
			local a = pop()
			push(a < b and 1 or 0)
		elseif op == "i64.lt_u" then
			local b = pop()
			local a = pop()
			push(ucmp64(a, b) < 0 and 1 or 0)
		elseif op == "i64.gt_s" then
			local b = pop()
			local a = pop()
			push(a > b and 1 or 0)
		elseif op == "i64.gt_u" then
			local b = pop()
			local a = pop()
			push(ucmp64(a, b) > 0 and 1 or 0)
		elseif op == "i64.le_s" then
			local b = pop()
			local a = pop()
			push(a <= b and 1 or 0)
		elseif op == "i64.le_u" then
			local b = pop()
			local a = pop()
			push(ucmp64(a, b) <= 0 and 1 or 0)
		elseif op == "i64.ge_s" then
			local b = pop()
			local a = pop()
			push(a >= b and 1 or 0)
		elseif op == "i64.ge_u" then
			local b = pop()
			local a = pop()
			push(ucmp64(a, b) >= 0 and 1 or 0)

		-- Floating Point Operations
		elseif op == "f32.add" or op == "f64.add" then
			local b = pop()
			local a = pop()
			push(a + b)
		elseif op == "f32.sub" or op == "f64.sub" then
			local b = pop()
			local a = pop()
			push(a - b)
		elseif op == "f32.mul" or op == "f64.mul" then
			local b = pop()
			local a = pop()
			push(a * b)
		elseif op == "f32.div" or op == "f64.div" then
			local b = pop()
			local a = pop()
			push(a / b)
		elseif op == "f32.sqrt" or op == "f64.sqrt" then
			push(math.sqrt(pop()))
		elseif op == "f32.min" or op == "f64.min" then
			local b = pop()
			local a = pop()
			push(math.min(a, b))
		elseif op == "f32.max" or op == "f64.max" then
			local b = pop()
			local a = pop()
			push(math.max(a, b))
		elseif op == "f32.ceil" or op == "f64.ceil" then
			push(math.ceil(pop()))
		elseif op == "f32.floor" or op == "f64.floor" then
			push(math.floor(pop()))
		elseif op == "f32.trunc" or op == "f64.trunc" then
			local v = pop()
			push(v >= 0 and math.floor(v) or math.ceil(v))
		elseif op == "f32.abs" or op == "f64.abs" then
			push(math.abs(pop()))
		elseif op == "f32.neg" or op == "f64.neg" then
			push(-pop())
		elseif op == "f32.copysign" or op == "f64.copysign" then
			local b = pop()
			local a = pop()
			if (b < 0) or (b == 0 and tostring(b) == "-0.0") then
				push(-math.abs(a))
			else
				push(math.abs(a))
			end

		-- Floating Point Comparisons
		elseif op == "f32.eq" or op == "f64.eq" then
			push(pop() == pop() and 1 or 0)
		elseif op == "f32.ne" or op == "f64.ne" then
			push(pop() ~= pop() and 1 or 0)
		elseif op == "f32.lt" or op == "f64.lt" then
			local b = pop()
			local a = pop()
			push(a < b and 1 or 0)
		elseif op == "f32.gt" or op == "f64.gt" then
			local b = pop()
			local a = pop()
			push(a > b and 1 or 0)
		elseif op == "f32.le" or op == "f64.le" then
			local b = pop()
			local a = pop()
			push(a <= b and 1 or 0)
		elseif op == "f32.ge" or op == "f64.ge" then
			local b = pop()
			local a = pop()
			push(a >= b and 1 or 0)

		-- Conversions & Reinterpretations
		elseif op == "i32.wrap_i64" then
			push(to_i32(pop()))
		elseif op == "i32.trunc_f32_s" or op == "i32.trunc_f64_s" then
			local v = pop()
			if v ~= v then
				error("invalid conversion to integer")
			end -- NaN
			push(to_i32(math.modf(v)))
		elseif op == "i32.trunc_f32_u" or op == "i32.trunc_f64_u" then
			local v = pop()
			if v ~= v then
				error("invalid conversion to integer")
			end
			push(to_i32(math.modf(v) & 0xFFFFFFFF))
		elseif op == "i64.trunc_f32_s" or op == "i64.trunc_f64_s" then
			local v = pop()
			if v ~= v then
				error("invalid conversion to integer")
			end
			push(math.modf(v))
		elseif op == "i64.trunc_f32_u" or op == "i64.trunc_f64_u" then
			local v = pop()
			if v ~= v then
				error("invalid conversion to integer")
			end
			push(math.modf(v))
		elseif op == "i64.extend_i32_s" then
			push(to_i32(pop()))
		elseif op == "i64.extend_i32_u" then
			push(to_u32(pop()))
		elseif op == "i32.extend8_s" then
			local v = pop() & 0xFF
			push((v & 0x80) ~= 0 and (v | (~0 << 7)) or v)
		elseif op == "i32.extend16_s" then
			local v = pop() & 0xFFFF
			push((v & 0x8000) ~= 0 and (v | (~0 << 15)) or v)
		elseif op == "i64.extend8_s" then
			local v = pop() & 0xFF
			push((v & 0x80) ~= 0 and (v | (~0 << 7)) or v)
		elseif op == "i64.extend16_s" then
			local v = pop() & 0xFFFF
			push((v & 0x8000) ~= 0 and (v | (~0 << 15)) or v)
		elseif op == "i64.extend32_s" then
			push(to_i32(pop()))
		elseif op == "f32.convert_i32_s" or op == "f32.convert_i64_s" then
			push(pop() * 1.0)
		elseif op == "f32.convert_i32_u" then
			push(to_u32(pop()) * 1.0)
		elseif op == "f64.convert_i32_s" or op == "f64.convert_i64_s" then
			push(pop() * 1.0)
		elseif op == "f64.convert_i32_u" then
			push(to_u32(pop()) * 1.0)
		elseif op == "f32.demote_f64" or op == "f64.promote_f32" then
			push(pop() * 1.0)
		elseif op == "i32.reinterpret_f32" then
			push(f32_to_bits(pop()))
		elseif op == "f32.reinterpret_i32" then
			push(bits_to_f32(pop()))
		elseif op == "i64.reinterpret_f64" then
			push(f64_to_bits(pop()))
		elseif op == "f64.reinterpret_i64" then
			push(bits_to_f64(pop()))

		-- Memory Loads
		elseif op == "i32.load" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i32(addr))
		elseif op == "i32.load8_s" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i8(addr))
		elseif op == "i32.load8_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_u8(addr))
		elseif op == "i32.load16_s" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i16(addr))
		elseif op == "i32.load16_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_u16(addr))
		elseif op == "i64.load" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i64(addr))
		elseif op == "i64.load8_s" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i8(addr))
		elseif op == "i64.load8_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_u8(addr))
		elseif op == "i64.load16_s" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i16(addr))
		elseif op == "i64.load16_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_u16(addr))
		elseif op == "i64.load32_s" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_i32(addr))
		elseif op == "i64.load32_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_u32(addr))
		elseif op == "f32.load" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_f32(addr))
		elseif op == "f64.load" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:load_f64(addr))

		-- Memory Stores
		elseif op == "i32.store" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i32(addr, val)
		elseif op == "i32.store8" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i8(addr, val)
		elseif op == "i32.store16" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i16(addr, val)
		elseif op == "i64.store" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i64(addr, val)
		elseif op == "i64.store8" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i8(addr, val)
		elseif op == "i64.store16" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i16(addr, val)
		elseif op == "i64.store32" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_i32(addr, val)
		elseif op == "f32.store" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_f32(addr, val)
		elseif op == "f64.store" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:store_f64(addr, val)

		-- Memory Size & Grow
		elseif op == "memory.size" then
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:size())
		elseif op == "memory.grow" then
			local delta = pop()
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:grow(delta))

		-- Bulk Memory (0xFC)
		elseif op == "memory.copy" then
			local len = pop()
			local src = pop()
			local dst = pop()
			default_mem:copy(dst, src, len)
		elseif op == "memory.fill" then
			local len = pop()
			local val = pop()
			local dst = pop()
			default_mem:fill(dst, val, len)

		-- Table Operations
		elseif op == "table.get" then
			local idx = pop()
			local tbl = (insn.table_index and self.tables[insn.table_index + 1]) or default_tbl
			push(tbl:get(idx))
		elseif op == "table.set" then
			local val = pop()
			local idx = pop()
			local tbl = (insn.table_index and self.tables[insn.table_index + 1]) or default_tbl
			tbl:set(idx, val)
		elseif op == "table.size" then
			local tbl = (insn.table_index and self.tables[insn.table_index + 1]) or default_tbl
			push(tbl:size())
		elseif op == "table.grow" then
			local delta = pop()
			local init_val = pop()
			local tbl = (insn.table_index and self.tables[insn.table_index + 1]) or default_tbl
			push(tbl:grow(delta, init_val))
		elseif op == "table.fill" then
			local len = pop()
			local val = pop()
			local dst = pop()
			local tbl = (insn.table_index and self.tables[insn.table_index + 1]) or default_tbl
			tbl:fill(dst, val, len)
		-- f32/f64 nearest (round-to-even / banker's rounding)
		elseif op == "f32.nearest" or op == "f64.nearest" then
			local v = pop()
			local fl = math.floor(v)
			local frac = v - fl
			if frac == 0.5 then
				-- round to even
				push(fl % 2 == 0 and fl or fl + 1)
			else
				push(math.floor(v + 0.5))
			end

		-- Missing float conversions
		elseif op == "f32.convert_i64_u" then
			push(to_u64_float(pop()) * 1.0)
		elseif op == "f64.convert_i64_u" then
			push(to_u64_float(pop()) * 1.0)

		-- Saturating truncations (0xFC 0x00-0x07)
		elseif op == "i32.trunc_sat_f32_s" or op == "i32.trunc_sat_f64_s" then
			local v = pop()
			if v ~= v then
				push(0) -- NaN → 0
			elseif v >= 2147483648.0 then
				push(2147483647)
			elseif v < -2147483648.0 then
				push(-2147483648)
			else
				push(to_i32(math.modf(v)))
			end
		elseif op == "i32.trunc_sat_f32_u" or op == "i32.trunc_sat_f64_u" then
			local v = pop()
			if v ~= v or v < 0 then
				push(0)
			elseif v >= 4294967296.0 then
				push(-1) -- 0xFFFFFFFF as i32
			else
				push(to_i32(math.modf(v) & 0xFFFFFFFF))
			end
		elseif op == "i64.trunc_sat_f32_s" or op == "i64.trunc_sat_f64_s" then
			local v = pop()
			if v ~= v then
				push(0)
			elseif v >= 9223372036854775808.0 then
				push(math.maxinteger)
			elseif v < -9223372036854775808.0 then
				push(math.mininteger)
			else
				push(math.modf(v))
			end
		elseif op == "i64.trunc_sat_f32_u" or op == "i64.trunc_sat_f64_u" then
			local v = pop()
			if v ~= v or v < 0 then
				push(0)
			else
				push(math.modf(v))
			end

		-- Bulk memory: memory.init
		elseif op == "memory.init" then
			local len = pop()
			local src_off = pop()
			local dst = pop()
			local data_sec = self.module:get_section("data_section")
			local seg = data_sec
				and (
					(data_sec.entries and data_sec.entries[insn.data_index + 1])
					or (data_sec.data and data_sec.data[insn.data_index + 1])
				)
			if not seg then
				error("memory.init: data segment " .. tostring(insn.data_index) .. " not found")
			end
			local mem = (insn.mem_index and insn.mem_index > 0 and self.memories[insn.mem_index + 1]) or default_mem
			if len > 0 then
				mem:init_from_string(dst, seg.bytes or seg.data or "", src_off, len)
			end

		-- Bulk memory: data.drop
		elseif op == "data.drop" then
			-- Mark data segment as dropped (set bytes to empty)
			local data_sec = self.module:get_section("data_section")
			local seg = data_sec
				and (
					(data_sec.entries and data_sec.entries[insn.data_index + 1])
					or (data_sec.data and data_sec.data[insn.data_index + 1])
				)
			if seg then
				seg.bytes = ""
				seg.data = ""
			end

		-- Table: table.init
		elseif op == "table.init" then
			local len = pop()
			local src_off = pop()
			local dst = pop()
			local tbl = (insn.table_index and self.tables[insn.table_index + 1]) or default_tbl
			local elem_sec = self.module:get_section("element_section")
			local seg = elem_sec and elem_sec.elements and elem_sec.elements[insn.elem_index + 1]
			if seg and (seg.functions or seg.funcs) then
				local fn_list = seg.functions or seg.funcs
				for i = 0, len - 1 do
					local fi = fn_list[src_off + i + 1]
					tbl:set(dst + i, fi and self.funcs[fi] or nil)
				end
			elseif seg and (seg.expressions or seg.refs) then
				local expr_list = seg.expressions or seg.refs
				for i = 0, len - 1 do
					local item = expr_list[src_off + i + 1]
					local fn = (type(item) == "table" and item.function_index and self.funcs[item.function_index])
						or item
					tbl:set(dst + i, fn)
				end
			end

		-- Table: table.copy (cross-table or same-table)
		elseif op == "table.copy" then
			local len = pop()
			local src_off = pop()
			local dst_off = pop()
			local dst_tbl = (insn.dst ~= nil and self.tables[insn.dst + 1]) or default_tbl
			local src_tbl = (insn.src ~= nil and self.tables[insn.src + 1]) or default_tbl
			if dst_tbl == src_tbl then
				dst_tbl:copy(dst_off, src_off, len)
			else
				if dst_off <= src_off then
					for i = 0, len - 1 do
						dst_tbl:set(dst_off + i, src_tbl:get(src_off + i))
					end
				else
					for i = len - 1, 0, -1 do
						dst_tbl:set(dst_off + i, src_tbl:get(src_off + i))
					end
				end
			end

		-- Table: elem.drop
		elseif op == "elem.drop" then
			local elem_sec = self.module:get_section("element_section")
			local seg = elem_sec and elem_sec.elements and elem_sec.elements[insn.elem_index + 1]
			if seg then
				seg.functions = {}
				seg.funcs = {}
				seg.expressions = {}
				seg.refs = {}
			end

		-- Wide arithmetic (0xFC 0x13-0x16)
		elseif op == "i64.add128" then
			-- pops two i64 pairs (hi2, lo2, hi1, lo1) and pushes result hi, lo
			local hi2 = pop()
			local lo2 = pop()
			local hi1 = pop()
			local lo1 = pop()
			local lo = lo1 + lo2
			local carry = (lo < lo1 or lo < lo2) and 1 or 0
			push(hi1 + hi2 + carry)
			push(lo)
		elseif op == "i64.sub128" then
			local hi2 = pop()
			local lo2 = pop()
			local hi1 = pop()
			local lo1 = pop()
			local lo = lo1 - lo2
			local borrow = (lo1 < lo2) and 1 or 0
			push(hi1 - hi2 - borrow)
			push(lo)
		elseif op == "i64.mul_wide_s" then
			local b = pop()
			local a = pop()
			-- Approximate: Lua integers are 64-bit, so we just push 0 hi and lo*
			push(0)
			push(a * b)
		elseif op == "i64.mul_wide_u" then
			local b = pop()
			local a = pop()
			push(0)
			push(a * b)

		-- Tail calls (return semantics — in our interpreter just call and return)
		elseif op == "return_call" then
			local target_func = self.funcs[insn.index + 1]
			if not target_func then
				error("return_call to unknown function " .. tostring(insn.index))
			end
			local call_param_count = target_func.type and #target_func.type.params or 0
			local call_args = {}
			for i = call_param_count, 1, -1 do
				call_args[i] = pop()
			end
			local results = { self:invoke_function(target_func, call_args) }
			for _, res in ipairs(results) do
				push(res)
			end
			break -- tail return
		elseif op == "return_call_indirect" then
			local tbl_idx = insn.table_index or 0
			local tbl = self.tables[tbl_idx + 1] or default_tbl
			local elem_idx = pop()
			local target_func = tbl:get(elem_idx)
			if not target_func then
				error("return_call_indirect: uninitialized element " .. tostring(elem_idx))
			end
			local call_param_count = target_func.type and #target_func.type.params or 0
			local call_args = {}
			for i = call_param_count, 1, -1 do
				call_args[i] = pop()
			end
			local results = { self:invoke_function(target_func, call_args) }
			for _, res in ipairs(results) do
				push(res)
			end
			break
		elseif op == "call_ref" or op == "return_call_ref" then
			local target_func = pop()
			if not target_func then
				error(op .. ": null function reference")
			end
			local call_param_count = target_func.type and #target_func.type.params or 0
			local call_args = {}
			for i = call_param_count, 1, -1 do
				call_args[i] = pop()
			end
			local results = { self:invoke_function(target_func, call_args) }
			for _, res in ipairs(results) do
				push(res)
			end
			if op == "return_call_ref" then
				break
			end

		-- Reference ops
		elseif op == "ref.eq" then
			local b = pop()
			local a = pop()
			push(a == b and 1 or 0)
		elseif op == "ref.as_non_null" then
			local v = peek()
			if v == nil then
				error("ref.as_non_null: null reference")
			end
		elseif op == "ref.i31" then
			-- create an i31ref from an i32 value (we represent as a tagged table)
			local v = pop()
			push({ __i31 = true, value = v & 0x7FFFFFFF })
		elseif op == "ref.test" then
			local v = pop()
			local ht = insn.heap_type or insn.type_index or insn.index
			push(gc_type_matches(v, ht) and 1 or 0)
		elseif op == "ref.cast" then
			local v = peek()
			local ht = insn.heap_type or insn.type_index or insn.index
			if not gc_type_matches(v, ht) then
				error("bad cast in ref.cast")
			end

		-- br_on_null / br_on_non_null
		elseif op == "br_on_null" then
			local v = peek()
			if v == nil then
				pop()
				pc = insn.target_pc
				if not pc then
					break
				end
			end
		elseif op == "br_on_non_null" then
			local v = peek()
			if v ~= nil then
				pc = insn.target_pc
				if not pc then
					break
				end
			else
				pop()
			end

		-- br_on_cast / br_on_cast_fail (GC proposal)
		elseif op == "br_on_cast" then
			local v = peek()
			local ht = insn.heap_type2 or insn.heap_type or insn.type_index2 or insn.type_index or insn.index
			if gc_type_matches(v, ht) then
				pc = insn.target_pc
				if not pc then
					break
				end
			end
		elseif op == "br_on_cast_fail" then
			local v = peek()
			local ht = insn.heap_type2 or insn.heap_type or insn.type_index2 or insn.type_index or insn.index
			if not gc_type_matches(v, ht) then
				pc = insn.target_pc
				if not pc then
					break
				end
			end

		-- Exception handling
		elseif op == "throw" then
			local tag_idx = insn.tag_index or 0
			local tag_sec = self.module:get_section("tag_section")
			local tag_entry = tag_sec and tag_sec.tags and tag_sec.tags[tag_idx + 1]
			local tag_type = tag_entry and self.types[tag_entry.type_index + 1]
			local param_count = tag_type and #tag_type.params or 0
			local ex_values = {}
			for i = param_count, 1, -1 do
				ex_values[i] = pop()
			end
			local ex = { __exception = true, tag = tag_idx, values = ex_values }

			local handled = false
			while #try_stack > 0 do
				local top_try = table.remove(try_stack)
				if top_try.insn.catches then
					for _, c in ipairs(top_try.insn.catches) do
						if
							(c.kind == "catch" and c.tag == tag_idx)
							or (c.kind == "catch_ref" and c.tag == tag_idx)
							or (c.kind == "catch_all")
							or (c.kind == "catch_all_ref")
						then
							sp = top_try.sp
							if c.kind == "catch" or c.kind == "catch_ref" then
								for _, val in ipairs(ex_values) do
									push(val)
								end
							end
							if c.kind == "catch_ref" or c.kind == "catch_all_ref" then
								push(ex)
							end
							pc = c.target_pc
							handled = true
							break
						end
					end
				end
				if handled then
					break
				end
			end
			if not handled then
				error("wasm exception thrown (tag " .. tostring(tag_idx) .. ")")
			end
			if not pc then
				break
			end
		elseif op == "throw_ref" then
			local ex = pop()
			if not ex or type(ex) ~= "table" or not ex.__exception then
				error("throw_ref: null or invalid exception reference")
			end
			local tag_idx = ex.tag
			local ex_values = ex.values or {}
			local handled = false
			while #try_stack > 0 do
				local top_try = table.remove(try_stack)
				if top_try.insn.catches then
					for _, c in ipairs(top_try.insn.catches) do
						if
							(c.kind == "catch" and c.tag == tag_idx)
							or (c.kind == "catch_ref" and c.tag == tag_idx)
							or (c.kind == "catch_all")
							or (c.kind == "catch_all_ref")
						then
							sp = top_try.sp
							if c.kind == "catch" or c.kind == "catch_ref" then
								for _, val in ipairs(ex_values) do
									push(val)
								end
							end
							if c.kind == "catch_ref" or c.kind == "catch_all_ref" then
								push(ex)
							end
							pc = c.target_pc
							handled = true
							break
						end
					end
				end
				if handled then
					break
				end
			end
			if not handled then
				error("wasm exception thrown (tag " .. tostring(tag_idx) .. ")")
			end
			if not pc then
				break
			end
		elseif op == "try_table" then
			-- Pushed to try_stack on entry (handled at block start)

			-- i31 operations (GC proposal)
		elseif op == "i31.get_s" then
			local v = pop()
			if type(v) == "table" and v.__i31 then
				local val = v.value & 0x7FFFFFFF
				push((val & 0x40000000) ~= 0 and (val | (~0 << 30)) or val)
			else
				push(0)
			end
		elseif op == "i31.get_u" then
			local v = pop()
			push(type(v) == "table" and v.__i31 and (v.value & 0x7FFFFFFF) or 0)

		-- Struct operations (GC proposal) — stub
		elseif op == "struct.new" then
			local type_idx = insn.type_index
			local ty = self.types[type_idx + 1]
			local field_count = ty and ty.fields and #ty.fields or 0
			local fields = {}
			for i = field_count, 1, -1 do
				fields[i] = pop()
			end
			push({ __struct = true, type_index = type_idx, fields = fields })
		elseif op == "struct.new_default" then
			local type_idx = insn.type_index
			local ty = self.types[type_idx + 1]
			local field_count = ty and ty.fields and #ty.fields or 0
			local fields = {}
			for i = 1, field_count do
				fields[i] = 0
			end
			push({ __struct = true, type_index = type_idx, fields = fields })
		elseif op == "struct.get" or op == "struct.get_u" then
			local s = pop()
			if type(s) == "table" and s.__struct then
				push(s.fields[insn.field_index + 1] or 0)
			else
				push(0)
			end
		elseif op == "struct.get_s" then
			local s = pop()
			push(type(s) == "table" and s.__struct and s.fields[insn.field_index + 1] or 0)
		elseif op == "struct.set" then
			local val = pop()
			local s = pop()
			if type(s) == "table" and s.__struct then
				s.fields[insn.field_index + 1] = val
			end

		-- Array operations (GC proposal) — stub
		elseif op == "array.new" then
			local init = pop()
			local len = pop()
			local arr = {}
			for i = 0, len - 1 do
				arr[i] = init
			end
			push({ __array = true, type_index = insn.type_index, elements = arr, length = len })
		elseif op == "array.new_default" then
			local len = pop()
			local arr = {}
			for i = 0, len - 1 do
				arr[i] = 0
			end
			push({ __array = true, type_index = insn.type_index, elements = arr, length = len })
		elseif op == "array.new_fixed" then
			local count = insn.size or insn.count or 0
			local arr = {}
			local elems = {}
			for i = count, 1, -1 do
				elems[i] = pop()
			end
			for i = 0, count - 1 do
				arr[i] = elems[i + 1]
			end
			push({ __array = true, type_index = insn.type_index, elements = arr, length = count })
		elseif op == "array.new_data" then
			local len = pop()
			local src = pop()
			push({ __array = true, type_index = insn.type_index, elements = {}, length = len })
		elseif op == "array.new_elem" then
			local len = pop()
			local src = pop()
			push({ __array = true, type_index = insn.type_index, elements = {}, length = len })
		elseif op == "array.get" or op == "array.get_u" then
			local idx = pop()
			local arr = pop()
			if type(arr) == "table" and arr.__array then
				local v = arr.elements[idx]
				push(v ~= nil and v or 0)
			else
				push(0)
			end
		elseif op == "array.get_s" then
			local idx = pop()
			local arr = pop()
			push(type(arr) == "table" and arr.__array and arr.elements[idx] or 0)
		elseif op == "array.set" then
			local val = pop()
			local idx = pop()
			local arr = pop()
			if type(arr) == "table" and arr.__array then
				arr.elements[idx] = val
			end
		elseif op == "array.len" then
			local arr = pop()
			push(type(arr) == "table" and arr.__array and arr.length or 0)
		elseif op == "array.fill" then
			local len = pop()
			local val = pop()
			local offset = pop()
			local arr = pop()
			if type(arr) == "table" and arr.__array then
				for i = offset, offset + len - 1 do
					arr.elements[i] = val
				end
			end
		elseif op == "array.copy" then
			local len = pop()
			local src_off = pop()
			local src_arr = pop()
			local dst_off = pop()
			local dst_arr = pop()
			if type(dst_arr) == "table" and dst_arr.__array and type(src_arr) == "table" and src_arr.__array then
				for i = 0, len - 1 do
					dst_arr.elements[dst_off + i] = src_arr.elements[src_off + i]
				end
			end
		elseif op == "array.init_data" then
			pop()
			pop()
			pop()
			pop() -- drain: dst_arr, offset, data_offset, length
		elseif op == "array.init_elem" then
			pop()
			pop()
			pop()
			pop() -- drain: dst_arr, offset, elem_offset, length

		-- extern/any conversions (GC proposal)
		elseif op == "any.convert_extern" or op == "extern.convert_any" then
			-- identity in our runtime (no GC type distinction)

			-- Atomics
		elseif op:find("^i32%.atomic%.load") or op:find("^i64%.atomic%.load") then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			if op == "i32.atomic.load" then
				push(mem:load_i32(addr))
			elseif op == "i32.atomic.load8_u" or op == "i64.atomic.load8_u" then
				push(mem:load_u8(addr))
			elseif op == "i32.atomic.load16_u" or op == "i64.atomic.load16_u" then
				push(mem:load_u16(addr))
			elseif op == "i64.atomic.load" then
				push(mem:load_i64(addr))
			elseif op == "i64.atomic.load32_u" then
				push(mem:load_u32(addr))
			end
		elseif op:find("^i32%.atomic%.store") or op:find("^i64%.atomic%.store") then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			if op == "i32.atomic.store" or op == "i64.atomic.store32" then
				mem:store_i32(addr, val)
			elseif op == "i32.atomic.store8" or op == "i64.atomic.store8" then
				mem:store_i8(addr, val)
			elseif op == "i32.atomic.store16" or op == "i64.atomic.store16" then
				mem:store_i16(addr, val)
			elseif op == "i64.atomic.store" then
				mem:store_i64(addr, val)
			end
		elseif op:find("%.atomic%.rmw%.cmpxchg") or op:find("%.atomic%.rmw%d*%.cmpxchg") then
			local repl = pop()
			local exp = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			local is_64 = op:find("^i64")
			local old
			if op:find("rmw8") then
				old = mem:load_u8(addr)
				if (old & 0xFF) == (exp & 0xFF) then
					mem:store_i8(addr, repl)
				end
			elseif op:find("rmw16") then
				old = mem:load_u16(addr)
				if (old & 0xFFFF) == (exp & 0xFFFF) then
					mem:store_i16(addr, repl)
				end
			elseif op:find("rmw32") then
				old = mem:load_u32(addr)
				if (old & 0xFFFFFFFF) == (exp & 0xFFFFFFFF) then
					mem:store_i32(addr, repl)
				end
			elseif is_64 then
				old = mem:load_i64(addr)
				if old == exp then
					mem:store_i64(addr, repl)
				end
			else
				old = mem:load_i32(addr)
				if (old & 0xFFFFFFFF) == (exp & 0xFFFFFFFF) then
					mem:store_i32(addr, repl)
				end
			end
			push(old)
		elseif op:find("%.atomic%.rmw") then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			local is_64 = op:find("^i64")
			local is_8 = op:find("rmw8")
			local is_16 = op:find("rmw16")
			local is_32 = op:find("rmw32")
			local old
			if is_8 then
				old = mem:load_u8(addr)
			elseif is_16 then
				old = mem:load_u16(addr)
			elseif is_32 then
				old = mem:load_u32(addr)
			elseif is_64 then
				old = mem:load_i64(addr)
			else
				old = mem:load_i32(addr)
			end

			local new_val
			if op:find("add") then
				new_val = old + val
			elseif op:find("sub") then
				new_val = old - val
			elseif op:find("and") then
				new_val = old & val
			elseif op:find("xor") then
				new_val = old ~ val
			elseif op:find("or") then
				new_val = old | val
			elseif op:find("xchg") then
				new_val = val
			end

			if is_8 then
				mem:store_i8(addr, new_val)
			elseif is_16 then
				mem:store_i16(addr, new_val)
			elseif is_32 or not is_64 then
				mem:store_i32(addr, new_val)
			else
				mem:store_i64(addr, new_val)
			end
			push(old)
		elseif op == "atomic.fence" then
			-- no-op
		elseif op == "memory.atomic.notify" then
			pop()
			pop()
			push(0)
		elseif op == "memory.atomic.wait32" or op == "memory.atomic.wait64" then
			local timeout = pop()
			local expected = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			local cur = (op == "memory.atomic.wait32") and mem:load_i32(addr) or mem:load_i64(addr)
			if cur ~= expected then
				push(1)
			else
				push(2)
			end

		-- SIMD: v128 constants and memory
		elseif op == "v128.const" then
			push(v128_from_bytes(insn.value))
		elseif op == "v128.load" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(mem:read_string(addr, 16))
		elseif op == "v128.load8x8_s" or op == "v128.load8x8_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			local lanes = {}
			for i = 0, 7 do
				lanes[i + 1] = (op == "v128.load8x8_s") and mem:load_i8(addr + i) or mem:load_u8(addr + i)
			end
			push(string.pack("<i2<i2<i2<i2<i2<i2<i2<i2", table.unpack(lanes, 1, 8)))
		elseif op == "v128.load16x4_s" or op == "v128.load16x4_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			local lanes = {}
			for i = 0, 3 do
				lanes[i + 1] = (op == "v128.load16x4_s") and mem:load_i16(addr + i * 2) or mem:load_u16(addr + i * 2)
			end
			push(string.pack("<i4<i4<i4<i4", table.unpack(lanes, 1, 4)))
		elseif op == "v128.load32x2_s" or op == "v128.load32x2_u" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			local l0 = (op == "v128.load32x2_s") and mem:load_i32(addr) or mem:load_u32(addr)
			local l1 = (op == "v128.load32x2_s") and mem:load_i32(addr + 4) or mem:load_u32(addr + 4)
			push(string.pack("<i8<i8", l0, l1))
		elseif op == "v128.load8_splat" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(i8x16_splat(mem:load_u8(addr)))
		elseif op == "v128.load16_splat" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(i16x8_splat(mem:load_u16(addr)))
		elseif op == "v128.load32_splat" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(i32x4_splat(mem:load_u32(addr)))
		elseif op == "v128.load64_splat" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(i64x2_splat(mem:load_i64(addr)))
		elseif op == "v128.load32_zero" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(string.pack("<I4<I4<I4<I4", mem:load_u32(addr), 0, 0, 0))
		elseif op == "v128.load64_zero" then
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			push(string.pack("<I8<I8", mem:load_i64(addr), 0))
		elseif op == "v128.store" then
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			mem:write_string(addr, val)
		elseif
			op == "v128.load8_lane"
			or op == "v128.load16_lane"
			or op == "v128.load32_lane"
			or op == "v128.load64_lane"
		then
			local lane = insn.lane or insn.index or 0
			local v = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			if op == "v128.load8_lane" then
				push(i8x16_replace_lane(v, lane, mem:load_u8(addr)))
			elseif op == "v128.load16_lane" then
				push(i16x8_replace_lane(v, lane, mem:load_u16(addr)))
			elseif op == "v128.load32_lane" then
				push(i32x4_replace_lane(v, lane, mem:load_u32(addr)))
			else
				push(i64x2_replace_lane(v, lane, mem:load_i64(addr)))
			end
		elseif
			op == "v128.store8_lane"
			or op == "v128.store16_lane"
			or op == "v128.store32_lane"
			or op == "v128.store64_lane"
		then
			local lane = insn.lane or insn.index or 0
			local val = pop()
			local addr = pop() + (insn.offset or 0)
			local mem = (insn.mem_index and self.memories[insn.mem_index + 1]) or default_mem
			if op == "v128.store8_lane" then
				mem:store_i8(addr, i8x16_extract_lane_u(val, lane))
			elseif op == "v128.store16_lane" then
				mem:store_i16(addr, i16x8_extract_lane_u(val, lane))
			elseif op == "v128.store32_lane" then
				mem:store_i32(addr, i32x4_extract_lane(val, lane))
			else
				mem:store_i64(addr, i64x2_extract_lane(val, lane))
			end
		elseif op == "v128.not" then
			push(v128_not(pop()))
		elseif op == "v128.and" then
			local b = pop()
			push(v128_and(pop(), b))
		elseif op == "v128.andnot" then
			local b = pop()
			push(v128_andnot(pop(), b))
		elseif op == "v128.or" then
			local b = pop()
			push(v128_or(pop(), b))
		elseif op == "v128.xor" then
			local b = pop()
			push(v128_xor(pop(), b))
		elseif op == "v128.bitselect" or op:find("%.relaxed_laneselect$") then
			local c = pop()
			local v2 = pop()
			local v1 = pop()
			push(v128_bitselect(v1, v2, c))
		elseif op == "v128.any_true" then
			push(v128_any_true(pop()))

		-- SIMD: splat
		elseif op:find("%.splat$") then
			local val = pop()
			if op == "i8x16.splat" then
				push(i8x16_splat(val))
			elseif op == "i16x8.splat" then
				push(i16x8_splat(val))
			elseif op == "i32x4.splat" then
				push(i32x4_splat(val))
			elseif op == "i64x2.splat" then
				push(i64x2_splat(val))
			elseif op == "f32x4.splat" then
				push(f32x4_splat(val))
			elseif op == "f64x2.splat" then
				push(f64x2_splat(val))
			end

		-- SIMD: extract_lane
		elseif op:find("%.extract_lane") then
			local lane = insn.lane or insn.index or 0
			local v = pop()
			if op == "i8x16.extract_lane_s" then
				push(i8x16_extract_lane_s(v, lane))
			elseif op == "i8x16.extract_lane_u" then
				push(i8x16_extract_lane_u(v, lane))
			elseif op == "i16x8.extract_lane_s" then
				push(i16x8_extract_lane_s(v, lane))
			elseif op == "i16x8.extract_lane_u" then
				push(i16x8_extract_lane_u(v, lane))
			elseif op == "i32x4.extract_lane" then
				push(i32x4_extract_lane(v, lane))
			elseif op == "i64x2.extract_lane" then
				push(i64x2_extract_lane(v, lane))
			elseif op == "f32x4.extract_lane" then
				push(f32x4_extract_lane(v, lane))
			elseif op == "f64x2.extract_lane" then
				push(f64x2_extract_lane(v, lane))
			end

		-- SIMD: replace_lane
		elseif op:find("%.replace_lane$") then
			local val = pop()
			local v = pop()
			local lane = insn.lane or insn.index or 0
			if op == "i8x16.replace_lane" then
				push(i8x16_replace_lane(v, lane, val))
			elseif op == "i16x8.replace_lane" then
				push(i16x8_replace_lane(v, lane, val))
			elseif op == "i32x4.replace_lane" then
				push(i32x4_replace_lane(v, lane, val))
			elseif op == "i64x2.replace_lane" then
				push(i64x2_replace_lane(v, lane, val))
			elseif op == "f32x4.replace_lane" then
				push(f32x4_replace_lane(v, lane, val))
			elseif op == "f64x2.replace_lane" then
				push(f64x2_replace_lane(v, lane, val))
			end

		-- SIMD: all_true & bitmask
		elseif op == "i8x16.all_true" then
			push(i8x16_all_true(pop()))
		elseif op == "i16x8.all_true" then
			push(i16x8_all_true(pop()))
		elseif op == "i32x4.all_true" then
			push(i32x4_all_true(pop()))
		elseif op == "i64x2.all_true" then
			push(i64x2_all_true(pop()))
		elseif op == "i8x16.bitmask" then
			push(i8x16_bitmask(pop()))
		elseif op == "i16x8.bitmask" then
			push(i16x8_bitmask(pop()))
		elseif op == "i32x4.bitmask" then
			push(i32x4_bitmask(pop()))
		elseif op == "i64x2.bitmask" then
			push(i64x2_bitmask(pop()))

		-- SIMD: shl / shr
		elseif op:find("^i%d+x%d+%.sh") then
			local shift = pop()
			local v = pop()
			if op == "i8x16.shl" then
				local s = shift % 8
				push(i8x16_binop(v, v, function(a)
					return a << s
				end))
			elseif op == "i8x16.shr_s" then
				local s = shift % 8
				push(i8x16_binop(v, v, function(a)
					return (a >= 128 and (a | (~0 << 7)) or a) >> s
				end))
			elseif op == "i8x16.shr_u" then
				local s = shift % 8
				push(i8x16_binop(v, v, function(a)
					return a >> s
				end))
			elseif op == "i16x8.shl" then
				local s = shift % 16
				push(i16x8_binop(v, v, function(a)
					return a << s
				end))
			elseif op == "i16x8.shr_s" then
				local s = shift % 16
				push(i16x8_binop(v, v, function(a)
					return a >> s
				end))
			elseif op == "i16x8.shr_u" then
				local s = shift % 16
				push(i16x8_binop(v, v, function(a)
					return (a & 0xFFFF) >> s
				end))
			elseif op == "i32x4.shl" then
				local s = shift % 32
				push(i32x4_binop(v, v, function(a)
					return a << s
				end))
			elseif op == "i32x4.shr_s" then
				local s = shift % 32
				push(i32x4_binop(v, v, function(a)
					return a >> s
				end))
			elseif op == "i32x4.shr_u" then
				local s = shift % 32
				push(i32x4_binop(v, v, function(a)
					return to_u32(a) >> s
				end))
			elseif op == "i64x2.shl" then
				local s = shift % 64
				push(i64x2_binop(v, v, function(a)
					return a << s
				end))
			elseif op == "i64x2.shr_s" then
				local s = shift % 64
				push(i64x2_binop(v, v, function(a)
					return a >> s
				end))
			elseif op == "i64x2.shr_u" then
				local s = shift % 64
				push(i64x2_binop(v, v, function(a)
					return (a >= 0 and a >> s or ((a >> 1) & 0x7FFFFFFFFFFFFFFF) >> (s - 1))
				end))
			end

		-- SIMD: shuffle & swizzle
		elseif op == "i8x16.shuffle" then
			local v2 = pop()
			local v1 = pop()
			local combined = v1 .. v2
			local t = {}
			local lanes = insn.lanes or {}
			for i = 1, 16 do
				local idx = (lanes[i] or 0)
				t[i] = string.char(string.byte(combined, idx + 1) or 0)
			end
			push(table.concat(t))
		elseif op == "i8x16.swizzle" or op == "i8x16.relaxed_swizzle" then
			local s = pop()
			local v = pop()
			local t = {}
			for i = 1, 16 do
				local idx = string.byte(s, i)
				t[i] = string.char((idx < 16) and string.byte(v, idx + 1) or 0)
			end
			push(table.concat(t))

		-- SIMD: i8x16 arithmetic & comparison
		elseif op:find("^i8x16%.") then
			if op == "i8x16.neg" then
				push(i8x16_binop(pop(), pop(), function(a)
					return -a
				end))
			elseif op == "i8x16.popcnt" then
				push(i8x16_binop(pop(), pop(), function(a)
					local c = 0
					while a ~= 0 do
						a = a & (a - 1)
						c = c + 1
					end
					return c
				end))
			else
				local vb = pop()
				local va = pop()
				if op == "i8x16.add" then
					push(i8x16_binop(va, vb, function(a, b)
						return a + b
					end))
				elseif op == "i8x16.sub" then
					push(i8x16_binop(va, vb, function(a, b)
						return a - b
					end))
				elseif op == "i8x16.eq" then
					push(i8x16_binop(va, vb, function(a, b)
						return a == b and 0xFF or 0
					end))
				elseif op == "i8x16.ne" then
					push(i8x16_binop(va, vb, function(a, b)
						return a ~= b and 0xFF or 0
					end))
				elseif op == "i8x16.lt_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						return sa < sb and 0xFF or 0
					end))
				elseif op == "i8x16.lt_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return a < b and 0xFF or 0
					end))
				elseif op == "i8x16.gt_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						return sa > sb and 0xFF or 0
					end))
				elseif op == "i8x16.gt_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return a > b and 0xFF or 0
					end))
				elseif op == "i8x16.le_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						return sa <= sb and 0xFF or 0
					end))
				elseif op == "i8x16.le_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return a <= b and 0xFF or 0
					end))
				elseif op == "i8x16.ge_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						return sa >= sb and 0xFF or 0
					end))
				elseif op == "i8x16.ge_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return a >= b and 0xFF or 0
					end))
				elseif op == "i8x16.min_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						return sa < sb and a or b
					end))
				elseif op == "i8x16.min_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return math.min(a, b)
					end))
				elseif op == "i8x16.max_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						return sa > sb and a or b
					end))
				elseif op == "i8x16.max_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return math.max(a, b)
					end))
				elseif op == "i8x16.add_sat_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						local sum = sa + sb
						return sum > 127 and 127 or (sum < -128 and -128 or sum)
					end))
				elseif op == "i8x16.add_sat_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return math.min(255, a + b)
					end))
				elseif op == "i8x16.sub_sat_s" then
					push(i8x16_binop(va, vb, function(a, b)
						local sa = (a >= 128) and (a | (~0 << 7)) or a
						local sb = (b >= 128) and (b | (~0 << 7)) or b
						local diff = sa - sb
						return diff > 127 and 127 or (diff < -128 and -128 or diff)
					end))
				elseif op == "i8x16.sub_sat_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return math.max(0, a - b)
					end))
				elseif op == "i8x16.avgr_u" then
					push(i8x16_binop(va, vb, function(a, b)
						return (a + b + 1) >> 1
					end))
				else
					push(va)
				end
			end

		-- SIMD: i16x8 arithmetic & comparison
		elseif op:find("^i16x8%.") then
			if op == "i16x8.neg" then
				push(i16x8_binop(pop(), pop(), function(a)
					return -a
				end))
			else
				local vb = pop()
				local va = pop()
				if op == "i16x8.add" then
					push(i16x8_binop(va, vb, function(a, b)
						return a + b
					end))
				elseif op == "i16x8.sub" then
					push(i16x8_binop(va, vb, function(a, b)
						return a - b
					end))
				elseif op == "i16x8.mul" then
					push(i16x8_binop(va, vb, function(a, b)
						return a * b
					end))
				elseif op == "i16x8.eq" then
					push(i16x8_binop(va, vb, function(a, b)
						return a == b and 0xFFFF or 0
					end))
				elseif op == "i16x8.ne" then
					push(i16x8_binop(va, vb, function(a, b)
						return a ~= b and 0xFFFF or 0
					end))
				elseif op == "i16x8.lt_s" then
					push(i16x8_binop(va, vb, function(a, b)
						return a < b and 0xFFFF or 0
					end))
				elseif op == "i16x8.lt_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return (a & 0xFFFF) < (b & 0xFFFF) and 0xFFFF or 0
					end))
				elseif op == "i16x8.gt_s" then
					push(i16x8_binop(va, vb, function(a, b)
						return a > b and 0xFFFF or 0
					end))
				elseif op == "i16x8.gt_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return (a & 0xFFFF) > (b & 0xFFFF) and 0xFFFF or 0
					end))
				elseif op == "i16x8.le_s" then
					push(i16x8_binop(va, vb, function(a, b)
						return a <= b and 0xFFFF or 0
					end))
				elseif op == "i16x8.le_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return (a & 0xFFFF) <= (b & 0xFFFF) and 0xFFFF or 0
					end))
				elseif op == "i16x8.ge_s" then
					push(i16x8_binop(va, vb, function(a, b)
						return a >= b and 0xFFFF or 0
					end))
				elseif op == "i16x8.ge_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return (a & 0xFFFF) >= (b & 0xFFFF) and 0xFFFF or 0
					end))
				elseif op == "i16x8.min_s" then
					push(i16x8_binop(va, vb, function(a, b)
						return math.min(a, b)
					end))
				elseif op == "i16x8.min_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return math.min(a & 0xFFFF, b & 0xFFFF)
					end))
				elseif op == "i16x8.max_s" then
					push(i16x8_binop(va, vb, function(a, b)
						return math.max(a, b)
					end))
				elseif op == "i16x8.max_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return math.max(a & 0xFFFF, b & 0xFFFF)
					end))
				elseif op == "i16x8.add_sat_s" then
					push(i16x8_binop(va, vb, function(a, b)
						local s = a + b
						return s > 32767 and 32767 or (s < -32768 and -32768 or s)
					end))
				elseif op == "i16x8.add_sat_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return math.min(65535, (a & 0xFFFF) + (b & 0xFFFF))
					end))
				elseif op == "i16x8.sub_sat_s" then
					push(i16x8_binop(va, vb, function(a, b)
						local d = a - b
						return d > 32767 and 32767 or (d < -32768 and -32768 or d)
					end))
				elseif op == "i16x8.sub_sat_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return math.max(0, (a & 0xFFFF) - (b & 0xFFFF))
					end))
				elseif op == "i16x8.avgr_u" then
					push(i16x8_binop(va, vb, function(a, b)
						return ((a & 0xFFFF) + (b & 0xFFFF) + 1) >> 1
					end))
				elseif op == "i16x8.q15mulr_sat_s" or op == "i16x8.relaxed_q15mulr_s" then
					push(i16x8_binop(va, vb, function(a, b)
						local res = (a * b + 0x4000) >> 15
						return res > 32767 and 32767 or (res < -32768 and -32768 or res)
					end))
				else
					push(va)
				end
			end

		-- SIMD: i32x4 arithmetic & comparison
		elseif op:find("^i32x4%.") then
			if op == "i32x4.neg" then
				push(i32x4_binop(pop(), pop(), function(a)
					return -a
				end))
			elseif op == "i32x4.trunc_sat_f32x4_s" or op == "i32x4.relaxed_trunc_f32x4_s" then
				local v = pop()
				local lanes = { string.unpack("<f<f<f<f", v) }
				local res = {}
				for i = 1, 4 do
					local f = lanes[i]
					res[i] = (f ~= f) and 0
						or (f >= 2147483647 and 2147483647 or (f <= -2147483648 and -2147483648 or math.modf(f)))
				end
				push(string.pack("<i4<i4<i4<i4", table.unpack(res, 1, 4)))
			elseif op == "i32x4.trunc_sat_f32x4_u" or op == "i32x4.relaxed_trunc_f32x4_u" then
				local v = pop()
				local lanes = { string.unpack("<f<f<f<f", v) }
				local res = {}
				for i = 1, 4 do
					local f = lanes[i]
					res[i] = (f ~= f or f <= 0) and 0 or (f >= 4294967295 and 4294967295 or math.modf(f))
				end
				push(string.pack("<I4<I4<I4<I4", table.unpack(res, 1, 4)))
			elseif op == "i32x4.dot_i16x8_s" then
				local vb = pop()
				local va = pop()
				local a = { string.unpack("<i2<i2<i2<i2<i2<i2<i2<i2", va) }
				local b = { string.unpack("<i2<i2<i2<i2<i2<i2<i2<i2", vb) }
				local r = {}
				for i = 0, 3 do
					r[i + 1] = to_i32(a[2 * i + 1] * b[2 * i + 1] + a[2 * i + 2] * b[2 * i + 2])
				end
				push(string.pack("<i4<i4<i4<i4", table.unpack(r, 1, 4)))
			else
				local vb = pop()
				local va = pop()
				if op == "i32x4.add" then
					push(i32x4_binop(va, vb, function(a, b)
						return a + b
					end))
				elseif op == "i32x4.sub" then
					push(i32x4_binop(va, vb, function(a, b)
						return a - b
					end))
				elseif op == "i32x4.mul" then
					push(i32x4_binop(va, vb, function(a, b)
						return a * b
					end))
				elseif op == "i32x4.eq" then
					push(i32x4_binop(va, vb, function(a, b)
						return a == b and -1 or 0
					end))
				elseif op == "i32x4.ne" then
					push(i32x4_binop(va, vb, function(a, b)
						return a ~= b and -1 or 0
					end))
				elseif op == "i32x4.lt_s" then
					push(i32x4_binop(va, vb, function(a, b)
						return a < b and -1 or 0
					end))
				elseif op == "i32x4.lt_u" then
					push(i32x4_binop(va, vb, function(a, b)
						return to_u32(a) < to_u32(b) and -1 or 0
					end))
				elseif op == "i32x4.gt_s" then
					push(i32x4_binop(va, vb, function(a, b)
						return a > b and -1 or 0
					end))
				elseif op == "i32x4.gt_u" then
					push(i32x4_binop(va, vb, function(a, b)
						return to_u32(a) > to_u32(b) and -1 or 0
					end))
				elseif op == "i32x4.le_s" then
					push(i32x4_binop(va, vb, function(a, b)
						return a <= b and -1 or 0
					end))
				elseif op == "i32x4.le_u" then
					push(i32x4_binop(va, vb, function(a, b)
						return to_u32(a) <= to_u32(b) and -1 or 0
					end))
				elseif op == "i32x4.ge_s" then
					push(i32x4_binop(va, vb, function(a, b)
						return a >= b and -1 or 0
					end))
				elseif op == "i32x4.ge_u" then
					push(i32x4_binop(va, vb, function(a, b)
						return to_u32(a) >= to_u32(b) and -1 or 0
					end))
				elseif op == "i32x4.min_s" then
					push(i32x4_binop(va, vb, function(a, b)
						return math.min(a, b)
					end))
				elseif op == "i32x4.min_u" then
					push(i32x4_binop(va, vb, function(a, b)
						return math.min(to_u32(a), to_u32(b))
					end))
				elseif op == "i32x4.max_s" then
					push(i32x4_binop(va, vb, function(a, b)
						return math.max(a, b)
					end))
				elseif op == "i32x4.max_u" then
					push(i32x4_binop(va, vb, function(a, b)
						return math.max(to_u32(a), to_u32(b))
					end))
				else
					push(va)
				end
			end

		-- SIMD: i64x2 arithmetic & comparison
		elseif op:find("^i64x2%.") then
			if op == "i64x2.neg" then
				push(i64x2_binop(pop(), pop(), function(a)
					return -a
				end))
			else
				local vb = pop()
				local va = pop()
				if op == "i64x2.add" then
					push(i64x2_binop(va, vb, function(a, b)
						return a + b
					end))
				elseif op == "i64x2.sub" then
					push(i64x2_binop(va, vb, function(a, b)
						return a - b
					end))
				elseif op == "i64x2.mul" then
					push(i64x2_binop(va, vb, function(a, b)
						return a * b
					end))
				elseif op == "i64x2.eq" then
					push(i64x2_binop(va, vb, function(a, b)
						return a == b and -1 or 0
					end))
				elseif op == "i64x2.ne" then
					push(i64x2_binop(va, vb, function(a, b)
						return a ~= b and -1 or 0
					end))
				elseif op == "i64x2.lt_s" then
					push(i64x2_binop(va, vb, function(a, b)
						return a < b and -1 or 0
					end))
				elseif op == "i64x2.gt_s" then
					push(i64x2_binop(va, vb, function(a, b)
						return a > b and -1 or 0
					end))
				elseif op == "i64x2.le_s" then
					push(i64x2_binop(va, vb, function(a, b)
						return a <= b and -1 or 0
					end))
				elseif op == "i64x2.ge_s" then
					push(i64x2_binop(va, vb, function(a, b)
						return a >= b and -1 or 0
					end))
				else
					push(va)
				end
			end

		-- SIMD: f32x4 arithmetic & comparison
		elseif op:find("^f32x4%.") then
			if op == "f32x4.abs" then
				push(f32x4_binop(pop(), pop(), function(a)
					return math.abs(a)
				end))
			elseif op == "f32x4.neg" then
				push(f32x4_binop(pop(), pop(), function(a)
					return -a
				end))
			elseif op == "f32x4.sqrt" then
				push(f32x4_binop(pop(), pop(), function(a)
					return math.sqrt(a)
				end))
			elseif op == "f32x4.ceil" then
				push(f32x4_binop(pop(), pop(), function(a)
					return math.ceil(a)
				end))
			elseif op == "f32x4.floor" then
				push(f32x4_binop(pop(), pop(), function(a)
					return math.floor(a)
				end))
			elseif op == "f32x4.trunc" then
				push(f32x4_binop(pop(), pop(), function(a)
					return math.modf(a)
				end))
			elseif op == "f32x4.convert_i32x4_s" then
				local v = pop()
				local l = { string.unpack("<i4<i4<i4<i4", v) }
				push(string.pack("<f<f<f<f", l[1] * 1.0, l[2] * 1.0, l[3] * 1.0, l[4] * 1.0))
			elseif op == "f32x4.convert_i32x4_u" then
				local v = pop()
				local l = { string.unpack("<I4<I4<I4<I4", v) }
				push(string.pack("<f<f<f<f", l[1] * 1.0, l[2] * 1.0, l[3] * 1.0, l[4] * 1.0))
			elseif op == "f32x4.relaxed_madd" or op == "f32x4.relaxed_nmadd" then
				local c = pop()
				local b = pop()
				local a = pop()
				local la = { string.unpack("<f<f<f<f", a) }
				local lb = { string.unpack("<f<f<f<f", b) }
				local lc = { string.unpack("<f<f<f<f", c) }
				local r = {}
				for i = 1, 4 do
					local prod = la[i] * lb[i]
					r[i] = (op == "f32x4.relaxed_madd") and (prod + lc[i]) or (-prod + lc[i])
				end
				push(string.pack("<f<f<f<f", table.unpack(r, 1, 4)))
			else
				local vb = pop()
				local va = pop()
				if op == "f32x4.add" then
					push(f32x4_binop(va, vb, function(a, b)
						return a + b
					end))
				elseif op == "f32x4.sub" then
					push(f32x4_binop(va, vb, function(a, b)
						return a - b
					end))
				elseif op == "f32x4.mul" then
					push(f32x4_binop(va, vb, function(a, b)
						return a * b
					end))
				elseif op == "f32x4.div" then
					push(f32x4_binop(va, vb, function(a, b)
						return a / b
					end))
				elseif op == "f32x4.min" or op == "f32x4.relaxed_min" then
					push(f32x4_binop(va, vb, function(a, b)
						return math.min(a, b)
					end))
				elseif op == "f32x4.max" or op == "f32x4.relaxed_max" then
					push(f32x4_binop(va, vb, function(a, b)
						return math.max(a, b)
					end))
				elseif op == "f32x4.pmin" then
					push(f32x4_binop(va, vb, function(a, b)
						return (b < a) and b or a
					end))
				elseif op == "f32x4.pmax" then
					push(f32x4_binop(va, vb, function(a, b)
						return (a < b) and b or a
					end))
				elseif op == "f32x4.eq" then
					push(f32x4_binop(va, vb, function(a, b)
						return a == b and -1 or 0
					end))
				elseif op == "f32x4.ne" then
					push(f32x4_binop(va, vb, function(a, b)
						return a ~= b and -1 or 0
					end))
				elseif op == "f32x4.lt" then
					push(f32x4_binop(va, vb, function(a, b)
						return a < b and -1 or 0
					end))
				elseif op == "f32x4.le" then
					push(f32x4_binop(va, vb, function(a, b)
						return a <= b and -1 or 0
					end))
				elseif op == "f32x4.gt" then
					push(f32x4_binop(va, vb, function(a, b)
						return a > b and -1 or 0
					end))
				elseif op == "f32x4.ge" then
					push(f32x4_binop(va, vb, function(a, b)
						return a >= b and -1 or 0
					end))
				else
					push(va)
				end
			end

		-- SIMD: f64x2 arithmetic & comparison
		elseif op:find("^f64x2%.") then
			if op == "f64x2.abs" then
				push(f64x2_binop(pop(), pop(), function(a)
					return math.abs(a)
				end))
			elseif op == "f64x2.neg" then
				push(f64x2_binop(pop(), pop(), function(a)
					return -a
				end))
			elseif op == "f64x2.sqrt" then
				push(f64x2_binop(pop(), pop(), function(a)
					return math.sqrt(a)
				end))
			elseif op == "f64x2.ceil" then
				push(f64x2_binop(pop(), pop(), function(a)
					return math.ceil(a)
				end))
			elseif op == "f64x2.floor" then
				push(f64x2_binop(pop(), pop(), function(a)
					return math.floor(a)
				end))
			elseif op == "f64x2.trunc" then
				push(f64x2_binop(pop(), pop(), function(a)
					return math.modf(a)
				end))
			elseif op == "f64x2.relaxed_madd" or op == "f64x2.relaxed_nmadd" then
				local c = pop()
				local b = pop()
				local a = pop()
				local la = { string.unpack("<d<d", a) }
				local lb = { string.unpack("<d<d", b) }
				local lc = { string.unpack("<d<d", c) }
				local r = {}
				for i = 1, 2 do
					local prod = la[i] * lb[i]
					r[i] = (op == "f64x2.relaxed_madd") and (prod + lc[i]) or (-prod + lc[i])
				end
				push(string.pack("<d<d", table.unpack(r, 1, 2)))
			else
				local vb = pop()
				local va = pop()
				if op == "f64x2.add" then
					push(f64x2_binop(va, vb, function(a, b)
						return a + b
					end))
				elseif op == "f64x2.sub" then
					push(f64x2_binop(va, vb, function(a, b)
						return a - b
					end))
				elseif op == "f64x2.mul" then
					push(f64x2_binop(va, vb, function(a, b)
						return a * b
					end))
				elseif op == "f64x2.div" then
					push(f64x2_binop(va, vb, function(a, b)
						return a / b
					end))
				elseif op == "f64x2.min" or op == "f64x2.relaxed_min" then
					push(f64x2_binop(va, vb, function(a, b)
						return math.min(a, b)
					end))
				elseif op == "f64x2.max" or op == "f64x2.relaxed_max" then
					push(f64x2_binop(va, vb, function(a, b)
						return math.max(a, b)
					end))
				elseif op == "f64x2.pmin" then
					push(f64x2_binop(va, vb, function(a, b)
						return (b < a) and b or a
					end))
				elseif op == "f64x2.pmax" then
					push(f64x2_binop(va, vb, function(a, b)
						return (a < b) and b or a
					end))
				elseif op == "f64x2.eq" then
					push(f64x2_binop(va, vb, function(a, b)
						return a == b and -1 or 0
					end))
				elseif op == "f64x2.ne" then
					push(f64x2_binop(va, vb, function(a, b)
						return a ~= b and -1 or 0
					end))
				elseif op == "f64x2.lt" then
					push(f64x2_binop(va, vb, function(a, b)
						return a < b and -1 or 0
					end))
				elseif op == "f64x2.le" then
					push(f64x2_binop(va, vb, function(a, b)
						return a <= b and -1 or 0
					end))
				elseif op == "f64x2.gt" then
					push(f64x2_binop(va, vb, function(a, b)
						return a > b and -1 or 0
					end))
				elseif op == "f64x2.ge" then
					push(f64x2_binop(va, vb, function(a, b)
						return a >= b and -1 or 0
					end))
				else
					push(va)
				end
			end
		else
			error(string.format("unimplemented opcode: '%s' at pc=%d", op, pc))
		end

		pc = pc + 1
	end

	-- Return results according to function signature
	local result_count = sig and #sig.results or 0
	if result_count == 0 then
		return
	elseif result_count == 1 then
		return stack[sp]
	else
		local rets = {}
		for i = 1, result_count do
			rets[i] = stack[sp - result_count + i]
		end
		return table.unpack(rets)
	end
end

--------------------------------------------------------------------------------
-- Instantiation & Linking
--------------------------------------------------------------------------------

--- Instantiate a decoded WebAssembly module with provided imports.
--- @param mod_or_path table|string Decoded module or file path.
--- @param import_object table|nil Map of module_name -> { field_name -> host_item }.
--- @return table Instance Instantiated module instance.
function Runtime.instantiate(mod_or_path, import_object)
	import_object = import_object or {}
	local auto_stub = import_object.auto_stub == true
	local mod
	if type(mod_or_path) == "string" then
		mod = decoder.decode_file(mod_or_path)
	elseif type(mod_or_path) == "table" and mod_or_path.sections then
		mod = mod_or_path
	else
		error("Expected decoded module table or file path string, got " .. type(mod_or_path))
	end

	local instance = setmetatable({
		module = mod,
		types = {},
		funcs = {},
		memories = {},
		tables = {},
		globals = {},
		exports = {},
		fuel = import_object.fuel or (import_object.limits and import_object.limits.fuel),
		deadline = (import_object.timeout or (import_object.limits and import_object.limits.timeout))
				and (os.clock() + (import_object.timeout or import_object.limits.timeout))
			or nil,
	}, Instance)

	-- 1. Types
	local type_sec = mod:get_section("type_section")
	if type_sec and type_sec.types then
		for i, ty in ipairs(type_sec.types) do
			instance.types[i] = ty
		end
	end

	-- 2. Imports
	local import_sec = mod:get_section("import_section")
	if import_sec and import_sec.imports then
		for _, imp in ipairs(import_sec.imports) do
			local mod_imports = import_object[imp.module]
			local host_item = mod_imports and mod_imports[imp.field]

			if imp.desc == opcodes.DESC_FUNC then
				if type(host_item) ~= "function" then
					if auto_stub then
						local signature = instance.types[imp.index]
						host_item = function()
							local result_count = signature and #signature.results or 0
							if result_count == 0 then
								return
							end
							local values = {}
							for i = 1, result_count do
								values[i] = 0
							end
							return table.unpack(values)
						end
					else
						error(string.format("Missing required function import: '%s.%s'", imp.module, imp.field))
					end
				end
				local sig = instance.types[imp.index]
				instance.funcs[#instance.funcs + 1] = {
					is_host = true,
					host_fn = host_item,
					type = sig,
				}
			elseif imp.desc == opcodes.DESC_TABLE then
				if host_item then
					instance.tables[#instance.tables + 1] = host_item
				else
					instance.tables[#instance.tables + 1] = Table:new(imp.min, imp.max, imp.type)
				end
			elseif imp.desc == opcodes.DESC_MEM then
				if host_item then
					instance.memories[#instance.memories + 1] = host_item
				else
					instance.memories[#instance.memories + 1] = Memory:new(imp.min, imp.max)
				end
			elseif imp.desc == opcodes.DESC_GLOBAL then
				local val = type(host_item) == "number" and host_item or (host_item and host_item.value or 0)
				instance.globals[#instance.globals + 1] = Global:new(val, imp.type, imp.mutable)
			end
		end
	end

	-- 3. Defined Tables
	local tbl_sec = mod:get_section("table_section")
	if tbl_sec and tbl_sec.tables then
		for _, tbl in ipairs(tbl_sec.tables) do
			instance.tables[#instance.tables + 1] = Table:new(tbl.min, tbl.max, tbl.type)
		end
	end

	-- 4. Defined Memories
	local mem_sec = mod:get_section("mem_section")
	if mem_sec and mem_sec.memory then
		for _, m in ipairs(mem_sec.memory) do
			instance.memories[#instance.memories + 1] = Memory:new(m.min, m.max, m.page_size)
		end
	end

	-- 5. Defined Globals
	local glob_sec = mod:get_section("global_section")
	if glob_sec and glob_sec.globals then
		for _, g in ipairs(glob_sec.globals) do
			local init_val = g.value or 0
			if g.op == opcodes.INSTR_GLOBAL_GET and g.global_index then
				local src_glob = instance.globals[g.global_index]
				if src_glob then
					init_val = src_glob:get()
				end
			end
			instance.globals[#instance.globals + 1] = Global:new(init_val, g.type, g.mutable)
		end
	end

	-- 6. Defined Functions
	local func_sec = mod:get_section("func_section")
	local code_sec = mod:get_section("code_section")
	if func_sec and code_sec and code_sec.code then
		for i, code_entry in ipairs(code_sec.code) do
			local type_idx = func_sec.indices[i]
			local sig = instance.types[type_idx + 1]
			local insns = disassembler.disasm_function(code_entry)
			precompute_control_flow(insns)

			instance.funcs[#instance.funcs + 1] = {
				is_host = false,
				type = sig,
				type_index = type_idx,
				locals = code_entry.locals,
				instructions = insns,
			}
		end
	end

	-- 7. Element Segments (Table Initialization)
	local elem_sec = mod:get_section("element_section")
	if elem_sec and elem_sec.elements then
		for _, el in ipairs(elem_sec.elements) do
			if (el.flag & 1) == 0 then -- active segment
				local tbl = instance.tables[(el.table_index or 0) + 1]
				local offset = type(el.offset) == "number" and el.offset or (el.offset and el.offset.value or 0)
				if tbl then
					if el.functions then
						for j, f_idx in ipairs(el.functions) do
							tbl:set(offset + j - 1, instance.funcs[f_idx])
						end
					elseif el.expressions then
						for j, expr in ipairs(el.expressions) do
							local fn = expr.function_index and instance.funcs[expr.function_index] or nil
							tbl:set(offset + j - 1, fn)
						end
					end
				end
			end
		end
	end

	-- 8. Data Segments (Memory Initialization)
	local data_sec = mod:get_section("data_section")
	local data_entries = data_sec and (data_sec.entries or data_sec.data)
	if data_entries then
		for _, d in ipairs(data_entries) do
			if (d.flag & 1) == 0 then -- active segment
				local mem = instance.memories[(d.memory_index or 0) + 1]
				local offset = type(d.offset) == "number" and d.offset or (d.offset and d.offset.value or 0)
				local bytes = d.data or d.bytes
				if not bytes and d.source and d.data_start and d.size then
					bytes = d.source:sub(d.data_start, d.data_start + d.size - 1)
				end
				if mem and bytes then
					mem:init_from_string(offset, bytes, 0, #bytes)
				end
			end
		end
	end

	-- 9. Exports & Callable Dispatcher
	local export_sec = mod:get_section("export_section")
	if export_sec and export_sec.exports then
		for _, exp in ipairs(export_sec.exports) do
			if exp.desc == opcodes.DESC_FUNC then
				local f = instance.funcs[exp.index + 1]
				instance.exports[exp.name] = function(...)
					return instance:invoke_function(f, { ... })
				end
			elseif exp.desc == opcodes.DESC_TABLE then
				instance.exports[exp.name] = instance.tables[exp.index + 1]
			elseif exp.desc == opcodes.DESC_MEM then
				instance.exports[exp.name] = instance.memories[exp.index + 1]
			elseif exp.desc == opcodes.DESC_GLOBAL then
				instance.exports[exp.name] = instance.globals[exp.index + 1]
			end
		end
	end

	-- 10. Start Section
	local start_sec = mod:get_section("start_section")
	if start_sec and start_sec.index then
		local start_func = instance.funcs[start_sec.index + 1]
		if start_func then
			instance:invoke_function(start_func, {})
		end
	end

	return instance
end

Runtime.Memory = Memory
Runtime.Table = Table
Runtime.Global = Global
Runtime.Instance = Instance

return Runtime
