local Binary = {}
Binary.__index = Binary

local native
local native_module
if os.getenv("LWASM_PURE_LUA") ~= "1" then
	local loaded, module = pcall(require, "lwasm_native")
	if loaded then
		native_module = module
		native = native_module
	end
end

Binary.native_enabled = native ~= nil

--- Select the integer decoder backend at runtime.
--- @param backend string "lua", "native", or "auto"
--- @return string active_backend
function Binary.set_backend(backend)
	if backend == "lua" then
		native = nil
	elseif backend == "native" or backend == "auto" then
		if not native_module then
			local loaded, module = pcall(require, "lwasm_native")
			if loaded then
				native_module = module
			end
		end
		if backend == "native" and not native_module then
			error("Native backend is not available", 2)
		end
		native = native_module
	else
		error("Unknown backend '" .. tostring(backend) .. "'; expected 'lua', 'native', or 'auto'", 2)
	end
	Binary.native_enabled = native ~= nil
	return native and "native" or "lua"
end

function Binary.get_backend()
	return native and "native" or "lua"
end

function Binary.available_backends()
	local backends = { "lua" }
	if not native_module then
		local loaded, module = pcall(require, "lwasm_native")
		if loaded then
			native_module = module
		end
	end
	if native_module then
		backends[#backends + 1] = "native"
	end
	return backends
end

--- Create a new Binary reader instance.
--- @param data string The binary data string to read.
--- @return table Binary reader instance.
function Binary:new(data)
	local obj = {
		data = data or "",
		cursor = 1,
	}
	setmetatable(obj, self)
	return obj
end

--- Ensure that at least `n` bytes are available from current cursor.
--- @param n integer Number of bytes required.
function Binary:assert_bytes(n)
	if self.cursor + n - 1 > #self.data then
		error(
			string.format(
				"Unexpected EOF: attempted to read %d byte(s) at offset 0x%X (%d), but only %d byte(s) remain",
				n,
				self.cursor,
				self.cursor,
				math.max(0, #self.data - self.cursor + 1)
			)
		)
	end
end

--- Check if the cursor has reached or passed the end of data.
--- @return boolean
function Binary:is_EOF()
	return self.cursor > #self.data
end

--- Alias for is_EOF()
function Binary:eof()
	return self:is_EOF()
end

--- Number of remaining bytes available to read.
--- @return integer
function Binary:remaining()
	return math.max(0, #self.data - self.cursor + 1)
end

--- Set the cursor to an absolute offset (1-based).
--- @param offset integer
function Binary:seek(offset)
	self.cursor = offset
end

--- Return current cursor position (1-based).
--- @return integer
function Binary:tell()
	return self.cursor
end

--- Advance cursor by `offset` bytes.
--- @param offset integer
function Binary:inc(offset)
	self.cursor = self.cursor + offset
end

--- Alias for inc()
function Binary:skip(offset)
	self:inc(offset)
end

--- Peek at next byte without advancing cursor.
--- @return integer Byte value (0-255).
function Binary:peek_byte()
	self:assert_bytes(1)
	return string.byte(self.data, self.cursor)
end

--- Read single unsigned byte (0-255) and advance cursor by 1.
--- @return integer
function Binary:read_byte()
	self:assert_bytes(1)
	local byte = string.byte(self.data, self.cursor)
	self.cursor = self.cursor + 1
	return byte
end

--- Read signed 8-bit integer (-128 to 127).
--- @return integer
function Binary:read_i8()
	self:assert_bytes(1)
	local val, next_pos = string.unpack("<b", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read a slice of string of given length and advance cursor.
--- @param length integer
--- @return string
function Binary:slice(length)
	if length <= 0 then
		return ""
	end
	self:assert_bytes(length)
	local s = string.sub(self.data, self.cursor, self.cursor + length - 1)
	self.cursor = self.cursor + length
	return s
end

--- Alias for slice(length)
function Binary:read_str(length)
	return self:slice(length)
end

--- Read a WebAssembly-style length-prefixed string (u32LEB length followed by UTF-8 bytes).
--- @return string
function Binary:read_name()
	local length = self:read_u32LEB()
	return self:slice(length)
end

--- Read bytes as an array of integer values [0-255].
--- Safe against Lua stack overflow on large buffers.
--- @param length integer
--- @return integer[]
function Binary:read_bytes(length)
	if length <= 0 then
		return {}
	end
	self:assert_bytes(length)

	local bytes = {}
	if length <= 2048 then
		bytes = { string.byte(self.data, self.cursor, self.cursor + length - 1) }
	else
		local start = self.cursor
		local finish = start + length - 1
		for i = start, finish, 2048 do
			local chunk_end = math.min(i + 2047, finish)
			local chunk = { string.byte(self.data, i, chunk_end) }
			for j = 1, #chunk do
				bytes[#bytes + 1] = chunk[j]
			end
		end
	end
	self.cursor = self.cursor + length
	return bytes
end

--- Create a new child Binary reader instance for a slice of `length` bytes.
--- Advances the parent reader's cursor by `length`.
--- @param length integer
--- @return table Binary child instance.
function Binary:sub_reader(length)
	return Binary:new(self:slice(length))
end

--- Read unsigned 16-bit integer (little-endian).
--- @return integer
function Binary:read_u16()
	self:assert_bytes(2)
	local val, next_pos = string.unpack("<I2", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read signed 16-bit integer (little-endian).
--- @return integer
function Binary:read_i16()
	self:assert_bytes(2)
	local val, next_pos = string.unpack("<i2", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read unsigned 32-bit integer (little-endian).
--- @return integer
function Binary:read_u32()
	self:assert_bytes(4)
	local val, next_pos = string.unpack("<I4", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read signed 32-bit integer (little-endian).
--- @return integer
function Binary:read_i32()
	self:assert_bytes(4)
	local val, next_pos = string.unpack("<i4", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read unsigned 64-bit integer (little-endian).
--- @return integer
function Binary:read_u64()
	self:assert_bytes(8)
	local val, next_pos = string.unpack("<I8", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read signed 64-bit integer (little-endian).
--- @return integer
function Binary:read_i64()
	self:assert_bytes(8)
	local val, next_pos = string.unpack("<i8", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read 32-bit IEEE-754 float (little-endian).
--- @return number
function Binary:read_f32()
	self:assert_bytes(4)
	local val, next_pos = string.unpack("<f", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

--- Read 64-bit IEEE-754 float (double, little-endian).
--- @return number
function Binary:read_f64()
	self:assert_bytes(8)
	local val, next_pos = string.unpack("<d", self.data, self.cursor)
	self.cursor = next_pos
	return val
end

-- Backward compatibility aliases: WebAssembly floats are IEEE-754, not LEB,
-- but the original code named them read_f32LEB/read_f64LEB.
Binary.read_f32LEB = Binary.read_f32
Binary.read_f64LEB = Binary.read_f64

local function leb_error(kind, offset, reason)
	error(string.format("Invalid %s at offset 0x%X: %s", kind, offset, reason), 3)
end

--- Decode a bounded LEB128 value in one pass. Returning scalar metadata avoids
--- allocating a temporary byte table for every integer in a module.
local function read_leb(self, kind, max_bytes)
	local offset = self.cursor
	local result = 0
	for i = 1, max_bytes do
		if self.cursor > #self.data then
			error(string.format("Unexpected EOF while reading %s at offset 0x%X", kind, self.cursor), 3)
		end
		local byte = string.byte(self.data, self.cursor)
		self.cursor = self.cursor + 1
		result = result | ((byte & 0x7F) << ((i - 1) * 7))
		if (byte & 0x80) == 0 then
			return result, byte, i, offset
		end
	end
	leb_error(kind, offset, "encoding exceeds " .. max_bytes .. " bytes")
end

--- Read unsigned LEB128 integer (u32 in Wasm, up to 5 bytes).
--- @return integer
function Binary:read_u32LEB()
	local cursor = self.cursor
	if cursor > #self.data then
		error(string.format("Unexpected EOF while reading u32LEB at offset 0x%X", cursor), 2)
	end
	local byte = string.byte(self.data, cursor)
	if byte < 0x80 then
		self.cursor = cursor + 1
		return byte
	end
	if native then
		return native.read_u32_leb(self)
	end
	self.cursor = cursor + 1

	local result = byte & 0x7F
	for i = 2, 5 do
		cursor = self.cursor
		if cursor > #self.data then
			error(string.format("Unexpected EOF while reading u32LEB at offset 0x%X", cursor), 2)
		end
		byte = string.byte(self.data, cursor)
		self.cursor = cursor + 1
		result = result | ((byte & 0x7F) << ((i - 1) * 7))
		if byte < 0x80 then
			if i == 5 and (byte & 0x7F) > 0x0F then
				leb_error("u32LEB", self.cursor - i, "unused high bits must be zero")
			end
			return result
		end
	end
	leb_error("u32LEB", self.cursor - 5, "encoding exceeds 5 bytes")
end

--- Read signed LEB128 integer (i32 in Wasm, up to 5 bytes).
--- @return integer
function Binary:read_i32LEB()
	if native then
		local cursor = self.cursor
		if cursor > #self.data then
			error(string.format("Unexpected EOF while reading i32LEB at offset 0x%X", cursor), 2)
		end
		local byte = string.byte(self.data, cursor)
		if byte < 0x80 then
			self.cursor = cursor + 1
			return byte < 0x40 and byte or byte - 0x80
		end
		return native.read_i32_leb(self)
	end
	local result, last, count, offset = read_leb(self, "i32LEB", 5)
	if count == 5 then
		local payload = last & 0x7F
		if payload > 0x07 and payload < 0x78 then
			leb_error("i32LEB", offset, "unused high bits do not match the sign bit")
		end
	end
	result = result & 0xFFFFFFFF
	if result >= 0x80000000 then
		result = result - 0x100000000
	elseif count < 5 and (last & 0x40) ~= 0 then
		result = result | (~0 << (count * 7))
	end
	return result
end

--- Read signed LEB128 integer (i64 in Wasm, up to 10 bytes).
--- @return integer
function Binary:read_i64LEB()
	if native then
		local cursor = self.cursor
		if cursor > #self.data then
			error(string.format("Unexpected EOF while reading i64LEB at offset 0x%X", cursor), 2)
		end
		local byte = string.byte(self.data, cursor)
		if byte < 0x80 then
			self.cursor = cursor + 1
			return byte < 0x40 and byte or byte - 0x80
		end
		return native.read_i64_leb(self)
	end
	local result, last, count, offset = read_leb(self, "i64LEB", 10)
	if count == 10 then
		local payload = last & 0x7F
		if payload ~= 0x00 and payload ~= 0x7F then
			leb_error("i64LEB", offset, "unused high bits do not match the sign bit")
		end
	end
	if count < 10 and (last & 0x40) ~= 0 then
		result = result | (~0 << (count * 7))
	end
	return result
end

--- Read unsigned LEB128 integer (u64 in Wasm, up to 10 bytes).
--- @return integer
function Binary:read_u64LEB()
	if native then
		local cursor = self.cursor
		if cursor > #self.data then
			error(string.format("Unexpected EOF while reading u64LEB at offset 0x%X", cursor), 2)
		end
		local byte = string.byte(self.data, cursor)
		if byte < 0x80 then
			self.cursor = cursor + 1
			return byte
		end
		return native.read_u64_leb(self)
	end
	local result, last, count, offset = read_leb(self, "u64LEB", 10)
	if count == 10 and (last & 0x7F) > 0x01 then
		leb_error("u64LEB", offset, "unused high bits must be zero")
	end
	return result
end

--- Read a WebAssembly vector: count (u32LEB) followed by elements parsed by `reader_fn(bin, index)`.
--- @param reader_fn fun(bin: table, index: integer): any
--- @return table items, integer count
function Binary:read_vec(reader_fn)
	local count = self:read_u32LEB()
	local items = {}
	for i = 1, count do
		items[i] = reader_fn(self, i)
	end
	return items, count
end

return Binary
