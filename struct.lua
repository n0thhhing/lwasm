--- struct.lua - C struct layout definition and memory deserialization for lwasm
--- Supports automatic alignment detection, padding calculation, and zero-copy views.
---@diagnostic disable: undefined-global

local Struct = {}
Struct.__index = Struct

--- Type descriptor registry with size, alignment, and load/store methods.
local PRIMITIVE_TYPES = {
	u8 = { size = 1, align = 1, read = "load_u8", write = "store_i8" },
	i8 = { size = 1, align = 1, read = "load_i8", write = "store_i8" },
	uint8 = { size = 1, align = 1, read = "load_u8", write = "store_i8" },
	int8 = { size = 1, align = 1, read = "load_i8", write = "store_i8" },
	byte = { size = 1, align = 1, read = "load_u8", write = "store_i8" },
	char = { size = 1, align = 1, read = "load_i8", write = "store_i8" },
	bool = {
		size = 1,
		align = 1,
		read_fn = function(mem, addr)
			return mem:load_u8(addr) ~= 0
		end,
		write_fn = function(mem, addr, val)
			mem:store_i8(addr, val and 1 or 0)
		end,
	},

	u16 = { size = 2, align = 2, read = "load_u16", write = "store_i16" },
	i16 = { size = 2, align = 2, read = "load_i16", write = "store_i16" },
	uint16 = { size = 2, align = 2, read = "load_u16", write = "store_i16" },
	int16 = { size = 2, align = 2, read = "load_i16", write = "store_i16" },
	short = { size = 2, align = 2, read = "load_i16", write = "store_i16" },

	u32 = { size = 4, align = 4, read = "load_u32", write = "store_i32" },
	i32 = { size = 4, align = 4, read = "load_i32", write = "store_i32" },
	uint32 = { size = 4, align = 4, read = "load_u32", write = "store_i32" },
	int32 = { size = 4, align = 4, read = "load_i32", write = "store_i32" },
	uint = { size = 4, align = 4, read = "load_u32", write = "store_i32" },
	int = { size = 4, align = 4, read = "load_i32", write = "store_i32" },
	f32 = { size = 4, align = 4, read = "load_f32", write = "store_f32" },
	float = { size = 4, align = 4, read = "load_f32", write = "store_f32" },

	u64 = { size = 8, align = 8, read = "load_i64", write = "store_i64" },
	i64 = { size = 8, align = 8, read = "load_i64", write = "store_i64" },
	uint64 = { size = 8, align = 8, read = "load_i64", write = "store_i64" },
	int64 = { size = 8, align = 8, read = "load_i64", write = "store_i64" },
	f64 = { size = 8, align = 8, read = "load_f64", write = "store_f64" },
	double = { size = 8, align = 8, read = "load_f64", write = "store_f64" },
}

--- Helper: Read bounded cstring from memory
local function read_bounded_cstring(mem, addr, max_len)
	local parts = {}
	for i = 0, max_len - 1 do
		local b = mem:read_byte(addr + i)
		if b == 0 then
			break
		end
		parts[#parts + 1] = string.char(b)
	end
	return table.concat(parts)
end

--- Helper: Write bounded cstring to memory (null-terminated and zero-padded)
local function write_bounded_cstring(mem, addr, str, max_len)
	str = tostring(str or "")
	local len = math.min(#str, max_len - 1)
	for i = 0, len - 1 do
		mem:write_byte(addr + i, string.byte(str, i + 1))
	end
	for i = len, max_len - 1 do
		mem:write_byte(addr + i, 0)
	end
end

--- Helper: Resolve pointer type characteristics based on options
local function get_pointer_info(opts)
	local is_64 = opts and (opts.arch == "wasm64" or opts.ptr_size == 8)
	if is_64 then
		return { size = 8, align = 8, read = "load_i64", write = "store_i64" }
	end
	return { size = 4, align = 4, read = "load_u32", write = "store_i32" }
end

--- Return the size and alignment of a type name or Struct instance.
--- @param type_desc string|table Type name or Struct instance
--- @param opts table|nil Options (e.g. arch = "wasm64")
--- @return integer size, integer align
function Struct.type_traits(type_desc, opts)
	if type(type_desc) == "table" and type_desc.is_struct then
		return type_desc.size, type_desc.align
	elseif type_desc == "ptr" or type_desc == "pointer" or type_desc == "uintptr" or type_desc == "size_t" then
		local ptr_info = get_pointer_info(opts)
		return ptr_info.size, ptr_info.align
	elseif PRIMITIVE_TYPES[type_desc] then
		local t = PRIMITIVE_TYPES[type_desc]
		return t.size, t.align
	end
	error("Unknown type: " .. tostring(type_desc), 2)
end

--- Define a new C-compatible Struct layout with automatic alignment detection.
--- @param fields table Array of field definitions
--- @param opts table|nil Options:
---   - align (boolean): Enable natural alignment padding (default: true)
---   - packed (boolean): If true, pack all fields with 1-byte alignment (equivalent to align = false)
---   - pack (integer): Max alignment boundary (e.g. 1, 2, 4), matching `#pragma pack(N)`
---   - arch (string): Target architecture ("wasm32" [default] or "wasm64")
---   - strict (boolean): If true, raise error on unaligned memory access (default: false)
---   - check_align (boolean): Alias for strict
--- @return table Struct layout object
function Struct.new(fields, opts)
	opts = opts or {}
	local ptr_info = get_pointer_info(opts)

	local natural_align = (opts.align ~= false) and not opts.packed
	local pack_limit = opts.pack
	local is_strict = opts.strict or opts.check_align or false

	local current_offset = 0
	local max_align = 1
	local parsed_fields = {}
	local offsets = {}
	local field_map = {}

	for idx, def in ipairs(fields) do
		local name, type_desc, count, extra

		if type(def) == "table" then
			if def[1] ~= nil then
				name = def[1]
				type_desc = def[2]
				if type(def[3]) == "number" then
					count = def[3]
					extra = def[4] or def
				elseif type(def[3]) == "table" then
					extra = def[3]
				else
					extra = def
				end
			else
				name = def.name
				type_desc = def.type
				count = def.count or def.length
				extra = def
			end
		else
			error(string.format("Field %d must be a table", idx), 2)
		end

		if not name or not type_desc then
			error(string.format("Field %d requires a name and type", idx), 2)
		end

		extra = extra or {}
		local field_size, field_align
		local is_array = false
		local is_nested_struct = false
		local is_cstring = false
		local is_bytes = false
		local prim_info = nil

		if type(type_desc) == "table" and type_desc.is_struct then
			is_nested_struct = true
			field_size = type_desc.size
			field_align = type_desc.align
		elseif type_desc == "ptr" or type_desc == "pointer" or type_desc == "uintptr" or type_desc == "size_t" then
			prim_info = ptr_info
			field_size = prim_info.size
			field_align = prim_info.align
		elseif PRIMITIVE_TYPES[type_desc] then
			prim_info = PRIMITIVE_TYPES[type_desc]
			if count and count > 1 then
				is_array = true
				field_size = prim_info.size * count
				field_align = prim_info.align
			else
				field_size = prim_info.size
				field_align = prim_info.align
			end
		elseif type_desc == "cstring" or type_desc == "string" then
			if not count or count <= 0 then
				error(string.format("Field '%s' of type '%s' requires a buffer size", name, type_desc), 2)
			end
			is_cstring = true
			field_size = count
			field_align = 1
		elseif type_desc == "bytes" then
			if not count or count <= 0 then
				error(string.format("Field '%s' of type 'bytes' requires a byte length", name, count), 2)
			end
			is_bytes = true
			field_size = count
			field_align = 1
		else
			error(string.format("Unknown field type '%s' in field '%s'", tostring(type_desc), name), 2)
		end

		-- Explicit field alignment override if provided
		if extra.align then
			field_align = extra.align
		elseif not natural_align then
			field_align = 1
		elseif pack_limit then
			field_align = math.min(field_align, pack_limit)
		end

		-- Explicit field offset override if provided
		local field_offset
		if extra.offset then
			field_offset = extra.offset
			current_offset = field_offset
		else
			-- Detect and apply alignment padding
			if natural_align and field_align > 1 then
				local rem = current_offset % field_align
				if rem ~= 0 then
					current_offset = current_offset + (field_align - rem)
				end
			end
			field_offset = current_offset
		end

		if field_align > max_align then
			max_align = field_align
		end

		current_offset = current_offset + field_size

		local field_obj = {
			name = name,
			type = type_desc,
			offset = field_offset,
			size = field_size,
			align = field_align,
			count = count,
			prim_info = prim_info,
			is_nested_struct = is_nested_struct,
			is_array = is_array,
			is_cstring = is_cstring,
			is_bytes = is_bytes,
			sub_struct = is_nested_struct and type_desc or nil,
			length_field = extra.length_field or extra.trim,
		}

		parsed_fields[#parsed_fields + 1] = field_obj
		offsets[name] = field_offset
		field_map[name] = field_obj
	end

	-- Total struct alignment
	local struct_align = natural_align and max_align or 1
	if pack_limit then
		struct_align = math.min(struct_align, pack_limit)
	end
	if opts.align_override then
		struct_align = opts.align_override
	end

	-- Tail padding to make struct size a multiple of struct alignment
	if natural_align and struct_align > 1 then
		local rem = current_offset % struct_align
		if rem ~= 0 then
			current_offset = current_offset + (struct_align - rem)
		end
	end

	local obj = {
		is_struct = true,
		size = current_offset,
		align = struct_align,
		fields = parsed_fields,
		offsets = offsets,
		field_map = field_map,
		strict = is_strict,
		ptr_info = ptr_info,
	}

	return setmetatable(obj, Struct)
end

--- Check whether an address satisfies the struct's alignment requirement.
--- @param addr integer Address in linear memory
--- @return boolean is_aligned, string|nil error_message
function Struct:check_alignment(addr)
	if (addr % self.align) ~= 0 then
		local msg = string.format("Unaligned address 0x%X (requires %d-byte alignment)", addr, self.align)
		if self.strict then
			error(msg, 2)
		end
		return false, msg
	end
	return true, nil
end

--- Read a single field value from memory at base address.
--- @param mem table Memory object
--- @param base integer Base struct address
--- @param f table Field descriptor
--- @return any Field value
local function read_field(mem, base, f)
	local addr = base + f.offset
	if f.prim_info then
		if f.is_array then
			local item_size = f.prim_info.size
			local arr = {}
			for i = 0, f.count - 1 do
				local item_addr = addr + i * item_size
				if f.prim_info.read_fn then
					arr[i + 1] = f.prim_info.read_fn(mem, item_addr)
				else
					arr[i + 1] = mem[f.prim_info.read](mem, item_addr)
				end
			end
			return arr
		else
			if f.prim_info.read_fn then
				return f.prim_info.read_fn(mem, addr)
			end
			return mem[f.prim_info.read](mem, addr)
		end
	elseif f.is_cstring then
		return read_bounded_cstring(mem, addr, f.count)
	elseif f.is_bytes then
		return mem:read_string(addr, f.count)
	elseif f.is_nested_struct then
		return f.sub_struct:read(mem, addr)
	end
	error("Cannot read field of type " .. tostring(f.type))
end

--- Write a single field value to memory at base address.
--- @param mem table Memory object
--- @param base integer Base struct address
--- @param f table Field descriptor
--- @param val any Value to write
local function write_field(mem, base, f, val)
	local addr = base + f.offset
	if f.prim_info then
		if f.is_array then
			local item_size = f.prim_info.size
			local tbl = val or {}
			for i = 0, f.count - 1 do
				local item_addr = addr + i * item_size
				local item_val = tbl[i + 1] or 0
				if f.prim_info.write_fn then
					f.prim_info.write_fn(mem, item_addr, item_val)
				else
					mem[f.prim_info.write](mem, item_addr, item_val)
				end
			end
		else
			if f.prim_info.write_fn then
				f.prim_info.write_fn(mem, addr, val)
			else
				mem[f.prim_info.write](mem, addr, val or 0)
			end
		end
	elseif f.is_cstring then
		write_bounded_cstring(mem, addr, val, f.count)
	elseif f.is_bytes then
		local s = tostring(val or "")
		if #s < f.count then
			s = s .. string.rep("\0", f.count - #s)
		elseif #s > f.count then
			s = s:sub(1, f.count)
		end
		mem:write_string(addr, s)
	elseif f.is_nested_struct then
		f.sub_struct:write(mem, addr, val or {})
	end
end

--- Deserialize a struct from linear memory into a Lua table.
--- @param mem table Memory instance
--- @param base integer Starting address in linear memory
--- @return table Decoded struct table
function Struct:read(mem, base)
	if self.strict then
		self:check_alignment(base)
	end
	local res = {}
	for _, f in ipairs(self.fields) do
		res[f.name] = read_field(mem, base, f)
	end

	-- Apply dynamic length trimming if specified (e.g. length_field = "size")
	for _, f in ipairs(self.fields) do
		if f.length_field and res[f.length_field] and type(res[f.name]) == "string" then
			local target_len = res[f.length_field]
			if target_len < #res[f.name] then
				res[f.name] = res[f.name]:sub(1, target_len)
			end
		end
	end

	return res
end

--- Serialize a Lua table into linear memory according to the struct layout.
--- @param mem table Memory instance
--- @param base integer Starting address in linear memory
--- @param data table Table with field values
function Struct:write(mem, base, data)
	if self.strict then
		self:check_alignment(base)
	end
	for _, f in ipairs(self.fields) do
		if data[f.name] ~= nil then
			write_field(mem, base, f, data[f.name])
		end
	end
end

--- Deserialize an array of contiguous structs from linear memory.
--- @param mem table Memory instance
--- @param base integer Starting address in linear memory
--- @param count integer Number of struct instances to read
--- @return table Array of decoded struct tables
function Struct:read_array(mem, base, count)
	if self.strict then
		self:check_alignment(base)
	end
	local result = {}
	local stride = self.size
	for i = 0, count - 1 do
		result[i + 1] = self:read(mem, base + i * stride)
	end
	return result
end

--- Serialize an array of tables into contiguous structs in linear memory.
--- @param mem table Memory instance
--- @param base integer Starting address in linear memory
--- @param data_list table Array of tables
function Struct:write_array(mem, base, data_list)
	if self.strict then
		self:check_alignment(base)
	end
	local stride = self.size
	for i, data in ipairs(data_list) do
		self:write(mem, base + (i - 1) * stride, data)
	end
end

--- Create a zero-copy proxy / view over a struct in linear memory.
--- Field accesses dynamically read/write linear memory without copying.
--- @param mem table Memory instance
--- @param base integer Starting address in linear memory
--- @return table Proxy object
function Struct:view(mem, base)
	if self.strict then
		self:check_alignment(base)
	end

	local proxy = {}
	local self_struct = self

	local mt = {
		__index = function(_, key)
			if key == "to_table" then
				return function()
					return self_struct:read(mem, base)
				end
			elseif key == "_address" or key == "address" and not self_struct.field_map["address"] then
				return base
			elseif key == "_size" then
				return self_struct.size
			elseif key == "_struct" then
				return self_struct
			end

			local f = self_struct.field_map[key]
			if f then
				local val = read_field(mem, base, f)
				if f.length_field and type(val) == "string" then
					local len_f = self_struct.field_map[f.length_field]
					if len_f then
						local len_val = read_field(mem, base, len_f)
						if type(len_val) == "number" and len_val < #val then
							val = val:sub(1, len_val)
						end
					end
				end
				return val
			end
			return nil
		end,

		__newindex = function(_, key, val)
			local f = self_struct.field_map[key]
			if f then
				write_field(mem, base, f, val)
			else
				rawset(proxy, key, val)
			end
		end,

		__tostring = function()
			return string.format("<struct view at 0x%X (size %d)>", base, self_struct.size)
		end,
	}

	return setmetatable(proxy, mt)
end

--- Create a zero-copy array view over contiguous structs in linear memory.
--- @param mem table Memory instance
--- @param base integer Starting address in linear memory
--- @param count integer Number of struct instances
--- @return table Array proxy object
function Struct:view_array(mem, base, count)
	if self.strict then
		self:check_alignment(base)
	end

	local self_struct = self
	local stride = self.size

	local array_proxy = {}
	local mt = {
		__index = function(_, idx)
			if type(idx) == "number" then
				if idx < 1 or idx > count then
					return nil
				end
				return self_struct:view(mem, base + (idx - 1) * stride)
			elseif idx == "count" or idx == "length" then
				return count
			elseif idx == "to_table" then
				return function()
					return self_struct:read_array(mem, base, count)
				end
			end
			return nil
		end,

		__len = function()
			return count
		end,
	}

	return setmetatable(array_proxy, mt)
end

--- Get byte offset of a field by name.
--- @param name string Field name
--- @return integer Field byte offset
function Struct:offset_of(name)
	local off = self.offsets[name]
	if not off then
		error("Unknown field: " .. tostring(name), 2)
	end
	return off
end

--- Get size of a field or whole struct in bytes.
--- @param name string|nil Field name (or nil for struct size)
--- @return integer Size in bytes
function Struct:size_of(name)
	if not name then
		return self.size
	end
	local f = self.field_map[name]
	if not f then
		error("Unknown field: " .. tostring(name), 2)
	end
	return f.size
end

--- Get alignment of a field or whole struct in bytes.
--- @param name string|nil Field name (or nil for struct align)
--- @return integer Alignment in bytes
function Struct:align_of(name)
	if not name then
		return self.align
	end
	local f = self.field_map[name]
	if not f then
		error("Unknown field: " .. tostring(name), 2)
	end
	return f.align
end

--- Format the struct layout description (offsets, padding, sizes, alignment).
--- @return string Formatted layout report
function Struct:format()
	local lines = {}
	lines[#lines + 1] = string.format("struct (size %d, align %d) {", self.size, self.align)

	local last_end = 0
	for _, f in ipairs(self.fields) do
		if f.offset > last_end then
			local pad = f.offset - last_end
			lines[#lines + 1] =
				string.format("  [%3d..%3d]  <padding %d byte%s>", last_end, f.offset - 1, pad, pad > 1 and "s" or "")
		end

		local type_str = tostring(f.type)
		if f.count then
			type_str = string.format("%s[%d]", type_str, f.count)
		end

		lines[#lines + 1] = string.format(
			"  [%3d..%3d]  %-14s %s (size %d, align %d)",
			f.offset,
			f.offset + f.size - 1,
			f.name .. ":",
			type_str,
			f.size,
			f.align
		)
		last_end = f.offset + f.size
	end

	if self.size > last_end then
		local pad = self.size - last_end
		lines[#lines + 1] =
			string.format("  [%3d..%3d]  <padding %d byte%s>", last_end, self.size - 1, pad, pad > 1 and "s" or "")
	end

	lines[#lines + 1] = "}"
	return table.concat(lines, "\n")
end

Struct.__tostring = Struct.format

-- Make Struct callable directly: `lwasm.struct(...)` or `Struct(...)`
setmetatable(Struct, {
	__call = function(_, fields, opts)
		return Struct.new(fields, opts)
	end,
})

return Struct
