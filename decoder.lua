--- WebAssembly Binary Module Decoder
--- Decodes binary .wasm format into structured Lua tables according to the WebAssembly specification.
---@diagnostic disable: undefined-global

local Binary = require("binary")
local utils = require("utils")
local opcodes = require("opcodes")

local WASM_decoder = {}

local WASM_MAGIC = "\0asm"
local WASM_VERSION = 1

--- Module metatable with convenience query methods
local Module = {}
Module.__index = Module

--- Get a section by name (e.g. 'type_section', 'code_section') or numeric section ID.
--- @param name_or_id string|integer
--- @return table|nil
function Module:get_section(name_or_id)
	if type(name_or_id) == "string" then
		return self.sections[name_or_id]
	end
	local id_to_name = {
		[SECT_CUSTOM] = "custom_section",
		[SECT_TYPE] = "type_section",
		[SECT_IMPORT] = "import_section",
		[SECT_FUNC] = "func_section",
		[SECT_TABLE] = "table_section",
		[SECT_MEM] = "mem_section",
		[SECT_GLOBAL] = "global_section",
		[SECT_EXPORT] = "export_section",
		[SECT_START] = "start_section",
		[SECT_ELEMENT] = "element_section",
		[SECT_CODE] = "code_section",
		[SECT_DATA] = "data_section",
		[SECT_DATA_COUNT] = "data_count_section",
		[SECT_TAG or 13] = "tag_section",
	}
	local name = id_to_name[name_or_id]
	return name and self.sections[name] or nil
end

--- Find a custom section by its name.
--- @param custom_name string
--- @return table|nil
function Module:get_custom_section(custom_name)
	if not self.sections.custom_sections then
		return nil
	end
	for _, s in ipairs(self.sections.custom_sections) do
		if s.name == custom_name then
			return s
		end
	end
	return nil
end

--- Get all exported items as a name -> export entry map.
--- @return table<string, table>
function Module:get_exports()
	local exports = {}
	local export_sec = self.sections.export_section
	if export_sec and export_sec.exports then
		for _, exp in ipairs(export_sec.exports) do
			exports[exp.name] = exp
		end
	end
	return exports
end

--- Parse limits (min, optional max, with memory64 / table64, shared, and custom page size support).
--- @param bin table Binary reader.
--- @return integer kind, integer min, integer|nil max, integer|nil page_size
local function parse_limits(bin)
	local kind = bin:read_byte()
	local is_64 = (kind & 0x04) ~= 0
	local has_max = (kind & 0x01) ~= 0
	local has_page_size = (kind & 0x08) ~= 0
	local min = is_64 and bin:read_u64LEB() or bin:read_u32LEB()
	local max
	if has_max then
		max = is_64 and bin:read_u64LEB() or bin:read_u32LEB()
	end
	local page_size
	if has_page_size then
		page_size = bin:read_u32LEB()
	end
	return kind, min, max, page_size
end

--- Read a WebAssembly value type (number, vector, or reference type).
--- @param bin table Binary reader.
--- @return integer|table Single byte integer or structured table for typed refs (ref / ref null).
local function read_valtype(bin)
	local b = bin:read_byte()
	if b == 0x63 or b == 0x64 then
		local nullable = (b == 0x63)
		local peek = bin:peek_byte()
		local ht
		if peek >= 0x6C and peek <= 0x73 then
			ht = bin:read_byte()
		else
			ht = bin:read_i64LEB()
		end
		return { kind = b, nullable = nullable, heap_type = ht }
	else
		return b
	end
end

local read_reftype = read_valtype

--- Parse constant initialization expression (used in globals, element offsets, data offsets).
--- Reads instruction and operand sequence until terminating 0x0B (end).
--- Supports WebAssembly 2.0 Extended Constant Expressions.
--- @param bin table Binary reader.
--- @param sections table Previously parsed sections.
--- @return table expr Structured constant expression.
local function parse_const_expr(bin, sections)
	local expr = { instructions = {} }
	while true do
		local op = bin:read_byte()
		if op == opcodes.EXPR_END or op == opcodes.INSTR_END then
			break
		end
		local insn = { op = op }
		if op == opcodes.INSTR_I32_CONST then
			insn.value = bin:read_i32LEB()
			expr.value = insn.value
			expr.offset = insn.value
		elseif op == opcodes.INSTR_I64_CONST then
			insn.value = bin:read_i64LEB()
			expr.value = insn.value
			expr.offset = insn.value
		elseif op == opcodes.INSTR_F32_CONST then
			insn.value = bin:read_f32()
			expr.value = insn.value
			expr.offset = insn.value
		elseif op == opcodes.INSTR_F64_CONST then
			insn.value = bin:read_f64()
			expr.value = insn.value
			expr.offset = insn.value
		elseif op == opcodes.INSTR_GLOBAL_GET then
			local index = bin:read_u32LEB() + 1
			insn.global_index = index
			expr.global_index = index
			if sections and sections.global_section and sections.global_section.globals then
				local global_entry = sections.global_section.globals[index]
				if global_entry then
					expr.offset = global_entry
				end
			end
		elseif op == opcodes.INSTR_REF_NULL then
			insn.ref_type = read_reftype(bin)
			expr.ref_type = insn.ref_type
		elseif op == opcodes.INSTR_REF_FUNC then
			insn.function_index = bin:read_u32LEB() + 1
			expr.function_index = insn.function_index
		elseif op == opcodes.PREFIX_SIMD then
			insn.simd_op = bin:read_u32LEB()
			if insn.simd_op == opcodes.INSTR_V128_CONST then
				insn.bytes = bin:read_bytes(16)
			end
		elseif op == opcodes.PREFIX_GC then
			insn.gc_op = bin:read_u32LEB()
			if insn.gc_op == 0 or insn.gc_op == 2 or insn.gc_op == 6 or insn.gc_op == 8 then
				insn.type_index = bin:read_u32LEB()
			end
		end
		if not expr.op then
			expr.op = op
			expr.init = op
		end
		expr.instructions[#expr.instructions + 1] = insn
	end

	expr.expr = 0x0B
	return expr
end

--- Section 0: Custom section (e.g. 'name', 'producers', DWARF debug info).
local function parse_custom_section(bin, section_size)
	local sub = bin:sub_reader(section_size)
	local name = ""
	local data = ""
	if section_size > 0 then
		name = sub:read_name()
		data = sub:slice(sub:remaining())
	end
	return {
		size = section_size,
		name = name,
		data = data,
	}
end

--- Section 1: Type section (function signatures).
local function parse_type_section(bin, section_size)
	local section = {
		size = section_size,
		type_count = bin:read_u32LEB(),
		types = {},
	}
	for _ = 1, section.type_count do
		local func = {}
		func.form = bin:read_byte()
		assert(func.form == 0x60, "Unsupported function form 0x" .. string.format("%X", func.form))
		func.param_count = bin:read_u32LEB()
		func.params = {}
		for _ = 1, func.param_count do
			func.params[#func.params + 1] = read_valtype(bin)
		end
		func.results_count = bin:read_u32LEB()
		func.results = {}
		for _ = 1, func.results_count do
			func.results[#func.results + 1] = read_valtype(bin)
		end
		section.types[#section.types + 1] = func
	end
	return section
end

local function parse_import_desc(bin, import)
	if import.desc == opcodes.DESC_FUNC then
		import.index = bin:read_u32LEB() + 1
	elseif import.desc == opcodes.DESC_TABLE then
		import.type = read_reftype(bin)
		import.kind, import.min, import.max = parse_limits(bin)
	elseif import.desc == opcodes.DESC_MEM then
		import.kind, import.min, import.max = parse_limits(bin)
	elseif import.desc == opcodes.DESC_GLOBAL then
		import.type = read_valtype(bin)
		import.mutable = bin:read_byte() ~= 0
	elseif import.desc == (opcodes.DESC_TAG or 4) then
		import.attribute = bin:read_byte()
		import.type_index = bin:read_u32LEB()
	else
		assert(false, "Unknown import desc: " .. import.desc)
	end
end

--- Section 2: Import section (with compact import section proposal support).
local function parse_import_section(bin, section_size)
	local section = {
		size = section_size,
		function_count = bin:read_u32LEB(),
		imports = {},
	}
	for _ = 1, section.function_count do
		local mod_name = bin:read_name()
		local field_name = bin:read_name()
		if #field_name == 0 and (bin:peek_byte() == 0x7F or bin:peek_byte() == 0x7E) then
			local compact_tag = bin:read_byte()
			if compact_tag == 0x7F then
				local item_count = bin:read_u32LEB()
				for _ = 1, item_count do
					local imp = {
						module = mod_name,
						module_name_len = #mod_name,
						field = bin:read_name(),
						desc = bin:read_byte(),
					}
					imp.field_len = #imp.field
					parse_import_desc(bin, imp)
					section.imports[#section.imports + 1] = imp
				end
			elseif compact_tag == 0x7E then
				local shared_desc = bin:read_byte()
				local template = { desc = shared_desc }
				parse_import_desc(bin, template)
				local item_count = bin:read_u32LEB()
				for _ = 1, item_count do
					local imp = {
						module = mod_name,
						module_name_len = #mod_name,
						field = bin:read_name(),
					}
					imp.field_len = #imp.field
					for k, v in pairs(template) do
						imp[k] = v
					end
					section.imports[#section.imports + 1] = imp
				end
			end
		else
			local import = {
				module = mod_name,
				module_name_len = #mod_name,
				field = field_name,
				field_len = #field_name,
				desc = bin:read_byte(),
			}
			parse_import_desc(bin, import)
			section.imports[#section.imports + 1] = import
		end
	end
	return section
end

--- Section 3: Function section (type indices for declared functions).
local function parse_func_section(bin, section_size)
	local section = {
		size = section_size,
		function_count = bin:read_u32LEB(),
		indices = {},
	}
	for _ = 1, section.function_count do
		section.indices[#section.indices + 1] = bin:read_u32LEB()
	end
	return section
end

--- Section 4: Table section.
local function parse_table_section(bin, section_size, sections)
	local section = {
		size = section_size,
		table_count = bin:read_u32LEB(),
		tables = {},
	}
	for _ = 1, section.table_count do
		local tbl = {}
		local b = bin:peek_byte()
		if b == 0x40 then
			bin:read_byte() -- 0x40
			tbl.has_init = bin:read_byte()
			tbl.type = read_reftype(bin)
			tbl.kind, tbl.min, tbl.max = parse_limits(bin)
			tbl.init = parse_const_expr(bin, sections)
		else
			tbl.type = read_reftype(bin)
			tbl.kind, tbl.min, tbl.max = parse_limits(bin)
		end
		section.tables[#section.tables + 1] = tbl
	end
	return section
end

--- Section 5: Memory section.
local function parse_mem_section(bin, section_size)
	local section = {
		size = section_size,
		memory_count = bin:read_u32LEB(),
		memory = {},
	}
	for _ = 1, section.memory_count do
		local mem = {}
		mem.kind, mem.min, mem.max = parse_limits(bin)
		section.memory[#section.memory + 1] = mem
	end
	return section
end

--- Section 6: Global section.
local function parse_global_section(bin, section_size, sections)
	local section = {
		size = section_size,
		global_count = bin:read_u32LEB(),
		globals = {},
	}
	for _ = 1, section.global_count do
		local global_entry = {}
		global_entry.type = read_valtype(bin)
		global_entry.mutable = bin:read_byte() ~= 0
		local expr = parse_const_expr(bin, sections)
		global_entry.op = expr.op
		global_entry.value = expr.value
		global_entry.global_index = expr.global_index
		global_entry.ref_type = expr.ref_type
		global_entry.function_index = expr.function_index
		global_entry.expr = expr.expr
		section.globals[#section.globals + 1] = global_entry
	end
	return section
end

--- Section 7: Export section.
local function parse_export_section(bin, section_size)
	local section = {
		size = section_size,
		export_count = bin:read_u32LEB(),
		exports = {},
	}
	for _ = 1, section.export_count do
		local export = {}
		export.name = bin:read_name()
		export.name_len = #export.name
		export.desc = bin:read_byte()
		export.index = bin:read_u32LEB()
		section.exports[#section.exports + 1] = export
	end
	return section
end

--- Section 8: Start section (entry point function index).
local function parse_start_section(bin, section_size)
	return {
		size = section_size,
		index = bin:read_u32LEB(),
	}
end

local function read_reftype(bin)
	local b = bin:read_byte()
	if b == 0x63 or b == 0x64 then
		local nullable = (b == 0x63)
		local peek = bin:peek_byte()
		local ht
		if peek >= 0x6C and peek <= 0x73 then
			ht = bin:read_byte()
		else
			ht = bin:read_i64LEB()
		end
		return { kind = b, nullable = nullable, heap_type = ht }
	else
		return b
	end
end

--- Section 9: Element section (table initializers).
local function parse_element_section(bin, section_size, sections)
	local section = {
		size = section_size,
		element_count = bin:read_u32LEB(),
		elements = {},
	}
	for _ = 1, section.element_count do
		local element = {}
		element.flag = bin:read_u32LEB()
		assert(element.flag <= 7, "Unknown element segment flag: " .. element.flag)
		element.table_index = 0
		if element.flag & (SEG_PASSIVE | SEG_EXPLICIT_INDEX) == SEG_EXPLICIT_INDEX then
			element.table_index = bin:read_u32LEB()
		end
		element.element_type = REF_FUNC
		if (element.flag & SEG_PASSIVE) ~= SEG_PASSIVE then
			local expr = parse_const_expr(bin, sections)
			element.init = expr.init
			element.offset = expr.offset
			element.expr = expr.expr
		end
		if element.flag & (SEG_PASSIVE | SEG_EXPLICIT_INDEX) ~= 0 then
			if (element.flag & SEG_ELEM_EXPR) ~= 0 then
				element.element_type = read_reftype(bin)
			else
				element.kind = bin:read_byte()
			end
		end

		if (element.flag & SEG_ELEM_EXPR) ~= 0 then
			element.expr_count = bin:read_u32LEB()
			element.expressions = {}
			for _ = 1, element.expr_count do
				element.expressions[#element.expressions + 1] = parse_const_expr(bin, sections)
			end
		else
			element.func_count = bin:read_u32LEB()
			element.functions = {}
			for _ = 1, element.func_count do
				element.functions[#element.functions + 1] = bin:read_u32LEB() + 1
			end
		end
		section.elements[#section.elements + 1] = element
	end
	return section
end

--- Section 10: Code section (function bodies and local variables).
local function parse_code_section(bin, section_size, _, options)
	local section = {
		size = section_size,
		code_count = bin:read_u32LEB(),
		code = {},
	}
	for _ = 1, section.code_count do
		local code = {}
		code.size = bin:read_u32LEB()
		local code_end = bin.cursor + code.size

		code.local_count = bin:read_u32LEB()
		code.locals = {}
		for _ = 1, code.local_count do
			local local_entry = {}
			local_entry.count = bin:read_u32LEB()
			local_entry.type = bin:read_byte()
			code.locals[#code.locals + 1] = local_entry
		end

		code.code_start = bin.cursor
		code.code_end = code_end
		code.body_size = code.code_end - code.code_start
		if options and options.lazy_code then
			code.source = bin.data
			bin:assert_bytes(code.body_size)
			bin:skip(code.body_size)
		else
			-- Keep bytecode in Lua's compact native string representation.
			code.body = bin:slice(code.body_size)
		end

		section.code[#section.code + 1] = code
	end
	return section
end

--- Section 11: Data section (memory initializers).
local function parse_data_section(bin, section_size, sections, options)
	local section = {
		size = section_size,
		data_count = bin:read_u32LEB(),
		entries = {},
	}
	for _ = 1, section.data_count do
		local entry = {}
		entry.flag = bin:read_u32LEB()
		entry.memory_index = 0
		if (entry.flag & SEG_EXPLICIT_INDEX) == SEG_EXPLICIT_INDEX then
			entry.memory_index = bin:read_u32LEB()
		end
		if (entry.flag & SEG_PASSIVE) ~= SEG_PASSIVE then
			local expr = parse_const_expr(bin, sections)
			entry.init = expr.init
			entry.offset = expr.offset
			entry.expr = expr.expr
		end

		entry.size = bin:read_u32LEB()
		if options and options.lazy_data then
			entry.source = bin.data
			entry.data_start = bin.cursor
			bin:assert_bytes(entry.size)
			bin:skip(entry.size)
		else
			entry.data = bin:slice(entry.size)
		end
		section.entries[#section.entries + 1] = entry
	end
	return section
end

--- Section 12: Data count section.
local function parse_data_count_section(bin, section_size)
	local section = {
		size = section_size,
		count = bin:read_u32LEB(),
	}
	return section
end

--- Section 13: Tag section (exception handling tags).
local function parse_tag_section(bin, section_size)
	local section = {
		size = section_size,
		tag_count = bin:read_u32LEB(),
		tags = {},
	}
	for _ = 1, section.tag_count do
		local tag = {}
		tag.attribute = bin:read_byte()
		tag.type_index = bin:read_u32LEB()
		section.tags[#section.tags + 1] = tag
	end
	return section
end

--- Parse all sections in the module.
--- @param bin table Binary reader.
--- @return table Map of sections.
local function parse_sections(bin, options)
	local sections = {}

	local section_parsers = {
		[opcodes.SECT_CUSTOM] = { parse_func = parse_custom_section, name = "custom_section" },
		[opcodes.SECT_TYPE] = { parse_func = parse_type_section, name = "type_section" },
		[opcodes.SECT_IMPORT] = { parse_func = parse_import_section, name = "import_section" },
		[opcodes.SECT_FUNC] = { parse_func = parse_func_section, name = "func_section" },
		[opcodes.SECT_TABLE] = { parse_func = parse_table_section, name = "table_section" },
		[opcodes.SECT_MEM] = { parse_func = parse_mem_section, name = "mem_section" },
		[opcodes.SECT_GLOBAL] = { parse_func = parse_global_section, name = "global_section" },
		[opcodes.SECT_EXPORT] = { parse_func = parse_export_section, name = "export_section" },
		[opcodes.SECT_START] = { parse_func = parse_start_section, name = "start_section" },
		[opcodes.SECT_ELEMENT] = { parse_func = parse_element_section, name = "element_section" },
		[opcodes.SECT_CODE] = { parse_func = parse_code_section, name = "code_section" },
		[opcodes.SECT_DATA] = { parse_func = parse_data_section, name = "data_section" },
		[opcodes.SECT_DATA_COUNT] = { parse_func = parse_data_count_section, name = "data_count_section" },
		[opcodes.SECT_TAG or 13] = { parse_func = parse_tag_section, name = "tag_section" },
	}

	local section_list = {}

	while not bin:is_EOF() do
		local sec_offset = bin.cursor - 1
		local id = bin:read_byte()
		local size = bin:read_u32LEB()
		local body_offset = bin.cursor - 1
		local parser_info = section_parsers[id]

		if not parser_info then
			assert(false, "Unknown or unsupported section ID: " .. id)
		end

		local section = parser_info.parse_func(bin, size, sections, options)
		local name = parser_info.name
		section.id = id
		section.section_name = name
		if id ~= opcodes.SECT_CUSTOM then
			section.name = name
		end
		section.offset = sec_offset
		section.size = size
		section.body_offset = body_offset
		section_list[#section_list + 1] = section

		if id == opcodes.SECT_CUSTOM then
			if not sections.custom_sections then
				sections.custom_sections = {}
			end
			sections.custom_sections[#sections.custom_sections + 1] = section
			sections.custom_section = section -- Retain backward-compatible singular reference
		elseif id == opcodes.SECT_GLOBAL and sections[name] then
			sections[name].global_count = (sections[name].global_count or 0) + section.global_count
			sections[name].globals = utils.merge(sections[name].globals, section.globals)
		else
			sections[name] = section
		end
	end

	sections.section_list = section_list
	return sections
end

--- Decode a WebAssembly binary byte string into a Module object.
--- @param bytes string Raw .wasm binary data.
--- @return table Module object.
function WASM_decoder.decode(bytes, options)
	local bin = Binary:new(bytes)

	local magic = bin:slice(4)
	assert(magic == WASM_MAGIC, "Invalid Wasm header magic: expected '\\0asm', got: " .. string.format("%q", magic))

	local version = bin:read_u32()
	assert(version == WASM_VERSION, "Unsupported Wasm version: " .. version .. " (expected " .. WASM_VERSION .. ")")

	local module = {
		magic = magic,
		version = version,
		file_size = #bytes,
		raw_bytes = bytes,
		sections = parse_sections(bin, options),
		options = options or {},
	}
	setmetatable(module.sections, {
		__call = function(sections)
			return sections.section_list or {}
		end,
	})

	setmetatable(module, Module)
	return module
end

--- Decode a WebAssembly file by path.
--- @param filepath string Path to .wasm file.
--- @return table Module object.
function WASM_decoder.decode_file(filepath, options)
	local content = utils.read_file_bytes(filepath)
	local mod = WASM_decoder.decode(content, options)
	mod.filepath = filepath
	return mod
end

WASM_decoder.Module = Module

return WASM_decoder
