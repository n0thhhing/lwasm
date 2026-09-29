--- WebAssembly File Dumper Module
--- Generates comprehensive, detailed dumps of entire .wasm files including:
---   - File metadata, header magic, version, and section table
---   - Detailed contents for every section (Types, Imports, Functions, Tables, Memories,
---     Globals, Exports, Start, Elements, Data, Tags, and Custom/Name sections)
---   - Full disassembly of all code section functions with offsets, hex bytecode, and indentation
---   - Formatted hex/ASCII dumps for data segments and custom payloads
--- Can be used as a Lua module or invoked directly from the CLI: `lua dumper.lua <file.wasm>`

local decoder = require("decoder")
local disasm = require("disassembler")
local opcodes = require("opcodes")
local Binary = require("binary")

local dumper = {}

--- Format a number of bytes into a human-readable size string.
--- @param bytes integer
--- @return string
local function format_size(bytes)
	if bytes < 1024 then
		return string.format("%d bytes", bytes)
	elseif bytes < 1024 * 1024 then
		return string.format("%d bytes (%.2f KiB)", bytes, bytes / 1024)
	else
		return string.format("%d bytes (%.2f MiB)", bytes, bytes / (1024 * 1024))
	end
end

--- Format binary bytes as standard 16-bytes-per-line hex + ASCII dump.
--- @param data string Raw byte data.
--- @param max_bytes integer|nil Maximum bytes to dump (defaults to 256).
--- @param indent string|nil Indentation prefix (defaults to "    ").
--- @return string
function dumper.format_hexdump(data, max_bytes, indent)
	indent = indent or "    "
	if not data or #data == 0 then
		return indent .. "(empty)"
	end
	max_bytes = max_bytes or 256
	local len = math.min(#data, max_bytes)
	local lines = {}

	for i = 1, len, 16 do
		local chunk = data:sub(i, math.min(i + 15, len))
		local hex_parts = {}
		local ascii_parts = {}

		for j = 1, 16 do
			if j <= #chunk then
				local b = string.byte(chunk, j)
				table.insert(hex_parts, string.format("%02x", b))
				if b >= 32 and b <= 126 then
					table.insert(ascii_parts, string.char(b))
				else
					table.insert(ascii_parts, ".")
				end
			else
				table.insert(hex_parts, "  ")
			end
			if j == 8 then
				table.insert(hex_parts, "")
			end
		end

		lines[#lines + 1] =
			string.format("%s%08x:  %-49s |%s|", indent, i - 1, table.concat(hex_parts, " "), table.concat(ascii_parts))
	end

	if #data > len then
		lines[#lines + 1] = string.format("%s... (%d more bytes omitted)", indent, #data - len)
	end

	return table.concat(lines, "\n")
end

--- Format a value type ID into its canonical string representation.
--- @param type_id integer|nil
--- @return string
local function format_type(type_id)
	if not type_id then
		return "?"
	end
	return opcodes.valtype_to_string(type_id)
end

--- Format a function type signature into `(param ...) -> (result ...)`.
--- @param sig table Type entry with params and results.
--- @return string
local function format_signature(sig)
	if not sig then
		return "(?)"
	end
	local params = {}
	if sig.params then
		for _, p in ipairs(sig.params) do
			params[#params + 1] = format_type(p)
		end
	end

	local results = {}
	if sig.results then
		for _, r in ipairs(sig.results) do
			results[#results + 1] = format_type(r)
		end
	end

	local param_str = #params > 0 and ("(param " .. table.concat(params, " ") .. ")") or "()"
	local result_str = #results > 0 and (" -> (result " .. table.concat(results, " ") .. ")") or ""
	return param_str .. result_str
end

--- Format limits (min, max).
--- @param min integer
--- @param max integer|nil
--- @param unit string|nil
--- @return string
local function format_limits(min, max, unit)
	unit = unit and (" " .. unit) or ""
	if max then
		return string.format("min=%d, max=%d%s", min, max, unit)
	else
		return string.format("min=%d%s", min, unit)
	end
end

--- Format a constant initializer expression.
--- @param expr table
--- @return string
local function format_const_expr(expr)
	if not expr then
		return "?"
	end
	local op = expr.op or expr.init
	if op == 0x41 then
		return string.format("i32.const %d", expr.value or expr.offset or 0)
	elseif op == 0x42 then
		return string.format("i64.const %d", expr.value or expr.offset or 0)
	elseif op == 0x43 then
		return string.format("f32.const %s", tostring(expr.value or expr.offset or 0))
	elseif op == 0x44 then
		return string.format("f64.const %s", tostring(expr.value or expr.offset or 0))
	elseif op == 0x23 then
		return string.format("global.get %d", (expr.global_index or 1) - 1)
	elseif op == 0xD0 then
		return string.format("ref.null %s", format_type(expr.ref_type))
	elseif op == 0xD2 then
		return string.format("ref.func %d", (expr.function_index or 1) - 1)
	elseif expr.offset ~= nil then
		return tostring(expr.offset)
	end
	return string.format("op=0x%02X", op or 0)
end

--- Parse the standard WebAssembly "name" custom section.
--- @param data string Raw bytes of the name section.
--- @return table Parsed names table.
local function parse_name_section(data)
	local bin = Binary:new(data)
	local names = {
		module_name = nil,
		functions = {},
		locals = {},
	}
	pcall(function()
		while not bin:is_EOF() do
			local sub_id = bin:read_byte()
			local sub_size = bin:read_u32LEB()
			local sub_reader = bin:sub_reader(sub_size)
			if sub_id == 0 then
				names.module_name = sub_reader:read_name()
			elseif sub_id == 1 then
				local count = sub_reader:read_u32LEB()
				for _ = 1, count do
					local func_idx = sub_reader:read_u32LEB()
					names.functions[func_idx] = sub_reader:read_name()
				end
			elseif sub_id == 2 then
				local count = sub_reader:read_u32LEB()
				for _ = 1, count do
					local func_idx = sub_reader:read_u32LEB()
					names.locals[func_idx] = {}
					local local_count = sub_reader:read_u32LEB()
					for _ = 1, local_count do
						local local_idx = sub_reader:read_u32LEB()
						names.locals[func_idx][local_idx] = sub_reader:read_name()
					end
				end
			end
		end
	end)
	return names
end

--- Generate a comprehensive dump of an entire WebAssembly binary or module.
--- @param mod_or_path table|string Decoded module object or path to .wasm file.
--- @param options table|nil Optional formatting settings:
---   - `headers_only`: boolean (print only file overview and section table)
---   - `no_disasm`: boolean (skip instruction disassembly in code section)
---   - `disasm_only`: boolean (print only disassembled code section)
---   - `max_hexdump_bytes`: integer (max bytes per data segment / custom section preview)
--- @return string Full formatted dump output.
function dumper.dump(mod_or_path, options)
	options = options or {}
	local mod
	local filepath = nil
	if type(mod_or_path) == "string" then
		filepath = mod_or_path
		mod = decoder.decode_file(mod_or_path)
	else
		mod = mod_or_path
		filepath = mod.filepath
	end

	local out = {}
	local function append(fmt, ...)
		if select("#", ...) == 0 then
			table.insert(out, fmt or "")
		else
			table.insert(out, string.format(fmt, ...))
		end
	end

	-- Collect helper lookups (types, imports, exports, names)
	local type_sec = mod:get_section("type_section")
	local types = type_sec and type_sec.types or {}

	local import_sec = mod:get_section("import_section")
	local imports = import_sec and import_sec.imports or {}

	local func_sec = mod:get_section("func_section")
	local func_indices = func_sec and func_sec.indices or {}

	local export_sec = mod:get_section("export_section")
	local exports = export_sec and export_sec.exports or {}

	-- Build index mappings
	local func_export_names = {}
	local table_export_names = {}
	local memory_export_names = {}
	local global_export_names = {}

	for _, exp in ipairs(exports) do
		if exp.desc == 0 then
			func_export_names[exp.index] = exp.name
		elseif exp.desc == 1 then
			table_export_names[exp.index] = exp.name
		elseif exp.desc == 2 then
			memory_export_names[exp.index] = exp.name
		elseif exp.desc == 3 then
			global_export_names[exp.index] = exp.name
		end
	end

	-- Count imported functions to calculate absolute function indices
	local imported_func_count = 0
	local imported_funcs = {}
	for _, imp in ipairs(imports) do
		if imp.desc == 0 then
			imported_funcs[imported_func_count] = imp
			imported_func_count = imported_func_count + 1
		end
	end

	-- Parse debug names if a "name" custom section is present
	local debug_names = { functions = {}, locals = {} }
	if mod.sections.custom_sections then
		for _, cs in ipairs(mod.sections.custom_sections) do
			if cs.name == "name" and cs.data then
				debug_names = parse_name_section(cs.data)
				break
			end
		end
	end

	local function get_func_name(func_idx)
		if func_export_names[func_idx] then
			return "<" .. func_export_names[func_idx] .. ">"
		elseif debug_names.functions[func_idx] then
			return "<$" .. debug_names.functions[func_idx] .. ">"
		end
		return ""
	end

	-- If disassembly only requested:
	if options.disasm_only then
		return disasm.dump(mod)
	end

	-- 1. File Overview / Header
	append(string.rep("=", 80))
	append("WebAssembly Binary Dump")
	append(string.rep("=", 80))
	if filepath then
		append("File:       %s", filepath)
	end
	if mod.file_size then
		append("Size:       %s", format_size(mod.file_size))
	end
	append("Magic:      0x6D736100 (\\0asm)")
	append("Version:    0x%08X (version %d)", mod.version, mod.version)

	-- 2. Section Table
	local section_list = mod.sections.section_list
	if not section_list then
		-- Synthesize if not recorded
		section_list = {}
		for _, name in pairs(opcodes.SECTION_NAMES) do
			local sec = mod:get_section(name .. "_section")
			if sec then
				table.insert(section_list, sec)
			end
		end
	end

	append("\n" .. string.rep("-", 80))
	append("Sections Overview (%d sections present):", #section_list)
	append(string.rep("-", 80))
	append("  Idx   Id  Name                    File Offset    Size (bytes)  Content Details")
	append("  ---+----+-----------------------+-------------+--------------+------------------------------")

	for idx, sec in ipairs(section_list) do
		local id_num = sec.id or 0
		local sec_name = opcodes.SECTION_NAMES[id_num] or sec.name or "unknown"
		sec_name = sec_name:sub(1, 1):upper() .. sec_name:sub(2)

		local details = ""
		if id_num == opcodes.SECT_CUSTOM then
			details = string.format("custom [%s]", sec.name or "?")
		elseif id_num == opcodes.SECT_TYPE then
			details = string.format("%d type signatures", sec.type_count or (sec.types and #sec.types) or 0)
		elseif id_num == opcodes.SECT_IMPORT then
			details = string.format("%d imports", sec.function_count or (sec.imports and #sec.imports) or 0)
		elseif id_num == opcodes.SECT_FUNC then
			details = string.format("%d declared functions", sec.function_count or (sec.indices and #sec.indices) or 0)
		elseif id_num == opcodes.SECT_TABLE then
			details = string.format("%d tables", sec.table_count or 0)
		elseif id_num == opcodes.SECT_MEM then
			details = string.format("%d memories", sec.memory_count or 0)
		elseif id_num == opcodes.SECT_GLOBAL then
			details = string.format("%d globals", sec.global_count or 0)
		elseif id_num == opcodes.SECT_EXPORT then
			details = string.format("%d exports", sec.export_count or 0)
		elseif id_num == opcodes.SECT_START then
			details = string.format("entry func[%d]", sec.index or 0)
		elseif id_num == opcodes.SECT_ELEMENT then
			details = string.format("%d element segments", sec.element_count or 0)
		elseif id_num == opcodes.SECT_CODE then
			details = string.format("%d function bodies", sec.code and #sec.code or 0)
		elseif id_num == opcodes.SECT_DATA then
			details = string.format("%d data segments", sec.data_count or (sec.entries and #sec.entries) or 0)
		elseif id_num == opcodes.SECT_DATA_COUNT then
			details = string.format("count = %d", sec.count or 0)
		elseif id_num == opcodes.SECT_TAG then
			details = string.format("%d tags", sec.tag_count or 0)
		end

		local offset_str = sec.offset and string.format("0x%08X", sec.offset) or "         n/a"
		append(
			"  %3d  %3d  %-23s  %11s    %12s  %s",
			idx,
			id_num,
			sec_name,
			offset_str,
			tostring(sec.size or 0),
			details
		)
	end

	if options.headers_only then
		return table.concat(out, "\n")
	end

	-- 3. Detailed Section Contents
	-- Section 1: Types
	if type_sec and type_sec.types and #type_sec.types > 0 then
		append("\n" .. string.rep("-", 80))
		append("Type Section (%d entries):", #type_sec.types)
		append(string.rep("-", 80))
		for i, sig in ipairs(type_sec.types) do
			append("  type[%d]: %s", i - 1, format_signature(sig))
		end
	end

	-- Section 2: Imports
	if import_sec and import_sec.imports and #import_sec.imports > 0 then
		append("\n" .. string.rep("-", 80))
		append("Import Section (%d entries):", #import_sec.imports)
		append(string.rep("-", 80))
		for i, imp in ipairs(import_sec.imports) do
			local desc_name = opcodes.DESC_NAMES[imp.desc] or string.format("desc_%d", imp.desc)
			local extra = ""
			if imp.desc == opcodes.DESC_FUNC then
				local sig = types[imp.index]
				extra = string.format("sig=type[%d] %s", (imp.index or 1) - 1, format_signature(sig))
			elseif imp.desc == opcodes.DESC_TABLE then
				extra = string.format("type=%s %s", format_type(imp.type), format_limits(imp.min or 0, imp.max))
			elseif imp.desc == opcodes.DESC_MEM then
				extra = format_limits(imp.min or 0, imp.max, "pages")
			elseif imp.desc == opcodes.DESC_GLOBAL then
				extra = string.format("%s (%s)", format_type(imp.type), imp.mutable and "mut" or "const")
			elseif imp.desc == opcodes.DESC_TAG then
				extra = string.format("type_index=%d", imp.type_index or 0)
			end
			append('  import[%d]: %-6s "%s"."%s" -> %s', i - 1, desc_name, imp.module, imp.field, extra)
		end
	end

	-- Section 3: Functions
	if func_sec and func_sec.indices and #func_sec.indices > 0 then
		append("\n" .. string.rep("-", 80))
		append(
			"Function Declarations (%d defined functions, %d total including imports):",
			#func_sec.indices,
			imported_func_count + #func_sec.indices
		)
		append(string.rep("-", 80))
		for i, type_idx in ipairs(func_sec.indices) do
			local abs_idx = imported_func_count + (i - 1)
			local name_str = get_func_name(abs_idx)
			name_str = name_str ~= "" and (" " .. name_str) or ""
			local sig = types[type_idx + 1]
			append("  func[%d]%s: sig=type[%d] %s", abs_idx, name_str, type_idx, format_signature(sig))
		end
	end

	-- Section 4: Tables
	local table_sec = mod:get_section("table_section")
	if table_sec and table_sec.tables and #table_sec.tables > 0 then
		append("\n" .. string.rep("-", 80))
		append("Table Section (%d entries):", #table_sec.tables)
		append(string.rep("-", 80))
		for i, tbl in ipairs(table_sec.tables) do
			local name_str = table_export_names[i - 1] and (" <" .. table_export_names[i - 1] .. ">") or ""
			append(
				"  table[%d]%s: type=%s %s",
				i - 1,
				name_str,
				format_type(tbl.type),
				format_limits(tbl.min or 0, tbl.max)
			)
		end
	end

	-- Section 5: Memories
	local mem_sec = mod:get_section("mem_section")
	if mem_sec and mem_sec.memory and #mem_sec.memory > 0 then
		append("\n" .. string.rep("-", 80))
		append("Memory Section (%d entries):", #mem_sec.memory)
		append(string.rep("-", 80))
		for i, mem in ipairs(mem_sec.memory) do
			local name_str = memory_export_names[i - 1] and (" <" .. memory_export_names[i - 1] .. ">") or ""
			local kib = (mem.min or 0) * 64
			append(
				"  memory[%d]%s: %s (%d KiB initial)",
				i - 1,
				name_str,
				format_limits(mem.min or 0, mem.max, "pages"),
				kib
			)
		end
	end

	-- Section 13: Tags
	local tag_sec = mod:get_section("tag_section")
	if tag_sec and tag_sec.tags and #tag_sec.tags > 0 then
		append("\n" .. string.rep("-", 80))
		append("Tag Section (%d entries):", #tag_sec.tags)
		append(string.rep("-", 80))
		for i, tag in ipairs(tag_sec.tags) do
			local sig = types[tag.type_index + 1]
			append(
				"  tag[%d]: attribute=0x%02X sig=type[%d] %s",
				i - 1,
				tag.attribute or 0,
				tag.type_index,
				format_signature(sig)
			)
		end
	end

	-- Section 6: Globals
	local global_sec = mod:get_section("global_section")
	if global_sec and global_sec.globals and #global_sec.globals > 0 then
		append("\n" .. string.rep("-", 80))
		append("Global Section (%d entries):", #global_sec.globals)
		append(string.rep("-", 80))
		for i, g in ipairs(global_sec.globals) do
			local name_str = global_export_names[i - 1] and (" <" .. global_export_names[i - 1] .. ">") or ""
			if g.module then
				append(
					'  global[%d]%s: imported from "%s"."%s" (%s, %s)',
					i - 1,
					name_str,
					g.module,
					g.field,
					format_type(g.type),
					g.mutable and "mut" or "const"
				)
			else
				local init_str = format_const_expr(g)
				append(
					"  global[%d]%s: %s (%s) = %s",
					i - 1,
					name_str,
					format_type(g.type),
					g.mutable and "mut" or "const",
					init_str
				)
			end
		end
	end

	-- Section 7: Exports
	if export_sec and export_sec.exports and #export_sec.exports > 0 then
		append("\n" .. string.rep("-", 80))
		append("Export Section (%d entries):", #export_sec.exports)
		append(string.rep("-", 80))
		for i, exp in ipairs(export_sec.exports) do
			local desc_name = opcodes.DESC_NAMES[exp.desc] or string.format("desc_%d", exp.desc)
			local extra = ""
			if exp.desc == opcodes.DESC_FUNC then
				local func_idx = exp.index
				local func_offset = func_idx - imported_func_count
				local type_idx = func_indices[func_offset + 1]
				local sig = type_idx and types[type_idx + 1]
				extra = sig and (" " .. format_signature(sig)) or ""
			end
			append('  export[%d]: "%s" -> %s[%d]%s', i - 1, exp.name, desc_name, exp.index, extra)
		end
	end

	-- Section 8: Start
	local start_sec = mod:get_section("start_section")
	if start_sec and start_sec.index then
		append("\n" .. string.rep("-", 80))
		append("Start Section:")
		append(string.rep("-", 80))
		append("  Entry point function: func[%d] %s", start_sec.index, get_func_name(start_sec.index))
	end

	-- Section 9: Elements
	local elem_sec = mod:get_section("element_section")
	if elem_sec and elem_sec.elements and #elem_sec.elements > 0 then
		append("\n" .. string.rep("-", 80))
		append("Element Section (%d segments):", #elem_sec.elements)
		append(string.rep("-", 80))
		for i, el in ipairs(elem_sec.elements) do
			local mode_str = (el.flag & 1) ~= 0 and "passive" or "active"
			local funcs = {}
			if el.functions then
				for _, f in ipairs(el.functions) do
					table.insert(funcs, string.format("func[%d]%s", f, get_func_name(f)))
				end
			end
			local func_list = #funcs > 0 and table.concat(funcs, ", ") or "none"
			append(
				"  elem[%d]: mode=%s, table[%d], offset=%s, items=[%s]",
				i - 1,
				mode_str,
				el.table_index or 0,
				tostring(el.offset or 0),
				func_list
			)
		end
	end

	-- Section 11: Data
	local data_sec = mod:get_section("data_section")
	local data_entries = data_sec and (data_sec.entries or data_sec.data)
	if data_entries and #data_entries > 0 then
		append("\n" .. string.rep("-", 80))
		append("Data Section (%d segments):", #data_entries)
		append(string.rep("-", 80))
		for i, d in ipairs(data_entries) do
			local mode = (d.flag and (d.flag & 1) ~= 0) and "passive" or "active"
			local init_str = format_const_expr(d)
			local d_size = d.data and #d.data or (d.size or 0)
			append(
				"  data[%d]: mode=%s, memory[%d], offset=(%s), size=%d bytes",
				i - 1,
				mode,
				d.memory_index or 0,
				init_str,
				d_size
			)
			if d.data and #d.data > 0 then
				append(dumper.format_hexdump(d.data, options.max_hexdump_bytes or 128, "    "))
			end
		end
	end

	-- Custom Sections
	if mod.sections.custom_sections and #mod.sections.custom_sections > 0 then
		append("\n" .. string.rep("-", 80))
		append("Custom Sections (%d entries):", #mod.sections.custom_sections)
		append(string.rep("-", 80))
		for i, cs in ipairs(mod.sections.custom_sections) do
			append('  custom[%d]: name="%s", size=%d bytes', i - 1, cs.name or "", cs.size or 0)
			if cs.name == "name" and debug_names.functions and next(debug_names.functions) then
				append("    Decoded function names:")
				for f_idx, f_name in pairs(debug_names.functions) do
					append('      func[%d] = "$%s"', f_idx, f_name)
				end
			elseif cs.data and #cs.data > 0 and (options.raw_data or cs.size <= 128) then
				append(dumper.format_hexdump(cs.data, options.max_hexdump_bytes or 64, "    "))
			end
		end
	end

	-- 4. Code Section Disassembly
	local code_sec = mod:get_section("code_section")
	if not options.no_disasm and code_sec and code_sec.code and #code_sec.code > 0 then
		append("\n" .. string.rep("=", 80))
		append("Code Section Disassembly (%d functions):", #code_sec.code)
		append(string.rep("=", 80))

		for i, code_entry in ipairs(code_sec.code) do
			local abs_func_idx = imported_func_count + (i - 1)
			local type_idx = func_indices[i]
			local sig = type_idx and types[type_idx + 1]
			local sig_str = sig and format_signature(sig) or ""
			local name_str = get_func_name(abs_func_idx)
			name_str = name_str ~= "" and (" " .. name_str) or ""

			local locals_desc = {}
			if code_entry.locals then
				for _, loc in ipairs(code_entry.locals) do
					table.insert(locals_desc, string.format("%d x %s", loc.count or 1, format_type(loc.type)))
				end
			end
			local locals_str = #locals_desc > 0 and ("locals: " .. table.concat(locals_desc, ", ")) or "locals: none"

			append(
				"\n%06x func[%d]%s (type %s: %s, size %d, %s):",
				code_entry.code_start or 0,
				abs_func_idx,
				name_str,
				tostring(type_idx or "?"),
				sig_str,
				code_entry.size or 0,
				locals_str
			)

			local insns = disasm.disasm_function(code_entry)
			local indent_level = 0
			for _, insn in ipairs(insns) do
				local op = insn.opcode
				if op == "end" or op == "else" then
					indent_level = math.max(0, indent_level - 1)
				end

				local raw = insn.raw_bytes or insn.raw
				local hex_bytes = {}
				if raw then
					for b = 1, #raw do
						table.insert(hex_bytes, string.format("%02x", string.byte(raw, b)))
					end
				end
				local hex_str = table.concat(hex_bytes, " ")

				local op_str = insn.opcode
				if insn.operands and insn.operands ~= "" then
					op_str = op_str .. " " .. tostring(insn.operands)
				end

				local indent_spaces = string.rep("  ", indent_level)
				append(" %06x: %-22s | %s%s", insn.pc or 0, hex_str, indent_spaces, op_str)

				if op == "block" or op == "loop" or op == "if" or op == "else" or op == "try_table" then
					indent_level = indent_level + 1
				end
			end
		end
	end

	append("\n" .. string.rep("=", 80))
	append("End of Module Dump")
	append(string.rep("=", 80))

	return table.concat(out, "\n")
end

-- CLI execution support: `lua dumper.lua <file.wasm> [options]`
if arg and arg[0] and (arg[0]:match("dumper%.lua$") or arg[0] == "dumper.lua") and arg[1] then
	local target_file = nil
	local opts = {}

	for _, a in ipairs(arg) do
		if a == "--headers" or a == "-h" then
			opts.headers_only = true
		elseif a == "--disasm" or a == "-d" then
			opts.disasm_only = true
		elseif a == "--no-disasm" or a == "-x" then
			opts.no_disasm = true
		elseif a == "--raw" or a == "-r" then
			opts.raw_data = true
		elseif not target_file and not a:sub(1, 1) == "-" then
			target_file = a
		elseif not target_file then
			target_file = a
		end
	end

	if target_file and target_file ~= "" then
		print(dumper.dump(target_file, opts))
	else
		print("Usage: lua dumper.lua <file.wasm> [options]")
		print("Options:")
		print("  -h, --headers    Print only section headers table")
		print("  -d, --disasm     Print only code disassembly")
		print("  -x, --no-disasm  Print section details without function disassembly")
		print("  -r, --raw        Include full raw hexdumps of data/custom payloads")
	end
end

return dumper
