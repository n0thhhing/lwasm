--- High-level analysis, validation, comparison, and convenience APIs.

local API = {}

local function count_imports(mod, desc, opcodes)
	local count = 0
	local section = mod:get_section("import_section")
	for _, import in ipairs(section and section.imports or {}) do
		if import.desc == desc then
			count = count + 1
		end
	end
	return count
end

local function structured_error(message)
	message = tostring(message)
	local offset = message:match("offset 0x(%x+)")
	local kind = "decode_error"
	if message:find("LEB", 1, true) then
		kind = "invalid_leb"
	elseif message:find("EOF", 1, true) then
		kind = "unexpected_eof"
	elseif message:find("opcode", 1, true) then
		kind = "unsupported_opcode"
	elseif message:find("section", 1, true) then
		kind = "invalid_section"
	elseif message:find("header", 1, true) or message:find("magic", 1, true) then
		kind = "invalid_header"
	end
	return {
		kind = kind,
		message = message,
		offset = offset and tonumber(offset, 16) or nil,
	}
end

function API.install(lwasm, Module, dependencies)
	local decoder = dependencies.decoder
	local disassembler = dependencies.disassembler
	local opcodes = dependencies.opcodes
	local Binary = dependencies.Binary

	local function ensure_module(input, options)
		if type(input) == "table" and input.sections then
			return input
		elseif type(input) == "string" and input:sub(1, 4) == "\0asm" then
			return decoder.decode(input, options)
		elseif type(input) == "string" then
			return decoder.decode_file(input, options)
		end
		error("Expected decoded module, file path, or Wasm byte string", 3)
	end

	function lwasm.try_decode(input, options)
		local ok, result = pcall(ensure_module, input, options)
		if ok then
			return result, nil
		end
		return nil, structured_error(result)
	end

	function lwasm.open(path, options)
		options = options or { lazy_code = true, lazy_data = true }
		return decoder.decode_file(path, options)
	end

	function lwasm.set_backend(backend)
		local active = Binary.set_backend(backend)
		lwasm.native_enabled = active == "native"
		lwasm.backend = active
		return active
	end

	function lwasm.available_backends()
		return Binary.available_backends()
	end

	function lwasm.backends()
		local active = Binary.get_backend()
		local result = {}
		for _, name in ipairs(Binary.available_backends()) do
			result[#result + 1] = { name = name, active = name == active, available = true }
		end
		return result
	end

	function lwasm.detect(data)
		if type(data) ~= "string" then
			return { kind = "unknown", valid = false, reason = "input is not a string" }
		end
		if data:sub(1, 4) ~= "\0asm" then
			return { kind = "unknown", valid = false, reason = "missing WebAssembly magic" }
		end
		local version = #data >= 8 and string.unpack("<I4", data, 5) or nil
		return { kind = version == 1 and "module" or "unknown", valid = version == 1, version = version }
	end

	function lwasm.validate(input, options)
		local mod, decode_error = lwasm.try_decode(input, options)
		if not mod then
			return { valid = false, errors = { decode_error }, error = decode_error }
		end

		local errors = {}
		local function add(kind, message, fields)
			local item = fields or {}
			item.kind = kind
			item.message = message
			errors[#errors + 1] = item
		end

		local ranks = {
			[1] = 1,
			[2] = 2,
			[3] = 3,
			[4] = 4,
			[5] = 5,
			[13] = 6,
			[6] = 7,
			[7] = 8,
			[8] = 9,
			[9] = 10,
			[12] = 11,
			[10] = 12,
			[11] = 13,
		}
		local seen, last_rank = {}, 0
		for _, section in ipairs(mod.sections.section_list or {}) do
			if section.id ~= 0 then
				local rank = ranks[section.id]
				if seen[section.id] then
					add(
						"duplicate_section",
						"Section " .. section.id .. " occurs more than once",
						{ section = section.id }
					)
				elseif rank and rank < last_rank then
					add("section_order", "Section " .. section.id .. " is out of order", { section = section.id })
				end
				seen[section.id] = true
				last_rank = rank or last_rank
			end
		end

		local types = mod:get_section("type_section")
		local type_count = types and #types.types or 0
		local funcs = mod:get_section("func_section")
		local code = mod:get_section("code_section")
		if (funcs and #funcs.indices or 0) ~= (code and #code.code or 0) then
			add("function_code_mismatch", "Function and code section counts differ")
		end
		for index, type_index in ipairs(funcs and funcs.indices or {}) do
			if type_index >= type_count then
				add(
					"invalid_type_index",
					"Function references a missing type",
					{ function_index = index - 1, type_index = type_index }
				)
			end
		end

		local imports = mod:get_section("import_section")
		for _, import in ipairs(imports and imports.imports or {}) do
			if
				import.desc == opcodes.DESC_FUNC and (not import.index or import.index < 1 or import.index > type_count)
			then
				add(
					"invalid_type_index",
					"Imported function references a missing type",
					{ module = import.module, field = import.field }
				)
			end
		end

		local limits = {
			[opcodes.DESC_FUNC] = count_imports(mod, opcodes.DESC_FUNC, opcodes) + (funcs and #funcs.indices or 0),
			[opcodes.DESC_TABLE] = count_imports(mod, opcodes.DESC_TABLE, opcodes)
				+ #(mod:get_section("table_section") and mod:get_section("table_section").tables or {}),
			[opcodes.DESC_MEM] = count_imports(mod, opcodes.DESC_MEM, opcodes)
				+ #(mod:get_section("mem_section") and mod:get_section("mem_section").memory or {}),
			[opcodes.DESC_GLOBAL] = count_imports(mod, opcodes.DESC_GLOBAL, opcodes)
				+ #(mod:get_section("global_section") and mod:get_section("global_section").globals or {}),
		}
		local exports = mod:get_section("export_section")
		local export_names = {}
		for _, export in ipairs(exports and exports.exports or {}) do
			if export_names[export.name] then
				add("duplicate_export", "Duplicate export name: " .. export.name, { export = export.name })
			end
			export_names[export.name] = true
			if limits[export.desc] and export.index >= limits[export.desc] then
				add(
					"invalid_export_index",
					"Export references a missing item",
					{ export = export.name, index = export.index }
				)
			end
		end

		for index, entry in ipairs(code and code.code or {}) do
			local ok, message = pcall(disassembler.disasm_function, entry)
			if not ok then
				local err = structured_error(message)
				err.function_index = index - 1 + count_imports(mod, opcodes.DESC_FUNC, opcodes)
				errors[#errors + 1] = err
			end
		end

		return { valid = #errors == 0, errors = errors, error = errors[1], module = mod }
	end

	function Module:instructions()
		local code = self:get_section("code_section")
		local entries = code and code.code or {}
		local imported = count_imports(self, opcodes.DESC_FUNC, opcodes)
		local function_index, instructions, instruction_index = 0, nil, 1
		return function()
			while true do
				if instructions and instruction_index <= #instructions then
					local insn = instructions[instruction_index]
					instruction_index = instruction_index + 1
					insn.function_index = imported + function_index - 1
					return insn, insn.function_index
				end
				function_index = function_index + 1
				local entry = entries[function_index]
				if not entry then
					return nil
				end
				instructions = disassembler.disasm_function(entry)
				instruction_index = 1
			end
		end
	end

	function Module:stats()
		local stats = {
			file_size = self.file_size,
			sections = #(self.sections.section_list or {}),
			types = #(self:get_section("type_section") and self:get_section("type_section").types or {}),
			imports = #(self:get_section("import_section") and self:get_section("import_section").imports or {}),
			exports = #(self:get_section("export_section") and self:get_section("export_section").exports or {}),
			functions = count_imports(self, opcodes.DESC_FUNC, opcodes),
			defined_functions = 0,
			instructions = 0,
			code_bytes = 0,
			data_bytes = 0,
			opcode_counts = {},
		}
		local code = self:get_section("code_section")
		stats.defined_functions = #(code and code.code or {})
		stats.functions = stats.functions + stats.defined_functions
		for _, entry in ipairs(code and code.code or {}) do
			stats.code_bytes = stats.code_bytes + (entry.body_size or (entry.body and #entry.body) or 0)
		end
		local data = self:get_section("data_section")
		for _, entry in ipairs(data and data.entries or {}) do
			stats.data_bytes = stats.data_bytes + (entry.size or 0)
		end
		for insn in self:instructions() do
			stats.instructions = stats.instructions + 1
			stats.opcode_counts[insn.opcode] = (stats.opcode_counts[insn.opcode] or 0) + 1
		end
		return stats
	end

	local FunctionView = {}
	FunctionView.__index = FunctionView
	function FunctionView:disassemble()
		return self.entry and disassembler.disasm_function(self.entry) or {}
	end
	function FunctionView:bytes()
		if not self.entry then
			return nil
		end
		if self.entry.body then
			return self.entry.body
		end
		if self.entry.source and self.entry.code_start and self.entry.body_size then
			return self.entry.source:sub(self.entry.code_start, self.entry.code_start + self.entry.body_size - 1)
		end
		return nil
	end
	function FunctionView:to_wat()
		local lines = {}
		for _, insn in ipairs(self:disassemble()) do
			lines[#lines + 1] = insn:to_string()
		end
		return table.concat(lines, "\n")
	end
	function FunctionView:instructions()
		if not self._instructions then
			self._instructions = self:disassemble()
		end
		return self._instructions
	end
	function FunctionView:signature()
		local section = self.module:get_section("type_section")
		return section and section.types[self.type_index + 1] or nil
	end
	function FunctionView:locals()
		local result = {}
		local signature = self:signature() or {}
		for index, value_type in ipairs(signature.params or {}) do
			result[#result + 1] = { index = index - 1, type = value_type, parameter = true }
		end
		for _, declaration in ipairs(self.entry and self.entry.locals or {}) do
			for _ = 1, declaration.count do
				result[#result + 1] = { index = #result, type = declaration.type, parameter = false }
			end
		end
		return result
	end
	function FunctionView:references()
		local refs = { functions = {}, globals = {}, memories = {}, tables = {}, types = {}, data = {} }
		local seen = {}
		local function add(kind, value)
			if value ~= nil and not seen[kind .. ":" .. value] then
				seen[kind .. ":" .. value] = true
				refs[kind][#refs[kind] + 1] = value
			end
		end
		for _, insn in ipairs(self:instructions()) do
			if insn.opcode == "call" or insn.opcode == "return_call" or insn.opcode == "ref.func" then
				add("functions", insn.index or insn.function_index)
			end
			if insn.opcode:find("global", 1, true) then
				add("globals", insn.index)
			end
			if insn.opcode:find("memory", 1, true) or insn.offset then
				add("memories", insn.mem_index or 0)
			end
			if insn.opcode:find("table", 1, true) then
				add("tables", insn.table_index or insn.index or 0)
			end
			add("types", insn.type_index)
			add("data", insn.data_index)
		end
		return refs
	end
	function FunctionView:callees()
		local result = {}
		for _, index in ipairs(self:references().functions) do
			result[#result + 1] = self.module:get_function(index) or index
		end
		return result
	end
	function FunctionView:callers()
		local graph = self.module:call_graph()
		local result = {}
		for _, index in ipairs(graph.callers[self.index] or {}) do
			result[#result + 1] = self.module:get_function(index)
		end
		return result
	end
	function FunctionView:cfg()
		local instructions, nodes, edges = self:instructions(), {}, {}
		for index, insn in ipairs(instructions) do
			nodes[#nodes + 1] = { id = index, pc = insn.pc, instruction = insn }
			if index < #instructions and insn.opcode ~= "return" and insn.opcode ~= "unreachable" then
				edges[#edges + 1] = { from = index, to = index + 1, kind = "fallthrough" }
			end
		end
		return { function_index = self.index, nodes = nodes, edges = edges }
	end

	local function function_names(mod)
		local names = {}
		local exports = mod:get_section("export_section")
		for _, export in ipairs(exports and exports.exports or {}) do
			if export.desc == opcodes.DESC_FUNC then
				names[export.index] = export.name
			end
		end
		local custom = mod:get_custom_section("name")
		if custom and custom.data then
			local bin = Binary:new(custom.data)
			local ok = pcall(function()
				while not bin:eof() do
					local subsection = bin:read_byte()
					local payload = bin:sub_reader(bin:read_u32LEB())
					if subsection == 1 then
						for _ = 1, payload:read_u32LEB() do
							names[payload:read_u32LEB()] = payload:read_name()
						end
					end
				end
			end)
			if not ok then
				-- Debug names are optional metadata; malformed names do not prevent lookup by export.
			end
		end
		return names
	end

	function Module:get_function(identifier)
		local absolute_index, name
		if type(identifier) == "number" then
			absolute_index = identifier
		elseif type(identifier) == "string" then
			for index, candidate in pairs(function_names(self)) do
				if candidate == identifier then
					absolute_index, name = index, candidate
					break
				end
			end
		else
			return nil
		end
		if absolute_index == nil then
			return nil
		end
		local imported = count_imports(self, opcodes.DESC_FUNC, opcodes)
		local func_section = self:get_section("func_section")
		local total_functions = imported + #(func_section and func_section.indices or {})
		if absolute_index < 0 or absolute_index ~= math.floor(absolute_index) or absolute_index >= total_functions then
			return nil
		end
		local defined_index = absolute_index - imported + 1
		local code = self:get_section("code_section")
		local funcs = func_section
		local entry = defined_index > 0 and code and code.code[defined_index] or nil
		if not entry and absolute_index >= imported then
			return nil
		end
		name = name or function_names(self)[absolute_index]
		local imported_type
		if absolute_index < imported then
			local current = 0
			for _, import in ipairs((self:get_section("import_section") or {}).imports or {}) do
				if import.desc == opcodes.DESC_FUNC then
					if current == absolute_index then
						imported_type = import.index - 1
						break
					end
					current = current + 1
				end
			end
		end
		return setmetatable({
			module = self,
			index = absolute_index,
			name = name,
			is_import = absolute_index < imported,
			defined_index = entry and defined_index - 1 or nil,
			type_index = entry and funcs and funcs.indices[defined_index] or imported_type,
			entry = entry,
		}, FunctionView)
	end

	function Module:required_imports()
		local result = {}
		local section = self:get_section("import_section")
		for _, import in ipairs(section and section.imports or {}) do
			result[#result + 1] = import
		end
		return result
	end

	function Module:get_export(name)
		for _, export in ipairs((self:get_section("export_section") or {}).exports or {}) do
			if export.name == name then
				return export
			end
		end
		return nil
	end

	function Module:get_import(module_name, field_name)
		for _, import in ipairs((self:get_section("import_section") or {}).imports or {}) do
			if import.module == module_name and (field_name == nil or import.field == field_name) then
				return import
			end
		end
		return nil
	end

	function Module:custom_sections(name)
		local result = {}
		for _, section in ipairs(self.sections.section_list or {}) do
			if section.id == 0 and (name == nil or section.custom_name == name or section.name == name) then
				result[#result + 1] = section
			end
		end
		return result
	end

	function Module:names()
		return { functions = function_names(self) }
	end

	local function resource_views(mod, section_name, field, import_desc)
		local result, index = {}, 0
		for _, import in ipairs((mod:get_section("import_section") or {}).imports or {}) do
			if import.desc == import_desc then
				result[#result + 1] = { module = mod, index = index, is_import = true, import = import }
				index = index + 1
			end
		end
		for _, value in ipairs((mod:get_section(section_name) or {})[field] or {}) do
			result[#result + 1] = { module = mod, index = index, is_import = false, value = value }
			index = index + 1
		end
		return result
	end

	function Module:types()
		local result = {}
		for index, value in ipairs((self:get_section("type_section") or {}).types or {}) do
			result[#result + 1] =
				{ module = self, index = index - 1, value = value, params = value.params, results = value.results }
		end
		return result
	end
	function Module:get_type(index)
		return self:types()[index + 1]
	end
	function Module:memories()
		return resource_views(self, "mem_section", "memory", opcodes.DESC_MEM)
	end
	function Module:get_memory(index)
		return self:memories()[index + 1]
	end
	function Module:tables()
		return resource_views(self, "table_section", "tables", opcodes.DESC_TABLE)
	end
	function Module:get_table(index)
		return self:tables()[index + 1]
	end
	function Module:globals()
		return resource_views(self, "global_section", "globals", opcodes.DESC_GLOBAL)
	end
	function Module:get_global(index)
		return self:globals()[index + 1]
	end
	function Module:tags()
		return resource_views(self, "tag_section", "tags", opcodes.DESC_TAG)
	end
	function Module:get_tag(index)
		return self:tags()[index + 1]
	end

	function Module:functions()
		local result, stats = {}, self:stats()
		for index = 0, stats.functions - 1 do
			result[#result + 1] = self:get_function(index)
		end
		return result
	end

	function Module:call_graph()
		local graph = { callees = {}, callers = {}, edges = {} }
		for _, func in ipairs(self:functions()) do
			graph.callees[func.index] = {}
			if not func.is_import then
				for _, target in ipairs(func:references().functions) do
					graph.callees[func.index][#graph.callees[func.index] + 1] = target
					graph.callers[target] = graph.callers[target] or {}
					graph.callers[target][#graph.callers[target] + 1] = func.index
					graph.edges[#graph.edges + 1] = { from = func.index, to = target }
				end
			end
		end
		return graph
	end

	function Module:find_instructions(query)
		query = type(query) == "table" and query or { opcode = query }
		local result = {}
		for insn, function_index in self:instructions() do
			if
				(not query.opcode or insn.opcode == query.opcode)
				and (not query.function_index or function_index == query.function_index)
				and (not query.address or insn.pc == query.address)
			then
				result[#result + 1] = { instruction = insn, function_index = function_index }
			end
		end
		return result
	end

	function Module:find_bytes(pattern, options)
		options = options or {}
		local result, start = {}, 1
		while true do
			local first, last = self.raw_bytes:find(pattern, start, options.plain ~= false)
			if not first then
				break
			end
			result[#result + 1] = { offset = first - 1, size = last - first + 1 }
			start = first + 1
		end
		return result
	end

	function Module:validate(options)
		return lwasm.validate(self, options)
	end
	function Module:encode()
		return assert(self.raw_bytes, "module has no original byte representation")
	end
	function Module:write(path)
		local file = assert(io.open(path, "wb"))
		file:write(self:encode())
		file:close()
		return path
	end
	function Module:rewrite(callback)
		local replacement = callback(self)
		if replacement == nil or replacement == self then
			return self
		end
		if type(replacement) == "string" then
			return decoder.decode(replacement)
		end
		error("rewrite callback must return Wasm bytes, the module, or nil", 2)
	end
	function Module:instrument(callback)
		return self:rewrite(callback)
	end
	function Module:strip(options)
		options = options or { custom = true }
		local chunks = { self.raw_bytes:sub(1, 8) }
		for _, section in ipairs(self.sections.section_list or {}) do
			local remove = false
			if section.id == 0 then
				remove = options.custom == true
					or (options.names == true and section.name == "name")
					or (options.debug == true and section.name and section.name:match("^%.debug"))
			end
			if not remove then
				chunks[#chunks + 1] = self.raw_bytes:sub(section.offset + 1, section.body_offset + section.size)
			end
		end
		return decoder.decode(table.concat(chunks), self.options)
	end

	function lwasm.encode(mod)
		return mod:encode()
	end
	function lwasm.rewrite(input, callback)
		return ensure_module(input):rewrite(callback)
	end

	function lwasm.compile_wat(text, options)
		options = options or {}
		assert(type(text) == "string", "WAT source must be a string")
		local input, output = os.tmpname() .. ".wat", os.tmpname() .. ".wasm"
		local file = assert(io.open(input, "wb"))
		file:write(text)
		file:close()
		local function quote(value)
			return "'" .. value:gsub("'", "'\\''") .. "'"
		end
		local command = (options.wat2wasm or "wat2wasm") .. " " .. quote(input) .. " -o " .. quote(output)
		local ok = os.execute(command)
		if not ok or ok == 0 then
			os.remove(input)
			os.remove(output)
			error("wat2wasm failed", 2)
		end
		local wasm = assert(io.open(output, "rb"))
		local bytes = wasm:read("*a")
		wasm:close()
		os.remove(input)
		os.remove(output)
		return bytes
	end

	function Module:get_data_segment(index)
		local section = self:get_section("data_section")
		local entry = section and section.entries[index + 1]
		if not entry then
			return nil
		end
		if entry.data then
			return entry.data, entry
		end
		if entry.source and entry.data_start and entry.size then
			return entry.source:sub(entry.data_start, entry.data_start + entry.size - 1), entry
		end
		return nil, entry
	end

	function lwasm.stub_imports(input)
		local mod = ensure_module(input)
		local result = { auto_stub = true }
		for _, import in ipairs(mod:required_imports()) do
			result[import.module] = result[import.module] or {}
		end
		return result
	end

	function lwasm.compare(left, right, options)
		left, right = ensure_module(left), ensure_module(right)
		options = options or {}
		local differences = {}
		local function check(path, a, b)
			if a ~= b then
				differences[#differences + 1] = { path = path, left = a, right = b }
			end
		end
		local a, b = left:stats(), right:stats()
		for _, field in ipairs({
			"file_size",
			"sections",
			"types",
			"imports",
			"exports",
			"functions",
			"instructions",
			"code_bytes",
			"data_bytes",
		}) do
			check(field, a[field], b[field])
		end
		if options.opcodes ~= false then
			local names = {}
			for name in pairs(a.opcode_counts) do
				names[name] = true
			end
			for name in pairs(b.opcode_counts) do
				names[name] = true
			end
			for name in pairs(names) do
				check("opcode_counts." .. name, a.opcode_counts[name] or 0, b.opcode_counts[name] or 0)
			end
		end
		return { equal = #differences == 0, differences = differences, left = a, right = b }
	end

	function lwasm.benchmark(input, options)
		options = options or {}
		local iterations = options.iterations or 1
		local operations = options.operations or { "decode", "disassemble" }
		assert(
			iterations > 0 and iterations == math.floor(iterations),
			"benchmark iterations must be a positive integer"
		)
		local bytes
		if type(input) == "string" and input:sub(1, 4) == "\0asm" then
			bytes = input
		elseif type(input) == "string" then
			local file = assert(io.open(input, "rb"))
			bytes = assert(file:read("*a"))
			file:close()
		else
			bytes = input.raw_bytes
		end
		local results = { backend = Binary.get_backend(), iterations = iterations, operations = {} }
		for _, operation in ipairs(operations) do
			assert(
				operation == "decode" or operation == "disassemble",
				"unknown benchmark operation: " .. tostring(operation)
			)
			collectgarbage("collect")
			local started, units = os.clock(), 0
			for _ = 1, iterations do
				local mod = decoder.decode(bytes)
				if operation == "disassemble" then
					for _, entry in ipairs((mod:get_section("code_section") or {}).code or {}) do
						units = units + #disassembler.disasm_function(entry)
					end
				else
					units = units + #bytes
				end
			end
			local elapsed = os.clock() - started
			results.operations[operation] =
				{ seconds = elapsed, units = units, rate = elapsed > 0 and units / elapsed or math.huge }
		end
		return results
	end
end

return API
