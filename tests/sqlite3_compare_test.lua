local Test = require("tests.tests")
local lwasm = require("lwasm")

Test:describe("Comprehensive SQLite3 Verification vs Reference WABT (wasm-objdump)", function()
	local mod = lwasm("build/sqlite3.wasm")

	-- Fetch wasm-objdump -x details once for metadata tests
	local handle_x = io.popen("wasm-objdump -x build/sqlite3.wasm 2>/dev/null")
	local objdump_x = handle_x and handle_x:read("*a") or ""
	if handle_x then
		handle_x:close()
	end

	Test:add("1. Section headers match wasm-objdump -h", function()
		local handle_h = io.popen("wasm-objdump -h build/sqlite3.wasm 2>/dev/null")
		if not handle_h then
			return
		end
		local out = handle_h:read("*a")
		handle_h:close()

		local ref_sections = {}
		for line in out:gmatch("[^\r\n]+") do
			local name, size, count =
				line:match("^%s*([%a_]+)%s+start=0x%x+%s+end=0x%x+%s+%(size=0x(%x+)%)%s+count:%s+(%d+)")
			if name then
				ref_sections[name:lower()] = { size = tonumber(size, 16), count = tonumber(count) }
			end
		end

		Test:assert_equals(mod:get_section("type_section").size, ref_sections["type"].size)
		Test:assert_equals(#mod:get_section("type_section").types, ref_sections["type"].count)

		Test:assert_equals(mod:get_section("import_section").size, ref_sections["import"].size)
		Test:assert_equals(#mod:get_section("import_section").imports, ref_sections["import"].count)

		Test:assert_equals(mod:get_section("func_section").size, ref_sections["function"].size)
		Test:assert_equals(#mod:get_section("func_section").indices, ref_sections["function"].count)

		Test:assert_equals(mod:get_section("export_section").size, ref_sections["export"].size)
		Test:assert_equals(#mod:get_section("export_section").exports, ref_sections["export"].count)

		Test:assert_equals(mod:get_section("code_section").size, ref_sections["code"].size)
		Test:assert_equals(#mod:get_section("code_section").code, ref_sections["code"].count)

		Test:assert_equals(mod:get_section("data_section").size, ref_sections["data"].size)
		Test:assert_equals(mod:get_section("data_section").data_count, ref_sections["data"].count)
	end)

	Test:add("2. All 94 type signatures match wasm-objdump -x", function()
		if objdump_x == "" then
			return
		end
		local type_sec = mod:get_section("type_section")
		local valtype_map = { [0x7F] = "i32", [0x7E] = "i64", [0x7D] = "f32", [0x7C] = "f64" }
		local matches = 0

		for t_idx, params_str, results_str in objdump_x:gmatch("type%[(%d+)%] %((.-)%) %-> ([%a%d_, ]+)") do
			local idx = tonumber(t_idx) + 1
			local t = type_sec.types[idx]

			local l_params = {}
			for _, p in ipairs(t.params) do
				table.insert(l_params, valtype_map[p] or tostring(p))
			end
			local l_params_str = table.concat(l_params, ", ")

			local l_results = {}
			for _, r in ipairs(t.results) do
				table.insert(l_results, valtype_map[r] or tostring(r))
			end
			local l_results_str = #l_results == 0 and "nil" or table.concat(l_results, ", ")

			Test:assert_equals(l_params_str, params_str)
			Test:assert_equals(l_results_str, results_str)
			matches = matches + 1
		end
		Test:assert_equals(matches, 94)
	end)

	Test:add("3. All 36 module imports match wasm-objdump -x", function()
		if objdump_x == "" then
			return
		end
		local imp_sec = mod:get_section("import_section")
		local kind_map = { [0] = "func", [1] = "table", [2] = "memory", [3] = "global", [4] = "tag" }

		local obj_imports = {}
		for line in objdump_x:gmatch("[^\r\n]+") do
			local kind, idx, mod_name, field_name = line:match("^ %- ([%a_]+)%[(%d+)%].* <%- ([^%.]+)%.(%S+)")
			if kind then
				table.insert(obj_imports, { kind = kind, index = tonumber(idx), mod = mod_name, field = field_name })
			end
		end

		Test:assert_equals(#obj_imports, 36)
		Test:assert_equals(#imp_sec.imports, 36)

		for i, imp in ipairs(imp_sec.imports) do
			local ref = obj_imports[i]
			Test:assert_equals(imp.module, ref.mod)
			Test:assert_equals(imp.field, ref.field)
			Test:assert_equals(kind_map[imp.desc], ref.kind)
		end
	end)

	Test:add("4. All 262 exports match wasm-objdump -x", function()
		if objdump_x == "" then
			return
		end
		local exp_sec = mod:get_section("export_section")
		local kind_map = { [0] = "func", [1] = "table", [2] = "memory", [3] = "global", [4] = "tag" }

		local exp_block = objdump_x:match("Export%[%d+%]:(.-)\n%s*[%a_]+%[") or objdump_x:match("Export%[%d+%]:(.*)")
		local obj_exports = {}
		for line in exp_block:gmatch("[^\r\n]+") do
			local kind, idx, name = line:match('^ %- ([%a_]+)%[(%d+)%].* %-> "(.-)"')
			if kind then
				obj_exports[name] = { kind = kind, index = tonumber(idx) }
			end
		end

		Test:assert_equals(#exp_sec.exports, 262)

		for _, exp in ipairs(exp_sec.exports) do
			local ref = obj_exports[exp.name]
			Test:assert_true(ref ~= nil)
			Test:assert_equals(exp.index, ref.index)
			Test:assert_equals(kind_map[exp.desc], ref.kind)
		end
	end)

	Test:add("5. All 2,668 function type signatures match wasm-objdump -x", function()
		if objdump_x == "" then
			return
		end
		local indices = mod:get_section("func_section").indices
		Test:assert_equals(#indices, 2668)

		local func_sigs = {}
		for f_idx, sig in objdump_x:gmatch("func%[(%d+)%] sig=(%d+)") do
			func_sigs[tonumber(f_idx)] = tonumber(sig)
		end

		for i = 1, #indices do
			local f_idx = 35 + (i - 1)
			Test:assert_equals(indices[i], func_sigs[f_idx])
		end
	end)

	Test:add("6. All 431 data segments match wasm-objdump -x", function()
		if objdump_x == "" then
			return
		end
		local data_sec = mod:get_section("data_section")
		Test:assert_equals(#data_sec.entries, 431)

		local seg_count = 0
		for s_idx, size, init_val in objdump_x:gmatch("segment%[(%d+)%] memory=%d+ size=(%d+) %- init i32=(%d+)") do
			local idx = tonumber(s_idx) + 1
			local entry = data_sec.entries[idx]
			Test:assert_true(entry ~= nil)
			Test:assert_equals(entry.size, tonumber(size))
			Test:assert_equals(entry.offset, tonumber(init_val))
			seg_count = seg_count + 1
		end
		Test:assert_equals(seg_count, 431)
	end)

	Test:add("7. Element segment matches wasm-objdump -x", function()
		local elem_sec = mod:get_section("element_section")
		Test:assert_equals(#elem_sec.elements, 1)
		local el = elem_sec.elements[1]
		Test:assert_equals(el.table_index, 0)
		Test:assert_equals(el.offset, 1)
		Test:assert_equals(#el.functions, 633)
		-- Verify first function index (67 in 0-based, stored as 68 in 1-based)
		Test:assert_equals(el.functions[1], 68)
	end)

	-- Full instruction disassembly and operand comparison
	Test:add("8. All 364,625 instruction opcodes and 212,242 operands match wasm-objdump -d", function()
		local handle_d = io.popen("wasm-objdump -d build/sqlite3.wasm 2>/dev/null")
		if not handle_d then
			return
		end

		local cur_func = nil
		local objdump_funcs = {}

		for line in handle_d:lines() do
			local f_idx = line:match("^%x+%s+func%[(%d+)%]")
			if f_idx then
				cur_func = tonumber(f_idx)
				objdump_funcs[cur_func] = {}
			elseif cur_func and line:match("^%s*%x+:") then
				local insn_part = line:match("|%s*(.-)%s*$")
				if insn_part and not insn_part:match("^local%[") and insn_part ~= "" then
					local op, args = insn_part:match("^(%S+)%s*(.-)$")
					if op then
						table.insert(objdump_funcs[cur_func], { op = op, args = args })
					end
				end
			end
		end
		handle_d:close()

		local code_sec = mod:get_section("code_section")
		Test:assert_equals(#code_sec.code, 2668)

		local total_insns = 0
		local calls_checked = 0
		local locals_checked = 0
		local globals_checked = 0
		local branches_checked = 0
		local memory_checked = 0

		for i, code_entry in ipairs(code_sec.code) do
			local func_idx = 35 + (i - 1)
			local lwasm_insns = lwasm.disasm_function(code_entry)
			local obj_insns = objdump_funcs[func_idx] or {}

			Test:assert_equals(#lwasm_insns, #obj_insns)
			total_insns = total_insns + #lwasm_insns

			for j = 1, #lwasm_insns do
				local l = lwasm_insns[j]
				local o = obj_insns[j]

				-- Verify opcode
				Test:assert_equals(l.opcode, o.op)

				-- Verify call target
				if l.opcode == "call" then
					local o_target = o.args:match("^(%d+)")
					Test:assert_equals(tostring(l.index or l.operands), o_target)
					calls_checked = calls_checked + 1
					-- Verify local variable index
				elseif l.opcode == "local.get" or l.opcode == "local.set" or l.opcode == "local.tee" then
					local o_idx = o.args:match("^(%d+)")
					Test:assert_equals(tostring(l.index or l.operands), o_idx)
					locals_checked = locals_checked + 1
					-- Verify global index
				elseif l.opcode == "global.get" or l.opcode == "global.set" then
					local o_idx = o.args:match("^(%d+)")
					Test:assert_equals(tostring(l.index or l.operands), o_idx)
					globals_checked = globals_checked + 1
					-- Verify branch label
				elseif l.opcode == "br" or l.opcode == "br_if" then
					local o_idx = o.args:match("^(%d+)")
					Test:assert_equals(tostring(l.label_index or l.operands), o_idx)
					branches_checked = branches_checked + 1
					-- Verify memory load/store align & offset
				elseif l.opcode:find("%.load") or l.opcode:find("%.store") then
					local o_align, o_offset = o.args:match("^(%d+)%s*(%d*)")
					o_offset = (o_offset and o_offset ~= "") and tonumber(o_offset) or 0
					Test:assert_equals(l.align, tonumber(o_align))
					Test:assert_equals(l.offset, o_offset)
					memory_checked = memory_checked + 1
				end
			end
		end

		Test:assert_equals(total_insns, 364625)
		Test:assert_equals(calls_checked, 14429)
		Test:assert_equals(locals_checked, 132853)
		Test:assert_equals(globals_checked, 2212)
		Test:assert_equals(branches_checked, 18430)
		Test:assert_equals(memory_checked, 44318)
	end)
end)

Test:run()
