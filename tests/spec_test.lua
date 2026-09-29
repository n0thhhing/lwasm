local Test = require("tests.tests")
local lwasm = require("lwasm")

local tmp_dir = "/tmp/lwasm_spec_test"
local wast2json_flags =
	"--enable-threads --enable-function-references --enable-gc --enable-custom-page-sizes --enable-wide-arithmetic"

--- Helper to decode, disassemble, and decompile all valid modules generated from a .wast spec suite.
--- @param wast_file string Path to .wast file.
--- @param suite_name string Suite name identifier.
--- @return integer module_count, integer insn_count
local function verify_spec_suite(wast_file, suite_name)
	os.execute("mkdir -p " .. tmp_dir)
	local json_path = string.format("%s/%s.json", tmp_dir, suite_name)
	local cmd = string.format("wast2json %s %s -o %s 2>/dev/null", wast2json_flags, wast_file, json_path)
	local status = os.execute(cmd)
	if status ~= 0 and status ~= true then
		return 0, 0
	end

	local jf = io.open(json_path, "r")
	if not jf then
		return 0, 0
	end
	local json_text = jf:read("*a")
	jf:close()

	local module_count = 0
	local insn_count = 0

	for fn in json_text:gmatch('"type":%s*"module"[^}]-"filename":%s*"([^"]+)"') do
		local wasm_path = tmp_dir .. "/" .. fn
		local mod = lwasm.decode_file(wasm_path)
		Test:assert_not_nil(mod)
		Test:assert_equals(mod.version, 1)

		if mod.sections.code_section and mod.sections.code_section.code then
			for _, code_entry in ipairs(mod.sections.code_section.code) do
				local insns = lwasm.disasm_function(code_entry)
				Test:assert_true(#insns > 0)
				insn_count = insn_count + #insns
			end
		end

		local wat = mod:to_wat()
		Test:assert_true(#wat > 0)
		module_count = module_count + 1
	end

	return module_count, insn_count
end

Test:describe("Official WebAssembly Spec Testsuite - Control Flow", function()
	local suites = {
		"block",
		"loop",
		"if",
		"br",
		"br_if",
		"br_table",
		"call",
		"call_indirect",
		"return",
		"nop",
		"unreachable",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Numerics & Types", function()
	local suites = {
		"i32",
		"i64",
		"f32",
		"f64",
		"conversions",
		"float_exprs",
		"float_literals",
		"float_misc",
		"int_exprs",
		"int_literals",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Memory Operations", function()
	local suites = {
		"memory",
		"memory_size",
		"memory_grow",
		"memory_copy",
		"memory_fill",
		"data",
		"align",
		"load",
		"store",
		"endianness",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Tables & Elements", function()
	local suites = {
		"table",
		"table_size",
		"table_grow",
		"table_copy",
		"table_fill",
		"table_get",
		"table_set",
		"elem",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Variables & Globals", function()
	local suites = {
		"global",
		"local_get",
		"local_set",
		"local_tee",
		"select",
		"const",
		"unwind",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - SIMD 128-bit", function()
	local suites = {
		"simd_boolean",
		"simd_bitwise",
		"simd_i8x16_arith",
		"simd_i8x16_cmp",
		"simd_i16x8_arith",
		"simd_i32x4_arith",
		"simd_i64x2_arith",
		"simd_f32x4_arith",
		"simd_f64x2_arith",
		"simd_lane",
		"simd_const",
		"simd_conversions",
		"simd_load",
		"simd_splat",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Structure & Linking", function()
	local suites = {
		"comments",
		"custom",
		"exports",
		"fac",
		"forward",
		"func",
		"func_ptrs",
		"labels",
		"linking",
		"start",
		"switch",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Memory64 & 64-bit Address Space", function()
	local suites = {
		"address64",
		"align64",
		"binary_leb128_64",
		"bulk64",
		"call_indirect64",
		"endianness64",
		"float_memory64",
		"load64",
		"memory_copy64",
		"memory_fill64",
		"memory_grow64",
		"memory_init64",
		"memory_redundancy64",
		"memory_trap64",
		"memory64-imports",
		"memory64",
		"table_copy64",
		"table_fill64",
		"table_get64",
		"table_grow64",
		"table_set64",
		"table_size64",
		"table64",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Typed References & Tail Calls", function()
	local suites = {
		"call_ref",
		"return_call",
		"return_call_indirect",
		"return_call_ref",
		"ref_func",
		"ref_as_non_null",
		"ref_is_null",
		"ref",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Multi-Memory & Multi-Table", function()
	local suites = {
		"memory-multi",
		"simd_memory-multi",
		"table-sub",
		"table_copy_mixed",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Relaxed & Extended SIMD", function()
	local suites = {
		"relaxed_dot_product",
		"relaxed_laneselect",
		"relaxed_madd_nmadd",
		"relaxed_min_max",
		"i16x8_relaxed_q15mulr_s",
		"i32x4_relaxed_trunc",
		"i8x16_relaxed_swizzle",
		"simd_address",
		"simd_align",
		"simd_bit_shift",
		"simd_f32x4_pmin_pmax",
		"simd_f32x4_rounding",
		"simd_f64x2_pmin_pmax",
		"simd_f64x2_rounding",
		"simd_i16x8_extadd_pairwise_i8x16",
		"simd_i16x8_extmul_i8x16",
		"simd_i16x8_q15mulr_sat_s",
		"simd_i32x4_dot_i16x8",
		"simd_i32x4_extadd_pairwise_i16x8",
		"simd_i32x4_extmul_i16x8",
		"simd_i32x4_trunc_sat_f32x4",
		"simd_i32x4_trunc_sat_f64x2",
		"simd_i64x2_extmul_i32x4",
		"simd_int_to_int_extend",
		"simd_load_extend",
		"simd_load_splat",
		"simd_load_zero",
		"simd_load8_lane",
		"simd_load16_lane",
		"simd_load32_lane",
		"simd_load64_lane",
		"simd_store8_lane",
		"simd_store16_lane",
		"simd_store32_lane",
		"simd_store64_lane",
	}
	for _, name in ipairs(suites) do
		Test:add(string.format("suite: %s.wast", name), function()
			local modules, insns = verify_spec_suite("spec/" .. name .. ".wast", name)
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Active Proposals", function()
	local proposals = {
		{ name = "threads/atomic", path = "spec/proposals/threads/atomic.wast" },
		{ name = "threads/memory", path = "spec/proposals/threads/memory.wast" },
		{ name = "threads/exports", path = "spec/proposals/threads/exports.wast" },
		{ name = "threads/imports", path = "spec/proposals/threads/imports.wast" },
		{ name = "wide-arithmetic", path = "spec/proposals/wide-arithmetic/wide-arithmetic.wast" },
		{ name = "custom-page-sizes", path = "spec/proposals/custom-page-sizes/custom-page-sizes.wast" },
		{ name = "custom-page-sizes/memory_max", path = "spec/proposals/custom-page-sizes/memory_max.wast" },
		{ name = "custom-page-sizes/memory_max_i64", path = "spec/proposals/custom-page-sizes/memory_max_i64.wast" },
	}
	for _, prop in ipairs(proposals) do
		Test:add(string.format("proposal: %s", prop.name), function()
			local modules, insns = verify_spec_suite(prop.path, prop.name:gsub("/", "_"))
			Test:assert_true(modules > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - WAT Round-Trip Verification", function()
	local representative_suites = { "block", "i32", "fac", "memory", "global", "exports", "simd_boolean", "call" }
	for _, name in ipairs(representative_suites) do
		Test:add(string.format("round-trip: %s.wast decompiled WAT re-assembles with wat2wasm", name), function()
			local wast_path = "spec/" .. name .. ".wast"
			local json_path = string.format("%s/rt_%s.json", tmp_dir, name)
			local cmd = string.format("wast2json %s %s -o %s 2>/dev/null", wast2json_flags, wast_path, json_path)
			local status = os.execute(cmd)
			Test:assert_true(status == 0 or status == true)

			local jf = io.open(json_path, "r")
			Test:assert_not_nil(jf)
			local json_text = jf:read("*a")
			jf:close()

			local count = 0
			for fn in json_text:gmatch('"type":%s*"module"[^}]-"filename":%s*"([^"]+)"') do
				local wasm_path = tmp_dir .. "/" .. fn
				local mod = lwasm.decode_file(wasm_path)
				local wat = mod:to_wat()
				Test:assert_true(#wat > 0)

				local wat_path = string.format("%s/%s.wat", tmp_dir, fn)
				local wasm_out = string.format("%s/%s.rt.wasm", tmp_dir, fn)
				local wf = io.open(wat_path, "w")
				wf:write(wat)
				wf:close()

				local wat2wasm_flags = wast2json_flags .. " --no-check"
				local reassemble_cmd =
					string.format("wat2wasm %s %s -o %s 2>/dev/null", wat2wasm_flags, wat_path, wasm_out)
				local reassemble_status = os.execute(reassemble_cmd)
				Test:assert_true(reassemble_status == 0 or reassemble_status == true)

				-- Verify re-assembled wasm can be decoded by lwasm
				local re_mod = lwasm.decode_file(wasm_out)
				Test:assert_not_nil(re_mod)
				Test:assert_equals(re_mod.version, 1)

				count = count + 1
			end
			Test:assert_true(count > 0)
		end)
	end
end)

Test:describe("Official WebAssembly Spec Testsuite - Full Corpus Mass Verification", function()
	Test:add("verify all remaining official spec files in spec/*.wast", function()
		local p = io.popen("ls spec/*.wast")
		if not p then
			return
		end
		local total_modules = 0
		local total_insns = 0
		local suites_tested = 0

		for wast_path in p:lines() do
			local name = wast_path:match("spec/(.+)%.wast")
			local modules, insns = verify_spec_suite(wast_path, name)
			if modules > 0 then
				suites_tested = suites_tested + 1
				total_modules = total_modules + modules
				total_insns = total_insns + insns
			end
		end
		p:close()

		-- Over 200 spec suites and 2,000+ valid modules should pass
		Test:assert_true(suites_tested >= 200)
		Test:assert_true(total_modules >= 2000)
		Test:assert_true(total_insns >= 40000)
	end)
end)

Test:run()

-- Clean up temporary test files
os.execute("rm -rf " .. tmp_dir)
