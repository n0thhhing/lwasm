local Test = require("tests.tests")
local lwasm = require("lwasm")

Test:describe("High-level API", function()
	Test:add("returns structured decode errors", function()
		local mod, err = lwasm.try_decode("\0asm\1")
		Test:assert_nil(mod)
		Test:assert_not_nil(err)
		Test:assert_not_nil(err.kind)
		Test:assert_not_nil(err.message)
	end)

	Test:add("validates decoded modules", function()
		local result = lwasm.validate("build/global.wasm")
		Test:assert_true(result.valid)
		Test:assert_equals(#result.errors, 0)
		Test:assert_not_nil(result.module)
	end)

	Test:add("reports module statistics and opcode counts", function()
		local stats = lwasm("build/function.wasm"):stats()
		Test:assert_true(stats.functions >= stats.defined_functions)
		Test:assert_true(stats.instructions > 100)
		Test:assert_true(stats.code_bytes > 0)
		Test:assert_true(stats.opcode_counts["end"] > 0)
	end)

	Test:add("iterates instructions without a module-wide instruction array", function()
		local mod = lwasm("build/function.wasm")
		local count, previous_function = 0, -1
		for insn, function_index in mod:instructions() do
			Test:assert_equals(insn.function_index, function_index)
			Test:assert_true(function_index >= previous_function)
			previous_function = function_index
			count = count + 1
		end
		Test:assert_true(count > 100)
	end)

	Test:add("looks up and disassembles individual functions", function()
		local mod = lwasm("build/global.wasm")
		local func = mod:get_function("get-a")
		Test:assert_not_nil(func)
		Test:assert_false(func.is_import)
		Test:assert_true(#func:disassemble() > 0)
		Test:assert_true(func:to_wat():find("global.get", 1, true) ~= nil)
	end)

	Test:add("opens code and data lazily", function()
		local code_mod = lwasm.open("build/function.wasm")
		local code = code_mod:get_section("code_section").code[1]
		Test:assert_nil(code.body)
		Test:assert_not_nil(code.source)
		Test:assert_true(#lwasm.disasm_function(code) > 0)
		local data_mod = lwasm.open("build/data.wasm")
		local data = data_mod:get_section("data_section").entries[1]
		Test:assert_nil(data.data)
		Test:assert_not_nil(data.source)
		local bytes, segment = data_mod:get_data_segment(0)
		Test:assert_equals(#bytes, segment.size)
		Test:assert_not_nil(data_mod:instantiate())
	end)

	Test:add("compares modules", function()
		local same = lwasm.compare("build/global.wasm", "build/global.wasm")
		Test:assert_true(same.equal)
		Test:assert_equals(#same.differences, 0)
		local different = lwasm.compare("build/global.wasm", "build/function.wasm")
		Test:assert_false(different.equal)
		Test:assert_true(#different.differences > 0)
	end)

	Test:add("lists imports", function()
		local mod = lwasm("build/global.wasm")
		local imports = mod:required_imports()
		Test:assert_true(#imports > 0)
		Test:assert_not_nil(imports[1].module)
		Test:assert_not_nil(imports[1].field)
		Test:assert_true(lwasm.stub_imports(mod).auto_stub)
	end)

	Test:add("benchmarks requested operations", function()
		local result = lwasm.benchmark("build/global.wasm", { iterations = 2, operations = { "decode" } })
		Test:assert_equals(result.iterations, 2)
		Test:assert_true(result.operations.decode.units > 0)
		Test:assert_true(result.operations.decode.rate > 0)
	end)

	Test:add("switches backends programmatically", function()
		local original = lwasm.backend
		Test:assert_equals(lwasm.set_backend("lua"), "lua")
		Test:assert_equals(lwasm.backend, "lua")
		Test:assert_true(#lwasm.available_backends() >= 1)
		lwasm.set_backend(original)
		Test:assert_equals(lwasm.backend, original)
	end)

	Test:add("auto-stubs missing function imports", function()
		local wat_path = "/tmp/lwasm_api_stub.wat"
		local wasm_path = "/tmp/lwasm_api_stub.wasm"
		local file = assert(io.open(wat_path, "w"))
		file:write(
			'(module (import "host" "value" (func $value (result i32))) (func (export "run") (result i32) call $value))'
		)
		file:close()
		local status = os.execute(string.format("wat2wasm %s -o %s", wat_path, wasm_path))
		Test:assert_true(status == true or status == 0)
		local instance = lwasm.instantiate(wasm_path, { auto_stub = true })
		Test:assert_equals(instance.exports.run(), 0)
	end)

	Test:add("exposes sections, types, functions, and resources as views", function()
		local mod = lwasm("build/function.wasm")
		Test:assert_true(#mod:sections() > 0)
		Test:assert_true(#mod:types() > 0)
		Test:assert_not_nil(mod:get_type(0))
		Test:assert_true(#mod:functions() > 0)
		Test:assert_not_nil(mod:get_export("value-i32"))
		local memory_mod = lwasm.from_bytes(lwasm.compile_wat('(module (memory (export "m") 1))'))
		Test:assert_equals(#memory_mod:memories(), 1)
		Test:assert_equals(memory_mod:get_memory(0).index, 0)
	end)

	Test:add("builds call graphs, CFGs, references, and searches", function()
		local mod = lwasm("build/function.wasm")
		local func = assert(mod:get_function("value-i32"))
		Test:assert_not_nil(func:signature())
		Test:assert_true(#func:instructions() > 0)
		Test:assert_not_nil(func:cfg().edges)
		Test:assert_not_nil(func:references().functions)
		Test:assert_not_nil(mod:call_graph().edges)
		Test:assert_true(#mod:find_instructions("i32.const") > 0)
		Test:assert_equals(mod:find_bytes("\0asm")[1].offset, 0)
	end)

	Test:add("encodes, rewrites, strips, detects, and writes modules", function()
		local mod = lwasm("build/function.wasm")
		Test:assert_equals(lwasm.detect(mod:encode()).kind, "module")
		Test:assert_equals(
			mod:rewrite(function()
				return nil
			end),
			mod
		)
		Test:assert_true(mod:strip({ custom = true }):validate().valid)
	end)

	Test:add("traces, snapshots, restores, invokes, and limits instances", function()
		local mod = lwasm("build/function.wasm")
		local instance = mod:instantiate({ fuel = 20 })
		local events = instance:trace()
		Test:assert_equals(instance:invoke("value-i32"), 77)
		instance:stop_trace()
		Test:assert_true(#events > 0)
		instance:restore(instance:snapshot())
		local exhausted = mod:instantiate({ fuel = 0 })
		local value, err = exhausted:invoke("value-i32")
		Test:assert_nil(value)
		Test:assert_equals(err.kind, "trap")
	end)
end)

Test:run()
