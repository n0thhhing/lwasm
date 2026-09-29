local Test = require("tests.tests")
local disasm = require("disassembler")
local decoder = require("decoder")

Test:describe("Disassembler Tests", function()
	Test:add("disassemble basic instructions", function()
		local code = "\x20\x00\x20\x01\x41\x20\x10\xc9\x01\x45\x0b"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 6)
		Test:assert_equals(insns[1].opcode, "local.get")
		Test:assert_equals(insns[1].index, 0)
		Test:assert_equals(insns[2].opcode, "local.get")
		Test:assert_equals(insns[2].index, 1)
		Test:assert_equals(insns[3].opcode, "i32.const")
		Test:assert_equals(insns[3].value, 32)
		Test:assert_equals(insns[4].opcode, "call")
		Test:assert_equals(insns[4].index, 201)
		Test:assert_equals(insns[5].opcode, "i32.eqz")
		Test:assert_equals(insns[6].opcode, "end")
	end)

	Test:add("disassemble control flow with blocks", function()
		-- block (result i32) / i32.const 42 / end
		local code = "\x02\x7f\x41\x2a\x0b"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 3)
		Test:assert_equals(insns[1].opcode, "block")
		Test:assert_equals(insns[1].blocktype, "i32")
		Test:assert_equals(insns[2].opcode, "i32.const")
		Test:assert_equals(insns[2].value, 42)
		Test:assert_equals(insns[3].opcode, "end")
	end)

	Test:add("disassemble memory load and store", function()
		-- i32.load align=2 offset=4 / i32.store align=2 offset=0
		local code = "\x28\x02\x04\x36\x02\x00"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 2)
		Test:assert_equals(insns[1].opcode, "i32.load")
		Test:assert_equals(insns[1].align, 2)
		Test:assert_equals(insns[1].offset, 4)
		Test:assert_equals(insns[2].opcode, "i32.store")
		Test:assert_equals(insns[2].align, 2)
		Test:assert_equals(insns[2].offset, 0)
	end)

	Test:add("disassemble 0xFC bulk memory and sat trunc", function()
		-- memory.copy / i32.trunc_sat_f32_s
		local code = "\xfc\x0a\x00\x00\xfc\x00"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 2)
		Test:assert_equals(insns[1].opcode, "memory.copy")
		Test:assert_equals(insns[2].opcode, "i32.trunc_sat_f32_s")
	end)

	Test:add("disassemble functions from decoded function.wasm module", function()
		local mod = decoder.decode_file("build/function.wasm")
		local code_sec = mod.sections.code_section
		Test:assert_true(#code_sec.code >= 90)
		local total_insns = 0
		for _, entry in ipairs(code_sec.code) do
			local insns = disasm.disasm_function(entry)
			total_insns = total_insns + #insns
			Test:assert_true(#insns > 0)
		end
		Test:assert_true(total_insns > 100)
	end)

	Test:add("disassemble 0xFD SIMD instructions", function()
		-- v128.const (16 zeros) + i8x16.add
		local code = "\xfd\x0c" .. string.rep("\x00", 16) .. "\xfd\x6e"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 2)
		Test:assert_equals(insns[1].opcode, "v128.const")
		Test:assert_equals(insns[2].opcode, "i8x16.add")
	end)

	Test:add("generate objdump-style disassembly dump", function()
		local dump_output = disasm.dump("build/global.wasm")
		Test:assert_true(#dump_output > 100)
		Test:assert_true(dump_output:find("func%[") ~= nil)
		Test:assert_true(dump_output:find("<get%-a>") ~= nil)
	end)

	Test:add("decompile full module to WAT", function()
		local wat = disasm.disasm_module("build/global.wasm")
		Test:assert_true(#wat > 200)
		Test:assert_true(wat:find("%(module") ~= nil)
		Test:assert_true(wat:find("%(import") ~= nil)
		Test:assert_true(wat:find("%(func") ~= nil)
		Test:assert_true(wat:find("%(export") ~= nil)
	end)

	Test:add("disassemble Wasm 2.0 exception handling and ref calls", function()
		-- throw 3 / throw_ref / call_ref 5 / return_call_ref 6
		local code = "\x08\x03\x0a\x14\x05\x15\x06"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 4)
		Test:assert_equals(insns[1].opcode, "throw")
		Test:assert_equals(insns[1].tag_index, 3)
		Test:assert_equals(insns[2].opcode, "throw_ref")
		Test:assert_equals(insns[3].opcode, "call_ref")
		Test:assert_equals(insns[3].type_index, 5)
		Test:assert_equals(insns[4].opcode, "return_call_ref")
		Test:assert_equals(insns[4].type_index, 6)
	end)

	Test:add("disassemble legacy exception handling instructions", function()
		local code = "\x06\x40\x07\x02\x09\x01\x18\x00\x19\x0b"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 6)
		Test:assert_equals(insns[1].opcode, "try")
		Test:assert_equals(insns[1].blocktype, "empty")
		Test:assert_equals(insns[2].opcode, "catch")
		Test:assert_equals(insns[2].tag_index, 2)
		Test:assert_equals(insns[3].opcode, "rethrow")
		Test:assert_equals(insns[3].label_index, 1)
		Test:assert_equals(insns[4].opcode, "delegate")
		Test:assert_equals(insns[4].label_index, 0)
		Test:assert_equals(insns[5].opcode, "catch_all")
		Test:assert_equals(insns[6].opcode, "end")
	end)

	Test:add("disassemble Wasm 2.0 try_table instruction", function()
		-- try_table (result i32) with 1 catch clause: kind=0x00 (tag=0, label=1) / end
		local code = "\x1f\x7f\x01\x00\x00\x01\x0b"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 2)
		Test:assert_equals(insns[1].opcode, "try_table")
		Test:assert_equals(insns[1].blocktype, "i32")
		Test:assert_equals(#insns[1].catches, 1)
		Test:assert_equals(insns[1].catches[1].kind, "catch")
		Test:assert_equals(insns[1].catches[1].tag, 0)
		Test:assert_equals(insns[1].catches[1].label, 1)
		Test:assert_equals(insns[2].opcode, "end")
	end)

	Test:add("disassemble Wasm 2.0 reference instructions and GC 0xFB", function()
		-- ref.eq / ref.as_non_null / br_on_null 0 / br_on_non_null 1
		-- 0xFB 0x00 0 (struct.new 0) / 0xFB 0x0F (array.len) / 0xFB 0x1C (ref.i31)
		local code = "\xd3\xd4\xd5\x00\xd6\x01\xfb\x00\x00\xfb\x0f\xfb\x1c"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 7)
		Test:assert_equals(insns[1].opcode, "ref.eq")
		Test:assert_equals(insns[2].opcode, "ref.as_non_null")
		Test:assert_equals(insns[3].opcode, "br_on_null")
		Test:assert_equals(insns[4].opcode, "br_on_non_null")
		Test:assert_equals(insns[5].opcode, "struct.new")
		Test:assert_equals(insns[5].type_index, 0)
		Test:assert_equals(insns[6].opcode, "array.len")
		Test:assert_equals(insns[7].opcode, "ref.i31")
	end)

	Test:add("disassemble Wasm 2.0 multi-memory memarg and relaxed SIMD", function()
		-- i32.load with bit 6 set: align=2 | 0x40 = 0x42, memidx=1, offset=8
		local code = "\x28\x42\x01\x08\xfd\x80\x02\xfd\x85\x02"
		local insns = disasm.disasm(code)
		Test:assert_equals(#insns, 3)
		Test:assert_equals(insns[1].opcode, "i32.load")
		Test:assert_equals(insns[1].align, 2)
		Test:assert_equals(insns[1].mem_index, 1)
		Test:assert_equals(insns[1].offset, 8)
		Test:assert_equals(insns[2].opcode, "i8x16.relaxed_swizzle")
		Test:assert_equals(insns[3].opcode, "f32x4.relaxed_madd")
	end)

	Test:add("dumper generates full wasm file dump", function()
		local dumper = require("dumper")
		local out = dumper.dump("build/global.wasm")
		Test:assert_true(#out > 500)
		Test:assert_true(out:find("WebAssembly Binary Dump") ~= nil)
		Test:assert_true(out:find("Sections Overview") ~= nil)
		Test:assert_true(out:find("Type Section") ~= nil)
		Test:assert_true(out:find("Global Section") ~= nil)
		Test:assert_true(out:find("Export Section") ~= nil)
		Test:assert_true(out:find("Code Section Disassembly") ~= nil)
		Test:assert_true(out:find("End of Module Dump") ~= nil)
	end)

	Test:add("dumper headers-only mode", function()
		local dumper = require("dumper")
		local out = dumper.dump("build/global.wasm", { headers_only = true })
		Test:assert_true(out:find("Sections Overview") ~= nil)
		Test:assert_true(out:find("Code Section Disassembly") == nil)
	end)

	Test:add("dumper data section with hexdump", function()
		local dumper = require("dumper")
		local out = dumper.dump("build/data.wasm")
		Test:assert_true(out:find("Data Section") ~= nil)
		Test:assert_true(out:find("|abcd|") ~= nil)
	end)

	Test:add("lwasm unified library exports and sub-modules", function()
		local lwasm = require("lwasm")
		local init = require("init")
		Test:assert_equals(lwasm, init)
		Test:assert_true(type(lwasm._VERSION) == "string")
		Test:assert_true(type(lwasm.decoder) == "table")
		Test:assert_true(type(lwasm.disassembler) == "table")
		Test:assert_true(type(lwasm.dissasembler) == "table")
		Test:assert_true(type(lwasm.dumper) == "table")
		Test:assert_true(type(lwasm.binary) == "table")
		Test:assert_true(type(lwasm.Binary) == "table")
		Test:assert_true(type(lwasm.opcodes) == "table")
		Test:assert_true(type(lwasm.utils) == "table")
		Test:assert_true(type(lwasm.Module) == "table")
	end)

	Test:add("lwasm callable interface and decoding", function()
		local lwasm = require("lwasm")
		-- Call with filepath
		local mod1 = lwasm("build/global.wasm")
		Test:assert_true(mod1 ~= nil)
		Test:assert_equals(mod1.version, 1)

		-- Call with raw bytes
		local mod2 = lwasm(mod1.raw_bytes)
		Test:assert_true(mod2 ~= nil)
		Test:assert_equals(mod2.version, 1)

		-- Explicit decode and decode_file
		local mod3 = lwasm.decode_file("build/global.wasm")
		local mod4 = lwasm.decode(mod1.raw_bytes)
		Test:assert_equals(mod3.version, 1)
		Test:assert_equals(mod4.version, 1)
	end)

	Test:add("lwasm disassembly and WAT decompilation functions", function()
		local lwasm = require("lwasm")
		local insns = lwasm.disasm("\x20\x00\x0b")
		Test:assert_equals(#insns, 2)
		Test:assert_equals(insns[1].opcode, "local.get")
		Test:assert_equals(insns[2].opcode, "end")

		local wat_snippet = lwasm.disasm_to_string("\x20\x00\x0b")
		Test:assert_true(wat_snippet:find("local.get 0") ~= nil)

		local wat1 = lwasm.disasm_module("build/global.wasm")
		local wat2 = lwasm.to_wat("build/global.wasm")
		Test:assert_equals(wat1, wat2)
		Test:assert_true(wat1:find("%(module") ~= nil)

		local disasm_dump = lwasm.disasm_dump("build/global.wasm")
		Test:assert_true(disasm_dump:find("func%[") ~= nil)
	end)

	Test:add("lwasm Module object methods", function()
		local lwasm = require("lwasm")
		local mod = lwasm("build/global.wasm")

		-- mod:to_wat()
		local wat = mod:to_wat()
		Test:assert_true(type(wat) == "string")
		Test:assert_true(wat:find("%(module") ~= nil)

		-- mod:dump(options)
		local dump_hdr = mod:dump({ headers_only = true })
		Test:assert_true(dump_hdr:find("Sections Overview") ~= nil)
		Test:assert_true(dump_hdr:find("Code Section Disassembly") == nil)

		-- mod:disassemble()
		local dis = mod:disassemble()
		Test:assert_true(dis:find("func%[") ~= nil)
	end)

	Test:add("lwasm format_hexdump utility", function()
		local lwasm = require("lwasm")
		local hex = lwasm.format_hexdump("Hello, WebAssembly!", 16, "  ")
		Test:assert_true(hex:find("48 65 6c 6c 6f", 1, true) ~= nil)
		Test:assert_true(hex:find("|Hello, WebAssemb|", 1, true) ~= nil)
	end)

	Test:add("lwasm namespaced modules and opcodes utilities", function()
		local op = require("opcodes")
		local dec = require("decoder")
		local dis = require("disassembler")
		local dmp = require("dumper")
		local bin = require("binary")

		Test:assert_not_nil(op)
		Test:assert_not_nil(dec)
		Test:assert_not_nil(dis)
		Test:assert_not_nil(dmp)
		Test:assert_not_nil(bin)

		-- Opcode helpers
		Test:assert_equals(op.section_name(op.SECT_TYPE), "type")
		Test:assert_equals(op.section_name(op.SECT_CODE), "code")
		Test:assert_equals(op.desc_name(op.DESC_FUNC), "func")
		Test:assert_equals(op.desc_name(op.DESC_GLOBAL), "global")

		Test:assert_equals(op.valtype_to_string(op.NUM_I32), "i32")
		Test:assert_equals(op.valtype_to_string(op.REF_FUNC), "funcref")
		Test:assert_equals(op.valtype_to_string({ nullable = true, heap_type = 0x70 }), "(ref null func)")
		Test:assert_equals(op.valtype_to_string({ nullable = false, heap_type = 2 }), "(ref 2)")

		Test:assert_true(op.is_prefix(op.PREFIX_MATH))
		Test:assert_true(op.is_prefix(op.PREFIX_SIMD))
		Test:assert_true(op.is_prefix(op.PREFIX_GC))
		Test:assert_true(op.is_prefix(op.PREFIX_THREADS))
		Test:assert_false(op.is_prefix(0x01))
	end)
end)

Test:run()
