--- struct_test.lua - Unit tests for Struct API in lwasm
local Test = require("tests.tests")
local lwasm = require("lwasm")
local Struct = lwasm.Struct
local Runtime = require("runtime")

-- Helper to create an in-memory Memory instance
local function create_memory(pages)
	local mem = Runtime.Memory:new(pages or 1)
	return mem
end

Test:describe("Struct > Alignment & Layout", function()
	Test:add("natural alignment and offsets of Capstone cs_insn", function()
		local CS_Insn = Struct({
			{ "id", "u32" },
			{ "address", "i64" },
			{ "size", "u16" },
			{ "bytes", "bytes", 24 },
			{ "mnemonic", "cstring", 32 },
			{ "op_str", "cstring", 160 },
			{ "detail", "ptr" },
		})

		Test:assert_equals(CS_Insn.align, 8)
		Test:assert_equals(CS_Insn.size, 240)
		Test:assert_equals(CS_Insn:offset_of("id"), 0)
		Test:assert_equals(CS_Insn:offset_of("address"), 8)
		Test:assert_equals(CS_Insn:offset_of("size"), 16)
		Test:assert_equals(CS_Insn:offset_of("bytes"), 18)
		Test:assert_equals(CS_Insn:offset_of("mnemonic"), 42)
		Test:assert_equals(CS_Insn:offset_of("op_str"), 74)
		Test:assert_equals(CS_Insn:offset_of("detail"), 236)
	end)

	Test:add("tail padding calculation", function()
		local S = Struct({
			{ "a", "u32" },
			{ "b", "u8" },
		})
		Test:assert_equals(S.align, 4)
		Test:assert_equals(S.size, 8)
	end)

	Test:add("packed struct option", function()
		local P = Struct({
			{ "a", "u8" },
			{ "b", "u32" },
			{ "c", "u64" },
		}, { packed = true })
		Test:assert_equals(P.align, 1)
		Test:assert_equals(P.size, 13)
		Test:assert_equals(P:offset_of("a"), 0)
		Test:assert_equals(P:offset_of("b"), 1)
		Test:assert_equals(P:offset_of("c"), 5)
	end)

	Test:add("pack limit boundary option", function()
		local P2 = Struct({
			{ "a", "u8" },
			{ "b", "u32" },
		}, { pack = 2 })
		Test:assert_equals(P2.align, 2)
		Test:assert_equals(P2:offset_of("a"), 0)
		Test:assert_equals(P2:offset_of("b"), 2)
		Test:assert_equals(P2.size, 6)
	end)
end)

Test:describe("Struct > Read & Write", function()
	Test:add("read and write primitives", function()
		local S = Struct({
			{ "flag", "bool" },
			{ "u16_val", "u16" },
			{ "i32_val", "i32" },
			{ "f64_val", "f64" },
		})

		local mem = create_memory(1)
		local write_data = {
			flag = true,
			u16_val = 1234,
			i32_val = -5678,
			f64_val = 3.1415926535,
		}

		S:write(mem, 16, write_data)
		local read_data = S:read(mem, 16)

		Test:assert_equals(read_data.flag, true)
		Test:assert_equals(read_data.u16_val, 1234)
		Test:assert_equals(read_data.i32_val, -5678)
		Test:assert_true(math.abs(read_data.f64_val - 3.1415926535) < 1e-9)
	end)

	Test:add("strings, cstrings, and length trimming", function()
		local S = Struct({
			{ "len", "u16" },
			{ "tag", "cstring", 16 },
			{ "payload", "bytes", 32, length_field = "len" },
		})

		local mem = create_memory(1)
		S:write(mem, 0, {
			len = 5,
			tag = "HELLO",
			payload = "WORLD1234567890",
		})

		local read_data = S:read(mem, 0)
		Test:assert_equals(read_data.len, 5)
		Test:assert_equals(read_data.tag, "HELLO")
		Test:assert_equals(read_data.payload, "WORLD")
	end)

	Test:add("primitive arrays", function()
		local S = Struct({
			{ "count", "u32" },
			{ "numbers", "u32", 4 },
		})

		local mem = create_memory(1)
		S:write(mem, 0, {
			count = 4,
			numbers = { 10, 20, 30, 40 },
		})

		local read_data = S:read(mem, 0)
		Test:assert_equals(read_data.count, 4)
		Test:assert_equals(#read_data.numbers, 4)
		Test:assert_equals(read_data.numbers[1], 10)
		Test:assert_equals(read_data.numbers[4], 40)
	end)

	Test:add("nested structs", function()
		local Point = Struct({
			{ "x", "f32" },
			{ "y", "f32" },
		})

		local Rect = Struct({
			{ "origin", Point },
			{ "width", "f32" },
			{ "height", "f32" },
		})

		Test:assert_equals(Rect.size, 16)
		Test:assert_equals(Rect.align, 4)

		local mem = create_memory(1)
		Rect:write(mem, 0, {
			origin = { x = 10.5, y = 20.5 },
			width = 100.0,
			height = 200.0,
		})

		local r = Rect:read(mem, 0)
		Test:assert_equals(r.origin.x, 10.5)
		Test:assert_equals(r.origin.y, 20.5)
		Test:assert_equals(r.width, 100.0)
		Test:assert_equals(r.height, 200.0)
	end)

	Test:add("read and write arrays of structs", function()
		local Item = Struct({
			{ "id", "u32" },
			{ "val", "i32" },
		})

		local mem = create_memory(1)
		local items = {
			{ id = 1, val = 100 },
			{ id = 2, val = 200 },
			{ id = 3, val = 300 },
		}

		Item:write_array(mem, 32, items)
		local read_items = Item:read_array(mem, 32, 3)

		Test:assert_equals(#read_items, 3)
		Test:assert_equals(read_items[1].id, 1)
		Test:assert_equals(read_items[1].val, 100)
		Test:assert_equals(read_items[2].id, 2)
		Test:assert_equals(read_items[2].val, 200)
		Test:assert_equals(read_items[3].id, 3)
		Test:assert_equals(read_items[3].val, 300)
	end)
end)

Test:describe("Struct > Zero-copy Views", function()
	Test:add("proxy property reads and writes", function()
		local S = Struct({
			{ "id", "u32" },
			{ "name", "cstring", 16 },
			{ "score", "f32" },
		})

		local mem = create_memory(1)
		local view = S:view(mem, 0)

		-- Direct write through view
		view.id = 99
		view.name = "player1"
		view.score = 99.5

		-- Read through view
		Test:assert_equals(view.id, 99)
		Test:assert_equals(view.name, "player1")
		Test:assert_true(math.abs(view.score - 99.5) < 1e-5)

		-- Convert view to table
		local tbl = view:to_table()
		Test:assert_equals(tbl.id, 99)
		Test:assert_equals(tbl.name, "player1")

		-- View array
		local arr_view = S:view_array(mem, 0, 3)
		Test:assert_equals(#arr_view, 3)
		Test:assert_equals(arr_view[1].id, 99)
	end)
end)

Test:describe("Struct > Alignment Checks & Formatter", function()
	Test:add("alignment detection and validation", function()
		local S = Struct({
			{ "id", "u32" },
			{ "addr", "u64" },
		})

		Test:assert_equals(S.align, 8)
		local ok, err = S:check_alignment(8)
		Test:assert_true(ok)
		Test:assert_nil(err)

		local bad_ok, bad_err = S:check_alignment(12)
		Test:assert_false(bad_ok)
		Test:assert_not_nil(bad_err)

		local StrictS = Struct({
			{ "id", "u64" },
		}, { strict = true })

		local pcall_ok = pcall(function()
			StrictS:check_alignment(3)
		end)
		Test:assert_false(pcall_ok)
	end)

	Test:add("Memory integration methods", function()
		local S = Struct({
			{ "magic", "u32" },
		})

		local mem = create_memory(1)
		mem:write_struct(S, 64, { magic = 0x12345678 })
		local obj = mem:read_struct(S, 64)
		Test:assert_equals(obj.magic, 0x12345678)

		local view = mem:struct_view(S, 64)
		Test:assert_equals(view.magic, 0x12345678)
	end)

	Test:add("struct format output", function()
		local S = Struct({
			{ "id", "u32" },
			{ "val", "u64" },
		})
		local report = S:format()
		Test:assert_not_nil(report:find("struct %(size 16, align 8%)"))
		Test:assert_not_nil(report:find("<padding 4 bytes>"))
	end)
end)

Test:run()
