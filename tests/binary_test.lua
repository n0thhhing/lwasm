local Test = require("tests.tests")
local Binary = require("binary")

local function bytes(...)
	return string.char(...)
end

local function assert_rejected(method, data, expected_message)
	local ok, message = pcall(function()
		local reader = Binary:new(data)
		return reader[method](reader)
	end)
	Test:assert_false(ok)
	Test:assert_true(tostring(message):find(expected_message, 1, true) ~= nil)
end

Test:describe("Binary LEB128", function()
	Test:add("decodes integer boundaries", function()
		Test:assert_equals(Binary:new(bytes(0xFF, 0xFF, 0xFF, 0xFF, 0x0F)):read_u32LEB(), 0xFFFFFFFF)
		Test:assert_equals(Binary:new(bytes(0x80, 0x80, 0x80, 0x80, 0x78)):read_i32LEB(), -0x80000000)
		Test:assert_equals(Binary:new(bytes(0xFF, 0xFF, 0xFF, 0xFF, 0x7F)):read_i32LEB(), -1)
		Test:assert_equals(
			Binary:new(bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F)):read_i64LEB(),
			-0x8000000000000000
		)
	end)

	Test:add("accepts legal non-minimal encodings", function()
		Test:assert_equals(Binary:new(bytes(0x80, 0x00)):read_u32LEB(), 0)
		Test:assert_equals(Binary:new(bytes(0xFF, 0x7F)):read_i32LEB(), -1)
	end)

	Test:add("rejects encodings longer than their type", function()
		assert_rejected("read_u32LEB", bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x00), "exceeds 5 bytes")
		assert_rejected(
			"read_i64LEB",
			bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00),
			"exceeds 10 bytes"
		)
	end)

	Test:add("rejects values with non-zero unused bits", function()
		assert_rejected("read_u32LEB", bytes(0x80, 0x80, 0x80, 0x80, 0x10), "unused high bits")
		assert_rejected("read_i32LEB", bytes(0x80, 0x80, 0x80, 0x80, 0x08), "sign bit")
		assert_rejected(
			"read_u64LEB",
			bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02),
			"unused high bits"
		)
		assert_rejected("read_i64LEB", bytes(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01), "sign bit")
	end)

	Test:add("reports truncated encodings", function()
		assert_rejected("read_u32LEB", bytes(0x80), "Unexpected EOF")
	end)
end)

Test:run()
