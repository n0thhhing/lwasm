--- Runtime Test Suite for lwasm
-- Tests the WebAssembly interpreter (runtime.lua) against inline WAT fixtures
-- and the prebuilt wasm binaries in build/.

local Test = require("tests.tests")
local Runtime = require("runtime")

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

local tmp = "/tmp/lwasm_runtime_test"
os.execute("mkdir -p " .. tmp)

--- Compile a WAT snippet to wasm and instantiate it.
--- @param wat string  WAT source text
--- @param name string Unique name for temp files
--- @param imports table|nil Import object for Runtime.instantiate
--- @return table instance
local function compile_and_instantiate(wat, name, imports)
	local wat_path = string.format("%s/%s.wat", tmp, name)
	local wasm_path = string.format("%s/%s.wasm", tmp, name)
	local f = assert(io.open(wat_path, "w"))
	f:write(wat)
	f:close()
	local rc = os.execute(string.format("wat2wasm --enable-all %s -o %s 2>/dev/null", wat_path, wasm_path))
	assert(rc == 0 or rc == true, "wat2wasm failed for " .. name)
	return Runtime.instantiate(wasm_path, imports or {})
end

--- spectest import object (common spec convention)
local spectest_imports = {
	spectest = {
		global_i32 = 0,
		global_i64 = 0,
		global_f32 = 0.0,
		global_f64 = 0.0,
	},
}

--------------------------------------------------------------------------------
-- i32 Arithmetic
--------------------------------------------------------------------------------

Test:describe("Runtime > i32 arithmetic", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "add")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
			(func (export "sub")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.sub)
			(func (export "mul")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.mul)
			(func (export "div_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.div_s)
			(func (export "div_u")(param i32 i32) (result i32) local.get 0 local.get 1 i32.div_u)
			(func (export "rem_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.rem_s)
			(func (export "rem_u")(param i32 i32) (result i32) local.get 0 local.get 1 i32.rem_u)
			(func (export "and")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.and)
			(func (export "or")   (param i32 i32) (result i32) local.get 0 local.get 1 i32.or)
			(func (export "xor")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.xor)
			(func (export "shl")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.shl)
			(func (export "shr_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.shr_s)
			(func (export "shr_u")(param i32 i32) (result i32) local.get 0 local.get 1 i32.shr_u)
			(func (export "clz")  (param i32) (result i32) local.get 0 i32.clz)
			(func (export "ctz")  (param i32) (result i32) local.get 0 i32.ctz)
			(func (export "popcnt")(param i32) (result i32) local.get 0 i32.popcnt)
			(func (export "eqz") (param i32) (result i32) local.get 0 i32.eqz)
			(func (export "eq")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.eq)
			(func (export "ne")  (param i32 i32) (result i32) local.get 0 local.get 1 i32.ne)
			(func (export "lt_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.lt_s)
			(func (export "lt_u")(param i32 i32) (result i32) local.get 0 local.get 1 i32.lt_u)
			(func (export "gt_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.gt_s)
			(func (export "le_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.le_s)
			(func (export "ge_s")(param i32 i32) (result i32) local.get 0 local.get 1 i32.ge_s)
		)
	]],
		"i32_arith"
	)

	Test:add("add", function()
		Test:assert_equals(inst.exports["add"](10, 3), 13)
	end)
	Test:add("add wraps at 32 bits", function()
		Test:assert_equals(inst.exports["add"](0x7fffffff, 1), -2147483648)
	end)
	Test:add("sub", function()
		Test:assert_equals(inst.exports["sub"](10, 3), 7)
	end)
	Test:add("sub underflow wraps", function()
		Test:assert_equals(inst.exports["sub"](0, 1), -1)
	end)
	Test:add("mul", function()
		Test:assert_equals(inst.exports["mul"](6, 7), 42)
	end)
	Test:add("div_s positive", function()
		Test:assert_equals(inst.exports["div_s"](10, 3), 3)
	end)
	Test:add("div_s negative", function()
		Test:assert_equals(inst.exports["div_s"](-10, 3), -3)
	end)
	Test:add("div_u", function()
		Test:assert_equals(inst.exports["div_u"](10, 3), 3)
	end)
	Test:add("rem_s", function()
		Test:assert_equals(inst.exports["rem_s"](10, 3), 1)
	end)
	Test:add("rem_s negative", function()
		Test:assert_equals(inst.exports["rem_s"](-10, 3), -1)
	end)
	Test:add("rem_u", function()
		Test:assert_equals(inst.exports["rem_u"](10, 3), 1)
	end)
	Test:add("and", function()
		Test:assert_equals(inst.exports["and"](0xFF, 0x0F), 0x0F)
	end)
	Test:add("or", function()
		Test:assert_equals(inst.exports["or"](0xF0, 0x0F), 0xFF)
	end)
	Test:add("xor", function()
		Test:assert_equals(inst.exports["xor"](0xFF, 0x0F), 0xF0)
	end)
	Test:add("shl", function()
		Test:assert_equals(inst.exports["shl"](1, 4), 16)
	end)
	Test:add("shr_s positive", function()
		Test:assert_equals(inst.exports["shr_s"](16, 2), 4)
	end)
	Test:add("shr_s negative (sign extend)", function()
		Test:assert_equals(inst.exports["shr_s"](-8, 1), -4)
	end)
	Test:add("shr_u (zero fill)", function()
		-- -1 as i32 = 0xFFFFFFFF; shr_u by 1 = 0x7FFFFFFF = 2147483647
		Test:assert_equals(inst.exports["shr_u"](-1, 1), 2147483647)
	end)
	Test:add("clz of 1", function()
		Test:assert_equals(inst.exports["clz"](1), 31)
	end)
	Test:add("clz of 0x80000000 (MSB set)", function()
		Test:assert_equals(inst.exports["clz"](0x80000000), 0)
	end)
	Test:add("ctz of 4", function()
		Test:assert_equals(inst.exports["ctz"](4), 2)
	end)
	Test:add("ctz of 1", function()
		Test:assert_equals(inst.exports["ctz"](1), 0)
	end)
	Test:add("popcnt", function()
		Test:assert_equals(inst.exports["popcnt"](0xFF), 8)
	end)
	Test:add("eqz true", function()
		Test:assert_equals(inst.exports["eqz"](0), 1)
	end)
	Test:add("eqz false", function()
		Test:assert_equals(inst.exports["eqz"](1), 0)
	end)
	Test:add("eq true", function()
		Test:assert_equals(inst.exports["eq"](5, 5), 1)
	end)
	Test:add("eq false", function()
		Test:assert_equals(inst.exports["eq"](5, 6), 0)
	end)
	Test:add("ne", function()
		Test:assert_equals(inst.exports["ne"](5, 6), 1)
	end)
	Test:add("lt_s signed", function()
		Test:assert_equals(inst.exports["lt_s"](-1, 0), 1)
	end)
	Test:add("lt_u unsigned", function()
		-- -1 as u32 > 0 unsigned
		Test:assert_equals(inst.exports["lt_u"](-1, 0), 0)
	end)
	Test:add("gt_s", function()
		Test:assert_equals(inst.exports["gt_s"](1, -1), 1)
	end)
	Test:add("le_s", function()
		Test:assert_equals(inst.exports["le_s"](3, 3), 1)
	end)
	Test:add("ge_s", function()
		Test:assert_equals(inst.exports["ge_s"](4, 3), 1)
	end)
end)

--------------------------------------------------------------------------------
-- i64 Arithmetic
--------------------------------------------------------------------------------

Test:describe("Runtime > i64 arithmetic", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "add")  (param i64 i64) (result i64) local.get 0 local.get 1 i64.add)
			(func (export "sub")  (param i64 i64) (result i64) local.get 0 local.get 1 i64.sub)
			(func (export "mul")  (param i64 i64) (result i64) local.get 0 local.get 1 i64.mul)
			(func (export "div_s")(param i64 i64) (result i64) local.get 0 local.get 1 i64.div_s)
			(func (export "div_u")(param i64 i64) (result i64) local.get 0 local.get 1 i64.div_u)
			(func (export "rem_s")(param i64 i64) (result i64) local.get 0 local.get 1 i64.rem_s)
			(func (export "and")  (param i64 i64) (result i64) local.get 0 local.get 1 i64.and)
			(func (export "or")   (param i64 i64) (result i64) local.get 0 local.get 1 i64.or)
			(func (export "xor")  (param i64 i64) (result i64) local.get 0 local.get 1 i64.xor)
			(func (export "shl")  (param i64 i64) (result i64) local.get 0 local.get 1 i64.shl)
			(func (export "shr_s")(param i64 i64) (result i64) local.get 0 local.get 1 i64.shr_s)
			(func (export "eqz") (param i64) (result i32) local.get 0 i64.eqz)
			(func (export "eq")  (param i64 i64) (result i32) local.get 0 local.get 1 i64.eq)
			(func (export "lt_s")(param i64 i64) (result i32) local.get 0 local.get 1 i64.lt_s)
		)
	]],
		"i64_arith"
	)

	Test:add("add large", function()
		Test:assert_equals(inst.exports["add"](1000000000, 2000000000), 3000000000)
	end)
	Test:add("sub", function()
		Test:assert_equals(inst.exports["sub"](10, 3), 7)
	end)
	Test:add("mul", function()
		Test:assert_equals(inst.exports["mul"](1000000, 1000000), 1000000000000)
	end)
	Test:add("div_s", function()
		Test:assert_equals(inst.exports["div_s"](100, 7), 14)
	end)
	Test:add("div_u", function()
		Test:assert_equals(inst.exports["div_u"](100, 7), 14)
	end)
	Test:add("rem_s", function()
		Test:assert_equals(inst.exports["rem_s"](100, 7), 2)
	end)
	Test:add("and", function()
		Test:assert_equals(inst.exports["and"](0xFF, 0x0F), 0x0F)
	end)
	Test:add("or", function()
		Test:assert_equals(inst.exports["or"](0xF0, 0x0F), 0xFF)
	end)
	Test:add("xor", function()
		Test:assert_equals(inst.exports["xor"](0xFF, 0x0F), 0xF0)
	end)
	Test:add("shl", function()
		Test:assert_equals(inst.exports["shl"](1, 40), 1099511627776)
	end)
	Test:add("shr_s", function()
		Test:assert_equals(inst.exports["shr_s"](1099511627776, 10), 1073741824)
	end)
	Test:add("eqz true", function()
		Test:assert_equals(inst.exports["eqz"](0), 1)
	end)
	Test:add("eqz false", function()
		Test:assert_equals(inst.exports["eqz"](1), 0)
	end)
	Test:add("eq true", function()
		Test:assert_equals(inst.exports["eq"](5, 5), 1)
	end)
	Test:add("lt_s", function()
		Test:assert_equals(inst.exports["lt_s"](-1, 0), 1)
	end)
end)

--------------------------------------------------------------------------------
-- f32 / f64 Arithmetic
--------------------------------------------------------------------------------

Test:describe("Runtime > float arithmetic", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "f32.add") (param f32 f32) (result f32) local.get 0 local.get 1 f32.add)
			(func (export "f32.mul") (param f32 f32) (result f32) local.get 0 local.get 1 f32.mul)
			(func (export "f32.div") (param f32 f32) (result f32) local.get 0 local.get 1 f32.div)
			(func (export "f32.sqrt")(param f32) (result f32) local.get 0 f32.sqrt)
			(func (export "f32.abs") (param f32) (result f32) local.get 0 f32.abs)
			(func (export "f32.neg") (param f32) (result f32) local.get 0 f32.neg)
			(func (export "f32.ceil")(param f32) (result f32) local.get 0 f32.ceil)
			(func (export "f32.floor")(param f32) (result f32) local.get 0 f32.floor)
			(func (export "f32.eq") (param f32 f32) (result i32) local.get 0 local.get 1 f32.eq)
			(func (export "f32.lt") (param f32 f32) (result i32) local.get 0 local.get 1 f32.lt)
			(func (export "f64.add") (param f64 f64) (result f64) local.get 0 local.get 1 f64.add)
			(func (export "f64.mul") (param f64 f64) (result f64) local.get 0 local.get 1 f64.mul)
			(func (export "f64.sqrt")(param f64) (result f64) local.get 0 f64.sqrt)
			(func (export "f64.min") (param f64 f64) (result f64) local.get 0 local.get 1 f64.min)
			(func (export "f64.max") (param f64 f64) (result f64) local.get 0 local.get 1 f64.max)
			(func (export "f64.eq") (param f64 f64) (result i32) local.get 0 local.get 1 f64.eq)
		)
	]],
		"float_arith"
	)

	local eps = 1e-6
	local function near(a, b)
		return math.abs(a - b) < eps
	end

	Test:add("f32.add", function()
		Test:assert_true(near(inst.exports["f32.add"](1.5, 2.5), 4.0))
	end)
	Test:add("f32.mul", function()
		Test:assert_true(near(inst.exports["f32.mul"](3.0, 4.0), 12.0))
	end)
	Test:add("f32.div", function()
		Test:assert_true(near(inst.exports["f32.div"](10.0, 4.0), 2.5))
	end)
	Test:add("f32.sqrt", function()
		Test:assert_true(near(inst.exports["f32.sqrt"](9.0), 3.0))
	end)
	Test:add("f32.abs", function()
		Test:assert_true(near(inst.exports["f32.abs"](-5.0), 5.0))
	end)
	Test:add("f32.neg", function()
		Test:assert_true(near(inst.exports["f32.neg"](3.0), -3.0))
	end)
	Test:add("f32.ceil", function()
		Test:assert_true(near(inst.exports["f32.ceil"](1.1), 2.0))
	end)
	Test:add("f32.floor", function()
		Test:assert_true(near(inst.exports["f32.floor"](1.9), 1.0))
	end)
	Test:add("f32.eq true", function()
		Test:assert_equals(inst.exports["f32.eq"](1.0, 1.0), 1)
	end)
	Test:add("f32.eq false", function()
		Test:assert_equals(inst.exports["f32.eq"](1.0, 2.0), 0)
	end)
	Test:add("f32.lt", function()
		Test:assert_equals(inst.exports["f32.lt"](1.0, 2.0), 1)
	end)
	Test:add("f64.add", function()
		Test:assert_true(near(inst.exports["f64.add"](1.5, 2.5), 4.0))
	end)
	Test:add("f64.mul", function()
		Test:assert_true(near(inst.exports["f64.mul"](3.0, 4.0), 12.0))
	end)
	Test:add("f64.sqrt", function()
		Test:assert_true(near(inst.exports["f64.sqrt"](16.0), 4.0))
	end)
	Test:add("f64.min", function()
		Test:assert_true(near(inst.exports["f64.min"](2.0, 3.0), 2.0))
	end)
	Test:add("f64.max", function()
		Test:assert_true(near(inst.exports["f64.max"](2.0, 3.0), 3.0))
	end)
	Test:add("f64.eq", function()
		Test:assert_equals(inst.exports["f64.eq"](1.0, 1.0), 1)
	end)
end)

--------------------------------------------------------------------------------
-- Locals
--------------------------------------------------------------------------------

Test:describe("Runtime > locals", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "get0") (param i32 i32) (result i32) local.get 0)
			(func (export "get1") (param i32 i32) (result i32) local.get 1)
			(func (export "set-get") (param i32) (result i32)
				i32.const 99 local.set 0 local.get 0
			)
			(func (export "tee") (param i32) (result i32 i32)
				i32.const 42 local.tee 0 local.get 0
			)
			(func (export "local-default") (result i32)
				(local i32) local.get 0
			)
		)
	]],
		"locals"
	)

	Test:add("get param 0", function()
		Test:assert_equals(inst.exports["get0"](10, 20), 10)
	end)
	Test:add("get param 1", function()
		Test:assert_equals(inst.exports["get1"](10, 20), 20)
	end)
	Test:add("local.set then local.get", function()
		Test:assert_equals(inst.exports["set-get"](0), 99)
	end)
	Test:add("local.tee leaves value on stack", function()
		local a, b = inst.exports["tee"](0)
		Test:assert_equals(a, 42)
		Test:assert_equals(b, 42)
	end)
	Test:add("uninitialized local defaults to 0", function()
		Test:assert_equals(inst.exports["local-default"](), 0)
	end)
end)

--------------------------------------------------------------------------------
-- Globals
--------------------------------------------------------------------------------

Test:describe("Runtime > globals", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(global $imm i32 (i32.const 100))
			(global $mut (mut i32) (i32.const 0))
			(func (export "get-imm") (result i32) global.get 0)
			(func (export "get-mut") (result i32) global.get 1)
			(func (export "set-mut") (param i32) global.get 1 drop local.get 0 global.set 1)
			(func (export "roundtrip") (param i32) (result i32)
				local.get 0 global.set 1 global.get 1
			)
		)
	]],
		"globals"
	)

	Test:add("immutable global get", function()
		Test:assert_equals(inst.exports["get-imm"](), 100)
	end)
	Test:add("mutable global default", function()
		Test:assert_equals(inst.exports["get-mut"](), 0)
	end)
	Test:add("mutable global set and get", function()
		inst.exports["set-mut"](55)
		Test:assert_equals(inst.exports["get-mut"](), 55)
	end)
	Test:add("global roundtrip", function()
		Test:assert_equals(inst.exports["roundtrip"](777), 777)
	end)
end)

--------------------------------------------------------------------------------
-- Memory load / store
--------------------------------------------------------------------------------

Test:describe("Runtime > memory load/store", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(memory 1)
			(func (export "store-i32") (param i32 i32) local.get 0 local.get 1 i32.store)
			(func (export "load-i32")  (param i32) (result i32) local.get 0 i32.load)
			(func (export "store-i8")  (param i32 i32) local.get 0 local.get 1 i32.store8)
			(func (export "load-u8")   (param i32) (result i32) local.get 0 i32.load8_u)
			(func (export "load-s8")   (param i32) (result i32) local.get 0 i32.load8_s)
			(func (export "store-i64") (param i32 i64) local.get 0 local.get 1 i64.store)
			(func (export "load-i64")  (param i32) (result i64) local.get 0 i64.load)
			(func (export "store-f32") (param i32 f32) local.get 0 local.get 1 f32.store)
			(func (export "load-f32")  (param i32) (result f32) local.get 0 f32.load)
			(func (export "store-f64") (param i32 f64) local.get 0 local.get 1 f64.store)
			(func (export "load-f64")  (param i32) (result f64) local.get 0 f64.load)
			(func (export "mem-size")  (result i32) memory.size)
			(func (export "mem-grow")  (param i32) (result i32) local.get 0 memory.grow)
		)
	]],
		"memory"
	)

	Test:add("i32 store and load", function()
		inst.exports["store-i32"](0, 12345)
		Test:assert_equals(inst.exports["load-i32"](0), 12345)
	end)
	Test:add("i32 store negative value", function()
		inst.exports["store-i32"](8, -1)
		Test:assert_equals(inst.exports["load-i32"](8), -1)
	end)
	Test:add("i8 store and load unsigned", function()
		inst.exports["store-i8"](4, 0xFF)
		Test:assert_equals(inst.exports["load-u8"](4), 255)
	end)
	Test:add("i8 store and load signed", function()
		inst.exports["store-i8"](4, 0xFF) -- -1 as i8
		Test:assert_equals(inst.exports["load-s8"](4), -1)
	end)
	Test:add("i64 store and load", function()
		inst.exports["store-i64"](16, 9876543210)
		Test:assert_equals(inst.exports["load-i64"](16), 9876543210)
	end)
	Test:add("f32 store and load", function()
		inst.exports["store-f32"](24, 3.14)
		local v = inst.exports["load-f32"](24)
		Test:assert_true(math.abs(v - 3.14) < 1e-5)
	end)
	Test:add("f64 store and load", function()
		inst.exports["store-f64"](32, 2.718281828)
		local v = inst.exports["load-f64"](32)
		Test:assert_true(math.abs(v - 2.718281828) < 1e-9)
	end)
	Test:add("memory.size returns 1 initially", function()
		Test:assert_equals(inst.exports["mem-size"](), 1)
	end)
	Test:add("memory.grow succeeds", function()
		local old = inst.exports["mem-grow"](1)
		Test:assert_equals(old, 1)
		Test:assert_equals(inst.exports["mem-size"](), 2)
	end)
end)

--------------------------------------------------------------------------------
-- Control Flow
--------------------------------------------------------------------------------

Test:describe("Runtime > control flow", function()
	local inst = compile_and_instantiate(
		[[
		(module
			;; block: break out early
			(func (export "block-br") (result i32)
				(block (result i32)
					i32.const 1
					br 0
					i32.const 2
				)
			)
			;; loop: count to N using accumulator
			(func (export "loop-count") (param i32) (result i32)
				(local i32)
				(loop
					local.get 0
					i32.const 0
					i32.gt_s
					(if
						(then
							local.get 0
							local.get 1
							i32.add
							local.set 1
							local.get 0
							i32.const 1
							i32.sub
							local.set 0
							br 1
						)
					)
				)
				local.get 1
			)
			;; if/else with result
			(func (export "sign") (param i32) (result i32)
				(if (result i32) (local.get 0)
					(then i32.const 1)
					(else i32.const -1)
				)
			)
			;; br_if: branch if cond nonzero, else fall through
			(func (export "br-if-test") (param i32) (result i32)
				(block (result i32)
					i32.const 99
					local.get 0
					br_if 0
					drop
					i32.const 0
				)
			)
			;; early return using `return` instruction via br_if
			(func (export "early-return") (param i32) (result i32)
				(block
					local.get 0
					i32.const 5
					i32.gt_s
					i32.eqz
					br_if 0
					i32.const 100
					return
				)
				i32.const 0
			)
			;; nested blocks propagate value
			(func (export "nested") (result i32)
				(block (result i32)
					(block (result i32)
						i32.const 7
					)
				)
			)
			;; select instruction
			(func (export "select-t") (param i32) (result i32)
				i32.const 10  i32.const 20  local.get 0  select
			)
		)
	]],
		"control"
	)

	Test:add("block with br exits and leaves value", function()
		Test:assert_equals(inst.exports["block-br"](), 1)
	end)
	Test:add("loop-count sums 1..5 = 15", function()
		Test:assert_equals(inst.exports["loop-count"](5), 15)
	end)
	Test:add("loop-count with 0 = 0", function()
		Test:assert_equals(inst.exports["loop-count"](0), 0)
	end)
	Test:add("if/else true branch", function()
		Test:assert_equals(inst.exports["sign"](1), 1)
	end)
	Test:add("if/else false branch", function()
		Test:assert_equals(inst.exports["sign"](0), -1)
	end)
	Test:add("br_if taken", function()
		Test:assert_equals(inst.exports["br-if-test"](1), 99)
	end)
	Test:add("br_if not taken", function()
		Test:assert_equals(inst.exports["br-if-test"](0), 0)
	end)
	Test:add("early return when > 5", function()
		Test:assert_equals(inst.exports["early-return"](10), 100)
	end)
	Test:add("early return skipped when <= 5", function()
		Test:assert_equals(inst.exports["early-return"](3), 0)
	end)
	Test:add("nested blocks propagate value", function()
		Test:assert_equals(inst.exports["nested"](), 7)
	end)
	Test:add("select truthy picks first", function()
		Test:assert_equals(inst.exports["select-t"](1), 10)
	end)
	Test:add("select falsy picks second", function()
		Test:assert_equals(inst.exports["select-t"](0), 20)
	end)
end)

--------------------------------------------------------------------------------
-- Function Calls (direct and indirect)
--------------------------------------------------------------------------------

Test:describe("Runtime > function calls", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(type $iii (func (param i32 i32) (result i32)))
			(table 2 funcref)
			(elem (i32.const 0) $add $mul)
			(func $add (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
			(func $mul (param i32 i32) (result i32) local.get 0 local.get 1 i32.mul)
			(func (export "direct-add") (param i32 i32) (result i32) local.get 0 local.get 1 call $add)
			(func (export "indirect") (param i32 i32 i32) (result i32)
				local.get 0 local.get 1 local.get 2 call_indirect (type $iii)
			)
			(func (export "factorial") (param i32) (result i32)
				local.get 0
				i32.const 1
				i32.le_s
				(if (result i32)
					(then i32.const 1)
					(else
						local.get 0
						local.get 0
						i32.const 1
						i32.sub
						call 4   ;; factorial itself (func index 4)
						i32.mul
					)
				)
			)
		)
	]],
		"calls"
	)

	Test:add("direct call", function()
		Test:assert_equals(inst.exports["direct-add"](3, 4), 7)
	end)
	Test:add("call_indirect add (elem 0)", function()
		Test:assert_equals(inst.exports["indirect"](10, 20, 0), 30)
	end)
	Test:add("call_indirect mul (elem 1)", function()
		Test:assert_equals(inst.exports["indirect"](5, 6, 1), 30)
	end)
	Test:add("recursive factorial(5) = 120", function()
		Test:assert_equals(inst.exports["factorial"](5), 120)
	end)
	Test:add("recursive factorial(0) = 1", function()
		Test:assert_equals(inst.exports["factorial"](0), 1)
	end)
end)

--------------------------------------------------------------------------------
-- Multiple Returns
--------------------------------------------------------------------------------

Test:describe("Runtime > multiple returns", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "swap") (param i32 i32) (result i32 i32)
				local.get 1 local.get 0
			)
			(func (export "minmax") (param i32 i32) (result i32 i32)
				(if (result i32 i32) (i32.lt_s (local.get 0) (local.get 1))
					(then local.get 0 local.get 1)
					(else local.get 1 local.get 0)
				)
			)
		)
	]],
		"multi_return"
	)

	Test:add("swap returns reversed args", function()
		local a, b = inst.exports["swap"](10, 20)
		Test:assert_equals(a, 20)
		Test:assert_equals(b, 10)
	end)
	Test:add("minmax(3,7) = (3,7)", function()
		local mn, mx = inst.exports["minmax"](3, 7)
		Test:assert_equals(mn, 3)
		Test:assert_equals(mx, 7)
	end)
	Test:add("minmax(9,2) = (2,9)", function()
		local mn, mx = inst.exports["minmax"](9, 2)
		Test:assert_equals(mn, 2)
		Test:assert_equals(mx, 9)
	end)
end)

--------------------------------------------------------------------------------
-- Type Conversions
--------------------------------------------------------------------------------

Test:describe("Runtime > type conversions", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "i32-wrap-i64")     (param i64) (result i32) local.get 0 i32.wrap_i64)
			(func (export "i64-extend-s-i32") (param i32) (result i64) local.get 0 i64.extend_i32_s)
			(func (export "i64-extend-u-i32") (param i32) (result i64) local.get 0 i64.extend_i32_u)
			(func (export "f32-demote-f64")   (param f64) (result f32) local.get 0 f32.demote_f64)
			(func (export "f64-promote-f32")  (param f32) (result f64) local.get 0 f64.promote_f32)
			(func (export "i32-trunc-f32-s")  (param f32) (result i32) local.get 0 i32.trunc_f32_s)
			(func (export "f32-convert-i32-s")(param i32) (result f32) local.get 0 f32.convert_i32_s)
			(func (export "f64-convert-i32-s")(param i32) (result f64) local.get 0 f64.convert_i32_s)
		)
	]],
		"conversions"
	)

	Test:add("i32.wrap_i64 truncates to 32 bits", function()
		Test:assert_equals(inst.exports["i32-wrap-i64"](0x100000005), 5)
	end)
	Test:add("i64.extend_i32_s sign-extends -1", function()
		Test:assert_equals(inst.exports["i64-extend-s-i32"](-1), -1)
	end)
	Test:add("i64.extend_i32_u zero-extends -1", function()
		Test:assert_equals(inst.exports["i64-extend-u-i32"](-1), 0xFFFFFFFF)
	end)
	Test:add("f32.demote_f64", function()
		local v = inst.exports["f32-demote-f64"](3.14)
		Test:assert_true(math.abs(v - 3.14) < 1e-5)
	end)
	Test:add("f64.promote_f32", function()
		local v = inst.exports["f64-promote-f32"](1.5)
		Test:assert_true(math.abs(v - 1.5) < 1e-9)
	end)
	Test:add("i32.trunc_f32_s", function()
		Test:assert_equals(inst.exports["i32-trunc-f32-s"](3.9), 3)
	end)
	Test:add("f32.convert_i32_s", function()
		local v = inst.exports["f32-convert-i32-s"](42)
		Test:assert_true(math.abs(v - 42.0) < 1e-5)
	end)
	Test:add("f64.convert_i32_s negative", function()
		local v = inst.exports["f64-convert-i32-s"](-5)
		Test:assert_true(math.abs(v - -5.0) < 1e-9)
	end)
end)

--------------------------------------------------------------------------------
-- Error cases
--------------------------------------------------------------------------------

Test:describe("Runtime > error cases", function()
	Test:add("division by zero traps", function()
		local inst = compile_and_instantiate(
			[[
			(module
				(func (export "div") (param i32 i32) (result i32)
					local.get 0 local.get 1 i32.div_s)
			)
		]],
			"div_trap"
		)
		local ok, err = pcall(inst.exports["div"], 1, 0)
		Test:assert_false(ok)
		Test:assert_true(err:find("zero") ~= nil or err:find("div") ~= nil)
	end)

	Test:add("immutable global set traps (Lua API)", function()
		-- WAT validators reject global.set on immutable globals at compile time,
		-- so we test the runtime Guard directly via the exposed module API.
		local Runtime = require("runtime")
		local inst = compile_and_instantiate(
			[[
			(module
				(global (mut i32) (i32.const 10))
				(global i32 (i32.const 42))
				(func (export "get-imm") (result i32) global.get 1)
			)
		]],
			"imm_guard"
		)
		-- The immutable global at index 2 (1-based) should refuse set()
		local ok, err = pcall(function()
			inst.globals[2]:set(99)
		end)
		Test:assert_false(ok)
		Test:assert_true(err:find("immutable") ~= nil)
		-- Mutable one at index 1 is fine
		inst.globals[1]:set(99)
		Test:assert_equals(inst.globals[1]:get(), 99)
	end)

	Test:add("unreachable traps", function()
		local inst = compile_and_instantiate(
			[[
			(module
				(func (export "trap") unreachable)
			)
		]],
			"unreachable_trap"
		)
		local ok = pcall(inst.exports["trap"])
		Test:assert_false(ok)
	end)
end)

--------------------------------------------------------------------------------
-- Integration: global.wasm fixture
--------------------------------------------------------------------------------

Test:describe("Runtime > global.wasm integration", function()
	local inst = Runtime.instantiate("build/global.wasm", spectest_imports)

	Test:add("get-a = -2 (immutable i32)", function()
		Test:assert_equals(inst.exports["get-a"](), -2)
	end)
	Test:add("get-b = -5 (immutable i64)", function()
		Test:assert_equals(inst.exports["get-b"](), -5)
	end)
	Test:add("get-x = -12 (mutable i32, initial)", function()
		Test:assert_equals(inst.exports["get-x"](), -12)
	end)
	Test:add("set-x and get-x roundtrip", function()
		inst.exports["set-x"](999)
		Test:assert_equals(inst.exports["get-x"](), 999)
		inst.exports["set-x"](-12) -- restore
	end)
	Test:add("get-y = -15 (mutable i64)", function()
		Test:assert_equals(inst.exports["get-y"](), -15)
	end)
	Test:add("set-y and get-y roundtrip", function()
		inst.exports["set-y"](12345678900)
		Test:assert_equals(inst.exports["get-y"](), 12345678900)
	end)
	Test:add("get-z1 = spectest.global_i32 = 0", function()
		Test:assert_equals(inst.exports["get-z1"](), 0)
	end)
	Test:add("get-3 = -3.0 (immutable f32)", function()
		Test:assert_true(math.abs(inst.exports["get-3"]() - -3.0) < 1e-6)
	end)
	Test:add("get-4 = -4.0 (immutable f64)", function()
		Test:assert_true(math.abs(inst.exports["get-4"]() - -4.0) < 1e-9)
	end)
	Test:add("set-7 and get-7 (mutable f32)", function()
		inst.exports["set-7"](2.5)
		Test:assert_true(math.abs(inst.exports["get-7"]() - 2.5) < 1e-5)
	end)
	Test:add("set-8 and get-8 (mutable f64)", function()
		inst.exports["set-8"](1.23456789)
		Test:assert_true(math.abs(inst.exports["get-8"]() - 1.23456789) < 1e-9)
	end)
	Test:add("as-if-condition uses global $x", function()
		inst.exports["set-x"](1)
		Test:assert_equals(inst.exports["as-if-condition"](), 2) -- then branch
		inst.exports["set-x"](0)
		Test:assert_equals(inst.exports["as-if-condition"](), 3) -- else branch
		inst.exports["set-x"](-12) -- restore
	end)
	Test:add("as-binary-operand = x*x", function()
		inst.exports["set-x"](5)
		Test:assert_equals(inst.exports["as-binary-operand"](), 25)
		inst.exports["set-x"](-12)
	end)
	Test:add("as-loop-last returns x", function()
		inst.exports["set-x"](77)
		Test:assert_equals(inst.exports["as-loop-last"](), 77)
		inst.exports["set-x"](-12)
	end)
end)

--------------------------------------------------------------------------------
-- Integration: function.wasm fixture
--------------------------------------------------------------------------------

Test:describe("Runtime > function.wasm integration", function()
	local inst = Runtime.instantiate("build/function.wasm")

	Test:add("value-i32 returns 77", function()
		Test:assert_equals(inst.exports["value-i32"](), 77)
	end)
	Test:add("value-i64 returns 7777", function()
		Test:assert_equals(inst.exports["value-i64"](), 7777)
	end)
	Test:add("value-f32 near 77.7", function()
		Test:assert_true(math.abs(inst.exports["value-f32"]() - 77.7) < 0.01)
	end)
	Test:add("value-f64 near 77.77", function()
		Test:assert_true(math.abs(inst.exports["value-f64"]() - 77.77) < 0.001)
	end)
	Test:add("empty returns nothing", function()
		local r = inst.exports["empty"]()
		Test:assert_nil(r)
	end)
	Test:add("value-void returns nothing", function()
		local r = inst.exports["value-void"]()
		Test:assert_nil(r)
	end)
	Test:add("return-i32 = 78", function()
		Test:assert_equals(inst.exports["return-i32"](), 78)
	end)
	Test:add("return-i64 = 7878", function()
		Test:assert_equals(inst.exports["return-i64"](), 7878)
	end)
	Test:add("break-i32 = 79", function()
		Test:assert_equals(inst.exports["break-i32"](), 79)
	end)
	Test:add("break-i64 = 7979", function()
		Test:assert_equals(inst.exports["break-i64"](), 7979)
	end)
	Test:add("local-first-i32 = 0 (default)", function()
		Test:assert_equals(inst.exports["local-first-i32"](), 0)
	end)
	Test:add("local-first-i64 = 0 (default)", function()
		Test:assert_equals(inst.exports["local-first-i64"](), 0)
	end)
	Test:add("param-first-i32 returns first param", function()
		Test:assert_equals(inst.exports["param-first-i32"](10, 20), 10)
	end)
	Test:add("param-second-i32 returns second param", function()
		Test:assert_equals(inst.exports["param-second-i32"](10, 20), 20)
	end)
	Test:add("init-local-i32 = 0", function()
		Test:assert_equals(inst.exports["init-local-i32"](), 0)
	end)
	Test:add("break-br_if-empty (cond=0 no break)", function()
		inst.exports["break-br_if-empty"](0) -- should not crash
	end)
	Test:add("break-br_if-num with cond=1 returns 50", function()
		Test:assert_equals(inst.exports["break-br_if-num"](1), 50)
	end)
	Test:add("break-br_if-num with cond=0 returns 51", function()
		Test:assert_equals(inst.exports["break-br_if-num"](0), 51)
	end)
	Test:add("break-br_table-num(0) = 50", function()
		Test:assert_equals(inst.exports["break-br_table-num"](0), 50)
	end)
	Test:add("type-use-2 returns 0", function()
		Test:assert_equals(inst.exports["type-use-2"](), 0)
	end)
	Test:add("value-block-i32 = 77", function()
		Test:assert_equals(inst.exports["value-block-i32"](), 77)
	end)
	Test:add("return-block-i32 = 77", function()
		Test:assert_equals(inst.exports["return-block-i32"](), 77)
	end)
end)

--------------------------------------------------------------------------------
-- Saturating Truncations (Non-trapping float-to-int)
--------------------------------------------------------------------------------

Test:describe("Runtime > saturating truncations", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func (export "trunc_sat_f32_s") (param f32) (result i32) local.get 0 i32.trunc_sat_f32_s)
			(func (export "trunc_sat_f32_u") (param f32) (result i32) local.get 0 i32.trunc_sat_f32_u)
			(func (export "trunc_sat_f64_s") (param f64) (result i32) local.get 0 i32.trunc_sat_f64_s)
		)
	]],
		"trunc_sat"
	)

	Test:add("trunc_sat_f32_s in range", function()
		Test:assert_equals(inst.exports["trunc_sat_f32_s"](42.7), 42)
	end)
	Test:add("trunc_sat_f32_s overflow saturates to max int", function()
		Test:assert_equals(inst.exports["trunc_sat_f32_s"](1e15), 2147483647)
	end)
	Test:add("trunc_sat_f32_s underflow saturates to min int", function()
		Test:assert_equals(inst.exports["trunc_sat_f32_s"](-1e15), -2147483648)
	end)
	Test:add("trunc_sat_f32_u underflow saturates to 0", function()
		Test:assert_equals(inst.exports["trunc_sat_f32_u"](-10.0), 0)
	end)
	Test:add("trunc_sat_f64_s normal", function()
		Test:assert_equals(inst.exports["trunc_sat_f64_s"](-100.5), -100)
	end)
end)

--------------------------------------------------------------------------------
-- Bulk Memory & Tables
--------------------------------------------------------------------------------

Test:describe("Runtime > bulk memory & tables", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(memory 1)
			(table 2 funcref)
			(func $f1 (result i32) i32.const 101)
			(elem (i32.const 0) $f1)
			(func (export "test_fill") (param i32 i32 i32)
				local.get 0 local.get 1 local.get 2 memory.fill
			)
			(func (export "test_copy") (param i32 i32 i32)
				local.get 0 local.get 1 local.get 2 memory.copy
			)
			(func (export "load_u8") (param i32) (result i32)
				local.get 0 i32.load8_u
			)
			(func (export "get_tbl_size") (result i32)
				table.size 0
			)
			(func (export "grow_tbl") (param i32) (result i32)
				ref.null func local.get 0 table.grow 0
			)
		)
	]],
		"bulk_mem_table"
	)

	Test:add("memory.fill fills bytes", function()
		inst.exports["test_fill"](10, 0xAB, 4)
		Test:assert_equals(inst.exports["load_u8"](10), 0xAB)
		Test:assert_equals(inst.exports["load_u8"](11), 0xAB)
		Test:assert_equals(inst.exports["load_u8"](12), 0xAB)
		Test:assert_equals(inst.exports["load_u8"](13), 0xAB)
		Test:assert_equals(inst.exports["load_u8"](14), 0)
	end)
	Test:add("memory.copy copies bytes", function()
		inst.exports["test_copy"](20, 10, 2)
		Test:assert_equals(inst.exports["load_u8"](20), 0xAB)
		Test:assert_equals(inst.exports["load_u8"](21), 0xAB)
		Test:assert_equals(inst.exports["load_u8"](22), 0)
	end)
	Test:add("table.size returns initial size", function()
		Test:assert_equals(inst.exports["get_tbl_size"](), 2)
	end)
	Test:add("table.grow grows table", function()
		local old = inst.exports["grow_tbl"](3)
		Test:assert_equals(old, 2)
		Test:assert_equals(inst.exports["get_tbl_size"](), 5)
	end)
end)

--------------------------------------------------------------------------------
-- Tail Calls
--------------------------------------------------------------------------------

Test:describe("Runtime > tail calls", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(func $sub (param i32 i32) (result i32)
				local.get 0 local.get 1 i32.sub
			)
			(func (export "test_return_call") (param i32 i32) (result i32)
				local.get 0 local.get 1 return_call $sub
			)
		)
	]],
		"tail_call"
	)

	Test:add("return_call delegates and returns result", function()
		Test:assert_equals(inst.exports["test_return_call"](20, 7), 13)
	end)
end)

--------------------------------------------------------------------------------
-- Typed Function References
--------------------------------------------------------------------------------

Test:describe("Runtime > typed function references", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(type $sig (func (param i32) (result i32)))
			(func $triple (type $sig)
				local.get 0 i32.const 3 i32.mul
			)
			(elem declare func $triple)
			(func (export "test_call_ref") (param i32) (result i32)
				local.get 0
				ref.func $triple
				call_ref $sig
			)
			(func (export "test_ref_is_null") (result i32)
				ref.null func
				ref.is_null
			)
			(func (export "test_ref_func_not_null") (result i32)
				ref.func $triple
				ref.is_null
			)
		)
	]],
		"typed_ref"
	)

	Test:add("call_ref invokes function reference", function()
		Test:assert_equals(inst.exports["test_call_ref"](7), 21)
	end)
	Test:add("ref.is_null returns 1 for null", function()
		Test:assert_equals(inst.exports["test_ref_is_null"](), 1)
	end)
	Test:add("ref.is_null returns 0 for ref.func", function()
		Test:assert_equals(inst.exports["test_ref_func_not_null"](), 0)
	end)
end)

--------------------------------------------------------------------------------
-- Conditional Reference Branches
--------------------------------------------------------------------------------

Test:describe("Runtime > conditional reference branches", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(type $sig (func (result i32)))
			(func $fortytwo (type $sig) (result i32) i32.const 42)
			(elem declare func $fortytwo)
			(func (export "test_br_on_null") (param i32) (result i32)
				(block $b (result i32)
					(block $null_target
						local.get 0
						if (result (ref null $sig))
							ref.func $fortytwo
						else
							ref.null $sig
						end
						br_on_null $null_target
						call_ref $sig
						br $b
					)
					i32.const 99
				)
			)
			(func (export "test_br_on_non_null") (param i32) (result i32)
				(block $b (result (ref $sig))
					local.get 0
					if (result (ref null $sig))
						ref.func $fortytwo
					else
						ref.null $sig
					end
					br_on_non_null $b
					ref.func $fortytwo
				)
				call_ref $sig
			)
		)
	]],
		"br_on_ref"
	)

	Test:add("br_on_null taken when null", function()
		Test:assert_equals(inst.exports["test_br_on_null"](0), 99)
	end)
	Test:add("br_on_null not taken when non-null", function()
		Test:assert_equals(inst.exports["test_br_on_null"](1), 42)
	end)
	Test:add("br_on_non_null returns function reference", function()
		Test:assert_equals(inst.exports["test_br_on_non_null"](1), 42)
		Test:assert_equals(inst.exports["test_br_on_non_null"](0), 42)
	end)
end)

--------------------------------------------------------------------------------
-- Exception Handling
--------------------------------------------------------------------------------

Test:describe("Runtime > exception handling", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(tag $e (param i32))
			(func (export "test_try_catch") (param i32) (result i32)
				(block $c (result i32)
					(try_table (catch $e $c)
						local.get 0
						throw $e
					)
					i32.const -1
				)
			)
			(func (export "test_try_nocatch") (result i32)
				(block $c (result i32)
					(try_table (result i32) (catch $e $c)
						i32.const 123
					)
				)
			)
		)
	]],
		"exceptions"
	)

	Test:add("try_table catches thrown exception with payload", function()
		Test:assert_equals(inst.exports["test_try_catch"](55), 55)
	end)
	Test:add("try_table produces normal result when no throw", function()
		Test:assert_equals(inst.exports["test_try_nocatch"](), 123)
	end)
end)

--------------------------------------------------------------------------------
-- SIMD v128 Operations
--------------------------------------------------------------------------------

Test:describe("Runtime > SIMD v128", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(memory 1)
			(func (export "splat_and_add") (param i32 i32) (result i32)
				local.get 0
				i32x4.splat
				local.get 1
				i32x4.splat
				i32x4.add
				i32x4.extract_lane 0
			)
			(func (export "simd_mem") (param i32) (result i32)
				i32.const 0
				local.get 0
				i32x4.splat
				v128.store
				i32.const 0
				v128.load
				i32x4.extract_lane 3
			)
		)
	]],
		"simd_v128"
	)

	Test:add("i32x4 splat, add and extract_lane", function()
		Test:assert_equals(inst.exports["splat_and_add"](10, 25), 35)
	end)
	Test:add("v128 store and load from memory", function()
		Test:assert_equals(inst.exports["simd_mem"](12345), 12345)
	end)
end)

--------------------------------------------------------------------------------
-- Atomics (Single-threaded)
--------------------------------------------------------------------------------

Test:describe("Runtime > atomics", function()
	local inst = compile_and_instantiate(
		[[
		(module
			(memory 1 1 shared)
			(func (export "atomic_add") (param i32 i32) (result i32)
				i32.const 0
				local.get 0
				i32.atomic.store
				i32.const 0
				local.get 1
				i32.atomic.rmw.add
				drop
				i32.const 0
				i32.atomic.load
			)
		)
	]],
		"atomics"
	)

	Test:add("atomic store, rmw.add, and load", function()
		Test:assert_equals(inst.exports["atomic_add"](100, 25), 125)
	end)
end)

--------------------------------------------------------------------------------
-- Module Run API
--------------------------------------------------------------------------------

Test:describe("Runtime > module run api", function()
	local lwasm = require("lwasm")

	Test:add("lwasm.run by path", function()
		local res = lwasm.run("build/function.wasm", "param-first-i32", 42, 99)
		Test:assert_equals(res, 42)
	end)
	Test:add("mod:run method", function()
		local mod = lwasm.decode_file("build/function.wasm")
		local res = mod:run("value-i32")
		Test:assert_equals(res, 77)
	end)
end)

Test:run()
