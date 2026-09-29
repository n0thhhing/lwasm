--- Unified Test Runner for lwasm
-- Executes all test suites across the project

local function run_suite(path)
	print("\n========================================================")
	print("Running Suite: " .. path)
	print("========================================================")
	local status = os.execute("lua " .. path)
	if status ~= true and status ~= 0 then
		error("Test suite failed: " .. path, 2)
	end
end

run_suite("tests/decode_test.lua")
run_suite("tests/binary_test.lua")
run_suite("tests/api_test.lua")
run_suite("tests/disasm_test.lua")
run_suite("tests/sqlite3_compare_test.lua")
run_suite("tests/spec_test.lua")
run_suite("tests/runtime_test.lua")
run_suite("tests/struct_test.lua")

print("\n\x1b[32m✔ All test suites passed successfully!\x1b[0m\n")
