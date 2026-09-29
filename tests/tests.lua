local Test = {}

Test.cases = {}
Test.setup = nil
Test.teardown = nil

function Test:add(name, func)
	table.insert(self.cases, { name = name, func = func })
end

function Test:set_setup(func)
	self.setup = func
end

function Test:set_teardown(func)
	self.teardown = func
end

function Test:run()
	local passed = 0
	local failed = 0
	local total_start = os.clock()

	for _, case in ipairs(self.cases) do
		if self.setup then
			self.setup()
		end
		local start_time = os.clock()
		local success, message = pcall(case.func)
		local end_time = os.clock()
		if self.teardown then
			self.teardown()
		end

		if success then
			passed = passed + 1
			print(
				string.format(
					"\x1b[32m✓\x1b[0m %s \x1b[90m[%.2fms]\x1b[0m",
					case.name,
					(end_time - start_time) * 1000
				)
			)
		else
			failed = failed + 1
			print(string.format("✗ %s - %s", case.name, message))
		end
	end
	local total_end = os.clock()

	print(
		string.format(
			"\n\x1b[32m%d pass\x1b[0m\n"
				.. (failed == 0 and "\x1b[90m" or "\x1b[31m")
				.. "%d fail\x1b[0m\n%d total \x1b[90m[%.2fms]\x1b[0m",
			passed,
			failed,
			#self.cases,
			(total_end - total_start) * 1000
		)
	)
	if failed > 0 then
		os.exit(1)
	end
end

function Test:describe(group_name, group_func)
	local previous_setup = self.setup
	local previous_teardown = self.teardown
	local previous_cases = self.cases

	self.cases = {}
	self.setup = nil
	self.teardown = nil

	group_func()

	local group_cases = self.cases
	self.cases = previous_cases
	self.setup = previous_setup
	self.teardown = previous_teardown

	for _, case in ipairs(group_cases) do
		table.insert(self.cases, { name = group_name .. " \x1b[90m>\x1b[0m " .. case.name, func = case.func })
	end
end

function Test:assert_equals(actual, expected)
	if actual ~= expected then
		error(string.format("Assertion failed: expected '%s', got '%s'", tostring(expected), tostring(actual)))
	end
end

function Test:assert_not_equals(actual, expected)
	if actual == expected then
		error(string.format("Assertion failed: expected different from '%s'", tostring(expected)))
	end
end

function Test:assert_true(value)
	if not value then
		error("Assertion failed: expected true, got false")
	end
end

function Test:assert_false(value)
	if value then
		error("Assertion failed: expected false, got true")
	end
end

function Test:assert_nil(value)
	if value ~= nil then
		error(string.format("Assertion failed: expected nil, got '%s'", tostring(value)))
	end
end

function Test:assert_not_nil(value)
	if value == nil then
		error("Assertion failed: expected not nil, got nil")
	end
end

function Test:todo(func)
	local success = pcall(func)
	if success then
		error("Assertion failed: expected error, got success, please add tests")
	end
end

return Test
