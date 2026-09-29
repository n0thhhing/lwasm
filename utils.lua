local utils = {}

function utils.enum(tbl)
	local result = {}
	local last_value = 0

	for _, v in ipairs(tbl) do
		local name, value = v:match("^(%S+)%s*=%s*(%d+)$") -- Match decimal numbers
		if not name then
			name, value = v:match("^(%S+)%s*=%s*(0x%x+)$") -- Match hexadecimal numbers
		end
		if name and value then
			value = tonumber(value) or last_value
			result[name] = value
			last_value = value
		else
			name = v
			last_value = last_value + 1
			result[name] = last_value
		end
	end
	utils.set_global(result)
	return result
end

function utils.set_global(enum)
	local env = _ENV or _G
	for name, value in pairs(enum) do
		env[name] = value
	end
end

-- @see https://stackoverflow.com/questions/9168058/how-to-dump-a-table-to-console
function utils.pprint(node)
	local cache, stack, output = {}, {}, {}
	local depth = 1
	local output_str = "{\n"

	while true do
		local size = 0
		for _, _ in pairs(node) do
			size = size + 1
		end

		local cur_index = 1
		for k, v in pairs(node) do
			if (cache[node] == nil) or (cur_index >= cache[node]) then
				if string.find(output_str, "}", output_str:len()) then
					output_str = output_str .. ",\n"
				elseif not (string.find(output_str, "\n", output_str:len())) then
					output_str = output_str .. "\n"
				end

				-- This is necessary for working with HUGE tables otherwise we run out of memory using concat on huge strings
				table.insert(output, output_str)
				output_str = ""

				local key
				if type(k) == "number" or type(k) == "boolean" then
					key = "[" .. tostring(k) .. "]"
				else
					key = "['" .. tostring(k) .. "']"
				end

				if type(v) == "number" or type(v) == "boolean" then
					output_str = output_str .. string.rep("\t", depth) .. key .. " = " .. tostring(v)
				elseif type(v) == "table" then
					output_str = output_str .. string.rep("\t", depth) .. key .. " = {\n"
					table.insert(stack, node)
					table.insert(stack, v)
					cache[node] = cur_index + 1
					break
				else
					output_str = output_str .. string.rep("\t", depth) .. key .. " = '" .. tostring(v) .. "'"
				end

				if cur_index == size then
					output_str = output_str .. "\n" .. string.rep("\t", depth - 1) .. "}"
				else
					output_str = output_str .. ","
				end
			else
				-- close the table
				if cur_index == size then
					output_str = output_str .. "\n" .. string.rep("\t", depth - 1) .. "}"
				end
			end

			cur_index = cur_index + 1
		end

		if size == 0 then
			output_str = output_str .. "\n" .. string.rep("\t", depth - 1) .. "}"
		end

		if #stack > 0 then
			node = stack[#stack]
			stack[#stack] = nil
			depth = cache[node] == nil and depth + 1 or depth - 1
		else
			break
		end
	end

	table.insert(output, output_str)
	output_str = table.concat(output)

	print(output_str)
end

function utils.reverse(tab)
	for i = 1, #tab // 2, 1 do
		tab[i], tab[#tab - i + 1] = tab[#tab - i + 1], tab[i]
	end
	return tab
end

function utils.read_file_bytes(filename)
	local file = assert(io.open(filename, "rb"))
	local content = file:read("*a")
	file:close()
	return content
end

function utils.merge(table1, table2)
	local result = {}
	for _, v in ipairs(table1) do
		table.insert(result, v)
	end
	for _, v in ipairs(table2) do
		table.insert(result, v)
	end
	return result
end

function utils.tablelength(tbl)
	local count = 0
	for _ in pairs(tbl) do
		count = count + 1
	end
	return count
end

return utils
