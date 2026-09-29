--- lwasm - WebAssembly Binary Decoder, Disassembler, and Inspection Toolkit for Lua
--- Conforms to the WebAssembly 2.0 Specification (W3C Recommendation / CRD)
---@diagnostic disable: undefined-global

local Binary = require("binary")
local utils = require("utils")
local opcodes = require("opcodes")
local decoder = require("decoder")
local disassembler = require("disassembler")
local dumper = require("dumper")
local runtime = require("runtime")
local Struct = require("struct")
local lwasm = {
	_VERSION = "lwasm 2.0.0",
	_DESCRIPTION = "WebAssembly 2.0 Binary Toolkit for Lua",

	-- Sub-modules and utilities
	Binary = Binary,
	binary = Binary,
	utils = utils,
	opcodes = opcodes,
	decoder = decoder,
	disassembler = disassembler,
	dissasembler = disassembler, -- backward-compatible spelling alias
	dumper = dumper,
	runtime = runtime,
	Runtime = runtime,
	Struct = Struct,
	struct = Struct.new,
	Module = decoder.Module,
	native_enabled = Binary.native_enabled,
	backend = Binary.native_enabled and "native" or "lua",
}

--- Decode raw binary WebAssembly bytecode string into a structured Module object.
--- @param bytes string Raw .wasm binary data.
--- @return table Module object with section queries and convenience methods.
function lwasm.decode(bytes, options)
	return decoder.decode(bytes, options)
end

lwasm.from_bytes = lwasm.decode

--- Read and decode a WebAssembly .wasm file from disk into a Module object.
--- @param filepath string Path to .wasm file.
--- @return table Module object.
function lwasm.decode_file(filepath, options)
	return decoder.decode_file(filepath, options)
end

--- Disassemble a raw bytecode string into an array of structured Instruction objects.
--- @param code string Raw instruction bytes.
--- @param base_offset integer|nil Base PC offset for instruction addresses (default: 0).
--- @return table Array of Instruction objects.
function lwasm.disasm(code, base_offset)
	return disassembler.disasm(code, base_offset)
end

--- Disassemble raw instruction bytes into a formatted WebAssembly Text (WAT) snippet.
--- @param code string Raw instruction bytes.
--- @param indent integer|nil Initial indentation level (default: 0).
--- @return string Formatted WAT string.
function lwasm.disasm_to_string(code, indent)
	return disassembler.disasm_to_string(code, indent)
end

--- Disassemble a single function code entry table (from code_section.code[i]).
--- @param code_entry table Function entry with .code, .locals, .code_start, .size.
--- @return table Array of Instruction objects.
function lwasm.disasm_function(code_entry)
	return disassembler.disasm_function(code_entry)
end

--- Decompile an entire WebAssembly module object or file into complete WAT text.
--- @param mod_or_path table|string Module object or path to .wasm file.
--- @return string Formatted WebAssembly Text (WAT) representation.
function lwasm.disasm_module(mod_or_path)
	return disassembler.disasm_module(mod_or_path)
end

--- Convenience alias for disasm_module(): decompile module or file into WAT text.
--- @param mod_or_path table|string Module object or path to .wasm file.
--- @return string Formatted WebAssembly Text (WAT) representation.
lwasm.to_wat = lwasm.disasm_module

--- Produce an objdump-style disassembly dump of all functions in a module.
--- @param mod_or_path table|string Module object or path to .wasm file.
--- @return string Hex-annotated disassembly dump.
function lwasm.disasm_dump(mod_or_path)
	return disassembler.dump(mod_or_path)
end

--- Produce a comprehensive, detailed binary dump of a .wasm file or Module object.
--- Formats file headers, section table, detailed contents of every section,
--- data segment hex dumps, and function disassembly.
--- @param mod_or_path table|string Module object or path to .wasm file.
--- @param options table|nil Optional formatting flags:
---   - headers_only (boolean): print only file summary and section headers table
---   - disasm_only (boolean): print only function disassembly
---   - no_disasm (boolean): print section contents without function disassembly
---   - raw_data (boolean): include full raw hexdumps of data and custom payloads
--- @return string Formatted comprehensive dump text.
function lwasm.dump(mod_or_path, options)
	return dumper.dump(mod_or_path, options)
end

--- Format binary bytes into a standard 16-bytes-per-line hex + ASCII dump.
--- @param data string Raw byte data.
--- @param max_bytes integer|nil Maximum bytes to dump (defaults to 256).
--- @param indent string|nil Indentation prefix (defaults to "    ").
--- @return string Formatted hex + ASCII string.
function lwasm.format_hexdump(data, max_bytes, indent)
	return dumper.format_hexdump(data, max_bytes, indent)
end

-- Augment Module metatable with convenience methods for object-oriented usage:
--   mod:to_wat()
--   mod:dump(options)
--   mod:disassemble()
if decoder.Module then
	function decoder.Module:to_wat()
		return disassembler.disasm_module(self)
	end

	function decoder.Module:dump(options)
		return dumper.dump(self, options)
	end

	function decoder.Module:disassemble()
		return disassembler.dump(self)
	end

	function decoder.Module:instantiate(import_object)
		return runtime.instantiate(self, import_object)
	end

	function decoder.Module:run(func_name, ...)
		return lwasm.run(self, func_name, ...)
	end
end

--- Instantiate a WebAssembly module with imports.
--- @param mod_or_path table|string Decoded module or path to .wasm file.
--- @param import_object table|nil Optional host import object.
--- @return table Instance
function lwasm.instantiate(mod_or_path, import_object)
	return runtime.instantiate(mod_or_path, import_object)
end

--- Instantiate and execute an exported function from a WebAssembly module.
--- @param mod_or_path table|string Decoded module or path to .wasm file.
--- @param func_name string|nil Name of exported function (defaults to "_start", "main", or first exported func).
--- @param ... any Arguments to pass to the function.
--- @return any Result(s) of the function call.
function lwasm.run(mod_or_path, func_name, ...)
	local instance = runtime.instantiate(mod_or_path)
	if not func_name then
		func_name = instance.exports["_start"] and "_start" or (instance.exports["main"] and "main" or nil)
		if not func_name then
			for k, v in pairs(instance.exports) do
				if type(v) == "function" then
					func_name = k
					break
				end
			end
		end
	end
	if not func_name or not instance.exports[func_name] then
		error("No callable export found in module" .. (func_name and (": " .. func_name) or ""))
	end
	return instance.exports[func_name](...)
end

require("api").install(lwasm, decoder.Module, {
	Binary = Binary,
	decoder = decoder,
	disassembler = disassembler,
	opcodes = opcodes,
})

-- Make the module table callable directly:
--   local mod = lwasm("file.wasm")
--   local mod = lwasm(raw_bytes)
setmetatable(lwasm, {
	__call = function(_, input, ...)
		if type(input) == "string" then
			if input:sub(1, 4) == "\0asm" then
				return lwasm.decode(input, ...)
			else
				return lwasm.decode_file(input, ...)
			end
		end
		error("lwasm(...) expects a file path string or raw binary wasm string, got " .. type(input), 2)
	end,
})

-- CLI execution support: `lua lwasm.lua <file.wasm> [command/options]`
if arg and arg[0] and (arg[0]:match("lwasm%.lua$") or arg[0] == "lwasm.lua") then
	if #arg == 0 or (arg[1] == "--help" or arg[1] == "-h") and not arg[2] then
		print("lwasm v2.0.0 - WebAssembly 2.0 Toolkit for Lua")
		print("Usage: lua lwasm.lua <file.wasm> [options]")
		print("   or: lua lwasm.lua <command> <file.wasm> [args...]")
		print("\nCommands / Options:")
		print("  run, --run, -x         Execute exported function from module")
		print("  dump, --dump, -d       Generate full binary dump (default)")
		print("  wat, --wat, -w         Decompile module to WAT assembly")
		print("  disasm, --disasm       Print disassembly of all code sections")
		print("  headers, --headers, -H Print only section headers table")
		print("  --help, -h             Display this help message")
		os.exit(0)
	end

	local file = nil
	local mode = "dump"
	local opts = {}
	local extra_args = {}

	for _, a in ipairs(arg) do
		if a == "run" or a == "--run" then
			mode = "run"
		elseif a == "wat" or a == "--wat" or a == "-w" then
			mode = "wat"
		elseif a == "disasm" or a == "--disasm" then
			mode = "disasm"
		elseif a == "headers" or a == "--headers" or a == "-H" then
			mode = "headers"
			opts.headers_only = true
		elseif a == "dump" or a == "--dump" or a == "-d" then
			mode = "dump"
		elseif a == "--raw" or a == "-r" then
			opts.raw_data = true
		elseif a == "--no-disasm" then
			opts.no_disasm = true
		elseif not file and (a:match("%.wasm$") or not a:match("^-")) then
			file = a
		else
			extra_args[#extra_args + 1] = tonumber(a) or a
		end
	end

	if not file then
		io.stderr:write("Error: No .wasm file specified.\n")
		os.exit(1)
	end

	if mode == "run" then
		local func_name = nil
		local call_args = {}
		if #extra_args > 0 and type(extra_args[1]) == "string" and not tonumber(extra_args[1]) then
			func_name = table.remove(extra_args, 1)
		end
		call_args = extra_args
		local results = { lwasm.run(file, func_name, table.unpack(call_args)) }
		if #results > 0 then
			print(table.concat(results, " "))
		end
	elseif mode == "wat" then
		print(lwasm.to_wat(file))
	elseif mode == "disasm" then
		print(lwasm.disasm_dump(file))
	elseif mode == "headers" then
		print(lwasm.dump(file, opts))
	else
		print(lwasm.dump(file, opts))
	end
end

return lwasm
