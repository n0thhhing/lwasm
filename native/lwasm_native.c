#include <stdint.h>
#include <stdio.h>
#include <lua.h>
#include <lauxlib.h>

typedef struct {
    lua_State *L;
    const unsigned char *data;
    size_t length;
    size_t cursor;
} Reader;

static int fail_invalid(lua_State *L, const char *kind, size_t offset, const char *reason) {
    char message[192];
    snprintf(message, sizeof(message), "Invalid %s at offset 0x%zX: %s", kind, offset + 1, reason);
    return luaL_error(L, "%s", message);
}

static Reader check_reader(lua_State *L) {
    Reader reader;
    reader.L = L;
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_getfield(L, 1, "data");
    reader.data = (const unsigned char *)luaL_checklstring(L, -1, &reader.length);
    lua_getfield(L, 1, "cursor");
    lua_Integer cursor = luaL_checkinteger(L, -1);
    if (cursor < 1) {
        luaL_error(L, "invalid binary reader cursor");
    }
    reader.cursor = (size_t)cursor - 1;
    return reader;
}

static void update_cursor(Reader *reader) {
    lua_pushinteger(reader->L, (lua_Integer)reader->cursor + 1);
    lua_setfield(reader->L, 1, "cursor");
}

static uint64_t read_leb(Reader *reader, const char *kind, unsigned max_bytes,
                         unsigned char *last, unsigned *count, size_t *offset) {
    uint64_t result = 0;
    *offset = reader->cursor;
    for (unsigned i = 0; i < max_bytes; ++i) {
        if (reader->cursor >= reader->length) {
            char message[128];
            snprintf(message, sizeof(message), "Unexpected EOF while reading %s at offset 0x%zX",
                     kind, reader->cursor + 1);
            luaL_error(reader->L, "%s", message);
        }
        unsigned char byte = reader->data[reader->cursor++];
        result |= (uint64_t)(byte & 0x7f) << (i * 7);
        if ((byte & 0x80) == 0) {
            *last = byte;
            *count = i + 1;
            update_cursor(reader);
            return result;
        }
    }
    char reason[64];
    snprintf(reason, sizeof(reason), "encoding exceeds %u bytes", max_bytes);
    fail_invalid(reader->L, kind, *offset, reason);
    return 0;
}

static int read_u32(lua_State *L) {
    Reader reader = check_reader(L);
    unsigned char last;
    unsigned count;
    size_t offset;
    uint64_t result = read_leb(&reader, "u32LEB", 5, &last, &count, &offset);
    if (count == 5 && (last & 0x7f) > 0x0f) {
        return fail_invalid(L, "u32LEB", offset, "unused high bits must be zero");
    }
    lua_pushinteger(L, (lua_Integer)(uint32_t)result);
    return 1;
}

static int read_i32(lua_State *L) {
    Reader reader = check_reader(L);
    unsigned char last;
    unsigned count;
    size_t offset;
    uint64_t result = read_leb(&reader, "i32LEB", 5, &last, &count, &offset);
    unsigned payload = last & 0x7f;
    if (count == 5 && payload > 0x07 && payload < 0x78) {
        return fail_invalid(L, "i32LEB", offset, "unused high bits do not match the sign bit");
    }
    if (count < 5 && (last & 0x40)) {
        result |= UINT64_MAX << (count * 7);
    }
    lua_pushinteger(L, (lua_Integer)(int32_t)(uint32_t)result);
    return 1;
}

static int read_u64(lua_State *L) {
    Reader reader = check_reader(L);
    unsigned char last;
    unsigned count;
    size_t offset;
    uint64_t result = read_leb(&reader, "u64LEB", 10, &last, &count, &offset);
    if (count == 10 && (last & 0x7f) > 0x01) {
        return fail_invalid(L, "u64LEB", offset, "unused high bits must be zero");
    }
    lua_pushinteger(L, (lua_Integer)result);
    return 1;
}

static int read_i64(lua_State *L) {
    Reader reader = check_reader(L);
    unsigned char last;
    unsigned count;
    size_t offset;
    uint64_t result = read_leb(&reader, "i64LEB", 10, &last, &count, &offset);
    unsigned payload = last & 0x7f;
    if (count == 10 && payload != 0x00 && payload != 0x7f) {
        return fail_invalid(L, "i64LEB", offset, "unused high bits do not match the sign bit");
    }
    if (count < 10 && (last & 0x40)) {
        result |= UINT64_MAX << (count * 7);
    }
    lua_pushinteger(L, (lua_Integer)result);
    return 1;
}

static const luaL_Reg functions[] = {
    {"read_u32_leb", read_u32},
    {"read_i32_leb", read_i32},
    {"read_u64_leb", read_u64},
    {"read_i64_leb", read_i64},
    {NULL, NULL}
};

int luaopen_lwasm_native(lua_State *L) {
    luaL_newlib(L, functions);
    lua_pushliteral(L, "lwasm native 1.0.0");
    lua_setfield(L, -2, "_VERSION");
    return 1;
}
