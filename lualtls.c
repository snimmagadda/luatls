/*
 * Copyright (c) 2016 Sunil Nimmagadda <sunil@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <tls.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static int
l_config_new(lua_State *l)
{
	struct tls_config *config;

	if ((config = tls_config_new()) == NULL)
		return luaL_error(l, "ltls:  failed to create a config");

	lua_pushlightuserdata(l, config);
	return 1;
}

static int
l_client(lua_State *l)
{
	struct tls *ctx;

	if ((ctx = tls_client()) == NULL)
		return luaL_error(l, "ltls: failed to create client context");

	lua_pushlightuserdata(l, ctx);
	return 1;
}

static int
l_configure(lua_State *l)
{
	struct tls_config	*config;
	struct tls		*ctx;

	luaL_checktype(l, 1, LUA_TLIGHTUSERDATA);
	luaL_checktype(l, 2, LUA_TLIGHTUSERDATA);

	if ((config = lua_touserdata(l, 1)) == NULL) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, "Invalid config");
		return 2;
	}

	if ((ctx = lua_touserdata(l, 2)) == NULL)
		return luaL_error(l, "ltls: Invalid context");

	if (tls_configure(ctx, config) != 0) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, tls_error(ctx));
		return 2;

	} else {
		lua_pushboolean(l, 1);
		return  1;
	}
}

static int
l_connect(lua_State *l)
{
	struct tls	*ctx;
	const char	*host, *port;

	luaL_checktype(l, 1, LUA_TLIGHTUSERDATA);
	if ((ctx = lua_touserdata(l, 1)) == NULL) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, "Invalid context");
		return 2;
	}

	host = luaL_checkstring(l, 2);
	port = luaL_checkstring(l, 3);

	if (tls_connect(ctx, host, port) != 0) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, tls_error(ctx));
		return 2;
	} else {
		lua_pushboolean(l, 1);
		return 1;
	}
}

static int
l_close(lua_State *l)
{
	struct tls *ctx;

	luaL_checktype(l, 1, LUA_TLIGHTUSERDATA);
	if ((ctx = lua_touserdata(l, 1)) == NULL) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, "Invalid context");
		return 2;
	}

	if (tls_close(ctx) != 0) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, tls_error(ctx));
		return 2;
	} else {
		lua_pushboolean(l, 1);
		return 1;
	}
}

static int
l_free(lua_State *l)
{
	struct tls *ctx;

	luaL_checktype(l, 1, LUA_TLIGHTUSERDATA);
	if ((ctx = lua_touserdata(l, 1)) == NULL) {
		lua_pushboolean(l, 0);
		lua_pushstring(l, "Invalid context");
		return 2;
	}

	tls_free(ctx);
	return 0;
}

int
luaopen_ltls(lua_State *l)
{
	struct luaL_Reg ltls[] = {
		{"config_new", l_config_new},
		{"client", l_client},
		{"configure", l_configure},
		{"connect", l_connect},
		{"close", l_close},
		{"free", l_free},
		{NULL, NULL}
	};

	if (tls_init() != 0)
		return luaL_error(l, "ltls: failed to initialize library");

	luaL_newlib(l, ltls);
	return 1;
}
