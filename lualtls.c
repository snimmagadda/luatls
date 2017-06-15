/*
 * Copyright (c) 2016 Sunil Nimmagadda <sunil@nimmagadda.net>
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

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define	TLS_CONTEXTHANDLE	"TLS context"

static int
l_config_new(lua_State *L)
{
	struct tls_config	*config;
	uint32_t		 protocols;

	if ((config = tls_config_new()) == NULL)
		return luaL_error(L, "config_new: config creation failed");

	if (lua_istable(L, 1) == 0)
		goto end;

	if (lua_getfield(L, 1, "ciphers") == LUA_TSTRING &&
	    tls_config_set_ciphers(config, lua_tostring(L, -1)))
		return luaL_error(L, tls_config_error(config));

	if (lua_getfield(L, 1, "verify") == LUA_TBOOLEAN &&
	    lua_toboolean(L, -1) == 0) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	if (lua_getfield(L, 1, "muststaple") == LUA_TBOOLEAN &&
	    lua_toboolean(L, -1) == 1)
		tls_config_ocsp_require_stapling(config);

	if (lua_getfield(L, 1, "cert") == LUA_TSTRING &&
	    tls_config_set_cert_file(config, lua_tostring(L, -1)))
		return luaL_error(L, tls_config_error(config));

	if (lua_getfield(L, 1, "key") == LUA_TSTRING &&
	    tls_config_set_key_file(config, lua_tostring(L, -1)))
		return luaL_error(L, tls_config_error(config));

	if (lua_getfield(L, 1, "ca") == LUA_TSTRING &&
	    tls_config_set_ca_file(config, lua_tostring(L, -1)))
		return luaL_error(L, tls_config_error(config));

	if (lua_getfield(L, 1, "depth") == LUA_TNUMBER)
	    tls_config_set_verify_depth(config, lua_tointeger(L, -1));

	if (lua_getfield(L, 1, "protocols") == LUA_TSTRING) {
		if (tls_config_parse_protocols(&protocols, lua_tostring(L, -1)))
			return luaL_error(L, "config_new: invalid protocols");

		tls_config_set_protocols(config, protocols);
	}
 end:
	lua_pushlightuserdata(L, config);
	return 1;
}

static int
l_connect(lua_State *L)
{
	struct tls		**ctx;
	struct tls_config	 *config;
	const char		 *host, *port;

	host = luaL_checkstring(L, 1);
	port = luaL_checkstring(L, 2);
	if (lua_islightuserdata(L, 3) == 0)
		return luaL_error(L, "connect: arg #3 config expected");

	config = lua_touserdata(L, 3);
	ctx = lua_newuserdata(L, sizeof *ctx);
	luaL_getmetatable(L, TLS_CONTEXTHANDLE);
	lua_setmetatable(L, -2);
	if ((*ctx = tls_client()) == NULL)
		return luaL_error(L, "connect: context creation failed");

	if (tls_configure(*ctx, config) != 0)
		return luaL_error(L, tls_error(*ctx));

	if (tls_connect(*ctx, host, port) != 0)
		return luaL_error(L, tls_error(*ctx));

	return 1;
}

static int
l_server(lua_State *L)
{
	struct tls		*tls;
	struct tls_config	*config;

	if ((tls = tls_server()) == NULL)
		return luaL_error(L, "server: context creation failed");

	if (lua_islightuserdata(L, 1) == 0)
		return luaL_error(L, "server: arg #1 config expected");

	config = lua_touserdata(L, 1);
	if (tls_configure(tls, config) != 0)
		return luaL_error(L, tls_error(tls));

	lua_pushlightuserdata(L, tls);
	return 1;
}

static int
l_accept(lua_State *L)
{
	struct tls		**ctx, *tls;
	struct tls_config	 *config;
	int			 s;

	s = luaL_checkinteger(L, 1);
	if (lua_islightuserdata(L, 2) == 0)
		return luaL_error(L, "accept: arg #2 server context expected");

	tls = lua_touserdata(L, 2);
	if (lua_islightuserdata(L, 3) == 0)
		return luaL_error(L, "accept: arg #3 config expected");

	config = lua_touserdata(L, 3);
	ctx = lua_newuserdata(L, sizeof *ctx);
	luaL_getmetatable(L, TLS_CONTEXTHANDLE);
	lua_setmetatable(L, -2);

	if (tls_accept_socket(tls, ctx, s) != 0)
		return luaL_error(L, tls_error(tls));

	return 1;
}

static int
l_read(lua_State *L)
{
	struct tls	**ctx;
	luaL_Buffer	  b;
	char		 *p;
	size_t		  bufsz;
	int		  r;

	ctx = luaL_checkudata(L, 1, TLS_CONTEXTHANDLE);
	bufsz = luaL_checkinteger(L, 2);
	p = luaL_buffinitsize(L, &b, bufsz);
	r = tls_read(*ctx, p, bufsz);
	if (r == -1) {
		lua_pushnil(L);
		lua_pushinteger(L, r);
		lua_pushstring(L, tls_error(*ctx));
		return 3;
	}

	if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
		luaL_addsize(&b, 0);
	else
		luaL_addsize(&b, r);

	luaL_pushresult(&b);
	lua_pushinteger(L, r);
	return 2;
}

static int
l_write(lua_State *L)
{
	struct tls	**ctx;
	const char	 *b;
	size_t		  len;
	int		  r;

	ctx = luaL_checkudata(L, 1, TLS_CONTEXTHANDLE);
	b = luaL_checklstring(L, 2, &len);
	r = tls_write(*ctx, b, len);
	lua_pushinteger(L, r);
	if (r == -1) {
		lua_pushstring(L, tls_error(*ctx));
		return 2;
	}

	return 1;
}

static int
l_close(lua_State *L)
{
	struct tls	**ctx;
	int		  r;

	ctx = luaL_checkudata(L, 1, TLS_CONTEXTHANDLE);
	r = tls_close(*ctx);
	lua_pushinteger(L, r);
	if (r == -1) {
		lua_pushstring(L, tls_error(*ctx));
		return 2;
	}

	return 1;
}

static int
l_context_gc(lua_State *L)
{
	struct tls	**ctx;

	ctx = luaL_checkudata(L, 1, TLS_CONTEXTHANDLE);
	tls_free(*ctx);
	return 0;
}

int
luaopen_ltls(lua_State *L)
{
	struct luaL_Reg ltls[] = {
		{"config_new", l_config_new},
		{"connect", l_connect},
		{"server", l_server},
		{"accept", l_accept},
		{NULL, NULL}
	};
	struct luaL_Reg context_methods[] = {
		{"read", l_read},
		{"write", l_write},
		{"close", l_close},
		{"__gc", l_context_gc},
		{NULL, NULL}
	};
	struct {
		const char	*name;
		int		 value;
	} ltls_constants[] = {
		{"WANT_POLLIN", TLS_WANT_POLLIN},
		{"WANT_POLLOUT", TLS_WANT_POLLOUT},
		{NULL, 0}
	};
	int i;

	if (tls_init() != 0)
		return luaL_error(L, "ltls: library initialization failed");

	luaL_newlib(L, ltls);
	luaL_newmetatable(L, TLS_CONTEXTHANDLE);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, context_methods, 0);
	lua_pop(L, 1);

	for (i = 0; ltls_constants[i].name != NULL; i++) {
		lua_pushinteger(L, ltls_constants[i].value);
		lua_setfield(L, -2, ltls_constants[i].name);
	}

	return 1;
}
