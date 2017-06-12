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

#define TLS_CONFIGHANDLE	"TLS config"
#define	TLS_CONTEXTHANDLE	"TLS context"

static int
l_config_new(lua_State *l)
{
	struct tls_config	**config;
	uint32_t		  protocols;

	config = lua_newuserdata(l, sizeof *config);
	luaL_getmetatable(l, TLS_CONFIGHANDLE);
	lua_setmetatable(l, -2);
	if ((*config = tls_config_new()) == NULL)
		return luaL_error(l, "ltls: failed to create a config");

	/* do nothing when no params are passed as a table argument */
	if (lua_istable(l, 1) == 0)
		return 1;

	if (lua_getfield(l, 1, "ciphers") == LUA_TSTRING &&
	    tls_config_set_ciphers(*config, lua_tostring(l, -1)))
		return luaL_error(l, "ltls: failed to set ciphers");

	lua_pop(l, 1);

	if (lua_getfield(l, 1, "verify") == LUA_TBOOLEAN &&
	    lua_toboolean(l, -1) == 0) {
		tls_config_insecure_noverifycert(*config);
		tls_config_insecure_noverifyname(*config);
	}
	lua_pop(l, 1);

	if (lua_getfield(l, 1, "muststaple") == LUA_TBOOLEAN &&
	    lua_toboolean(l, -1) == 1)
		tls_config_ocsp_require_stapling(*config);

	lua_pop(l, 1);

	if (lua_getfield(l, 1, "cert") == LUA_TSTRING &&
	    tls_config_set_cert_file(*config, lua_tostring(l, -1)))
		return luaL_error(l, "ltls: failed to set cert file");

	lua_pop(l, 1);

	if (lua_getfield(l, 1, "key") == LUA_TSTRING &&
	    tls_config_set_key_file(*config, lua_tostring(l, -1)))
		return luaL_error(l, "ltls: failed to set key file");

	lua_pop(l, 1);

	if (lua_getfield(l, 1, "ca") == LUA_TSTRING &&
	    tls_config_set_ca_file(*config, lua_tostring(l, -1)))
		return luaL_error(l, "ltls: failed to set ca file");

	lua_pop(l, 1);

	if (lua_getfield(l, 1, "depth") == LUA_TNUMBER)
	    tls_config_set_verify_depth(*config, lua_tointeger(l, -1));

	lua_pop(l, 1);

	if (lua_getfield(l, 1, "protocols") == LUA_TSTRING) {
		if (tls_config_parse_protocols(&protocols, lua_tostring(l, -1)))
			return luaL_error(l, "ltls: failed to parse protocols");

		tls_config_set_protocols(*config, protocols);
	}

	lua_pop(l, 1);
	return 1;
}

static int
l_connect(lua_State *l)
{
	struct tls_config	 *config;
	struct tls		**ctx;
	const char		 *host, *port;

	host = luaL_checkstring(l, 1);
	port = luaL_checkstring(l, 2);
	config = luaL_checkudata(l, 3, TLS_CONFIGHANDLE);
	ctx = lua_newuserdata(l, sizeof *ctx);
	luaL_getmetatable(l, TLS_CONTEXTHANDLE);
	lua_setmetatable(l, -2);
	if ((*ctx = tls_client()) == NULL)
		return luaL_error(l, "ltls: failed to create client context");

	if (tls_configure(*ctx, config) != 0)
		return luaL_error(l, tls_error(*ctx));

	if (tls_connect(*ctx, host, port) != 0)
		return luaL_error(l, tls_error(*ctx));

	return 1;
}

static int
l_accept(lua_State *l)
{
	struct tls_config	*config;
	struct tls		*tls, **ctx;
	int			 s;

	s = luaL_checkinteger(l, 1);
	config = luaL_checkudata(l, 2, TLS_CONFIGHANDLE);
	if ((tls = tls_server()) == NULL)
		return luaL_error(l, "ltls: failed to created server context");

	if (tls_configure(tls, config) != 0)
		return luaL_error(l, tls_error(tls));

	ctx = lua_newuserdata(l, sizeof *ctx);
	luaL_getmetatable(l, TLS_CONTEXTHANDLE);
	lua_setmetatable(l, -2);

	if (tls_accept_socket(tls, ctx, s) != 0)
		return luaL_error(l, tls_error(tls));

	return 1;
}

static int
l_read(lua_State *l)
{
	struct tls	*ctx, **pctx;
	luaL_Buffer	 b;
	char		*p;
	size_t		 bufsz;
	int		 r;

	pctx = luaL_checkudata(l, 1, TLS_CONTEXTHANDLE);
	ctx = *pctx;
	bufsz = luaL_checkinteger(l, 2);
	p = luaL_buffinitsize(l, &b, bufsz);
	r = tls_read(ctx, p, bufsz);
	if (r == -1) {
		lua_pushnil(l);
		lua_pushstring(l, tls_error(ctx));
		return 2;
	}

	if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
		luaL_addsize(&b, 0);
	else
		luaL_addsize(&b, r);

	luaL_pushresult(&b);
	lua_pushinteger(l, r);
	return 2;
}

static int
l_write(lua_State *l)
{
	struct tls	*ctx, **pctx;
	const char	*b;
	size_t		 len;
	int		 r;

	pctx = luaL_checkudata(l, 1, TLS_CONTEXTHANDLE);
	ctx = *pctx;
	b = luaL_checklstring(l, 2, &len);
	lua_pop(l, 1);
	r = tls_write(ctx, b, len);
	if (r == -1)
		lua_pushstring(l, tls_error(ctx));
	else
		lua_pushinteger(l, r);

	return 2;
}

static int
l_close(lua_State *l)
{
	struct tls	*ctx, **pctx;
	int		 r;

	pctx = luaL_checkudata(l, 1, TLS_CONTEXTHANDLE);
	ctx = *pctx;
	r = tls_close(ctx);
	lua_pushboolean(l, r == 0);
	if (r) {
		lua_pushstring(l, tls_error(ctx));
		return 2;
	}

	return 1;
}

static int
l_context_gc(lua_State *l)
{
	struct tls *ctx, **pctx;

	pctx = luaL_checkudata(l, 1, TLS_CONTEXTHANDLE);
	ctx = *pctx;
	tls_close(ctx);
	tls_free(ctx);
	return 0;
}

int
luaopen_ltls(lua_State *l)
{
	struct luaL_Reg ltls[] = {
		{"config_new", l_config_new},
		{"connect", l_connect},
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
		return luaL_error(l, "ltls: failed to initialize library");

	luaL_newlib(l, ltls);
	luaL_newmetatable(l, TLS_CONTEXTHANDLE);
	lua_pushvalue(l, -1);
	lua_setfield(l, -2, "__index");
	luaL_setfuncs(l, context_methods, 0);
	lua_pop(l, 1);

	for (i = 0; ltls_constants[i].name != NULL; i++) {
		lua_pushinteger(l, ltls_constants[i].value);
		lua_setfield(l, -2, ltls_constants[i].name);
	}

	return 1;
}
