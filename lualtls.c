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

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define TLS_CONFIGHANDLE	"TLS config"
#define	TLS_CONTEXTHANDLE	"TLS context"

static struct tls_config *default_config;

static struct tls_config **
ltlsL_optconfig(lua_State *l, int arg)
{
	if (lua_isnoneornil(l, arg))
		return &default_config;

	return luaL_checkudata(l, arg, TLS_CONFIGHANDLE);
}

static int
l_config_new(lua_State *l)
{
	struct tls_config	**config;

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
	/* XXX todo rest of the config params */

	return 1;
}

static int
l_config_gc(lua_State *l)
{
	struct tls_config *config, **pc;

	pc = luaL_checkudata(l, 1, TLS_CONFIGHANDLE);
	config = *pc;
	tls_config_free(config);
	return 0;
}

static int
l_connect(lua_State *l)
{
	struct tls_config	 *config, **pc;
	struct tls		**ctx;
	const char		 *host, *port;

	host = luaL_checkstring(l, 1);
	port = luaL_checkstring(l, 2);
	pc = ltlsL_optconfig(l, 3);
	config = *pc;
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
again:
	switch ((r = tls_read(ctx, p, bufsz))) {
	case TLS_WANT_POLLIN:
	case TLS_WANT_POLLOUT:
		goto again;	/* XXX just the blocking mode for now */
	}

	if (r == -1) {
		lua_pushnil(l);
		lua_pushstring(l, tls_error(ctx));
		return 2;
	}

	luaL_addsize(&b, r);
	luaL_pushresult(&b);
	return 1;
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
again:
	switch ((r = tls_write(ctx, b, len))) {
	case TLS_WANT_POLLIN:
	case TLS_WANT_POLLOUT:
		goto again;	/* XXX just the blocking mode for now */
	}

	if (r == -1) {
		lua_pushnil(l);
		lua_pushstring(l, tls_error(ctx));
		return 2;
	}
	
	lua_pop(l, 1); /* pop string arg; keep context and return */
	return 1;
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
	tls_free(ctx);
	return 0;
}

int
luaopen_ltls(lua_State *l)
{
	struct luaL_Reg ltls[] = {
		{"config_new", l_config_new},
		{"connect", l_connect},
		{NULL, NULL}
	};

	struct luaL_Reg config_methods[] = {
		{"__gc", l_config_gc},
		{NULL, NULL}
	};

	struct luaL_Reg context_methods[] = {
		{"read", l_read},
		{"write", l_write},
		{"close", l_close},
		{"__gc", l_context_gc},
		{NULL, NULL}
	};

	if (tls_init() != 0)
		return luaL_error(l, "ltls: failed to initialize library");

	if ((default_config = tls_config_new()) == NULL)
		return luaL_error(l, "ltls: failed to create default config");

	luaL_newlib(l, ltls);
	luaL_newmetatable(l, TLS_CONFIGHANDLE);
	lua_pushvalue(l, -1);
	lua_setfield(l, -2, "__index");
	luaL_setfuncs(l, config_methods, 0);
	lua_pop(l, 1);

	luaL_newmetatable(l, TLS_CONTEXTHANDLE);
	lua_pushvalue(l, -1);
	lua_setfield(l, -2, "__index");
	luaL_setfuncs(l, context_methods, 0);
	lua_pop(l, 1);

	return 1;
}
