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

static int
l_config_new(lua_State *l)
{
	struct tls_config **config;

	config = lua_newuserdata(l, sizeof *config);
	luaL_getmetatable(l, TLS_CONFIGHANDLE);
	lua_setmetatable(l, -2);
	if ((*config = tls_config_new()) == NULL)
		return luaL_error(l, "ltls: failed to create a config");

	return 1;
}

static int
l_set_ciphers(lua_State *l)
{
	struct tls_config	*config, **pc;
	const char		*ciphers;
	int			 r;

	pc = luaL_checkudata(l, 1, TLS_CONFIGHANDLE);
	config = *pc;
	ciphers = luaL_checkstring(l, 2);
	r = tls_config_set_ciphers(config, ciphers);
	lua_pushboolean(l, r == 0);
	if (r)
		lua_pushstring(l, "ltls: failed to set ciphers");

	return r == 0 ? 1 : 2;
}

static int
l_noverifycert(lua_State *l)
{
	struct tls_config *config, **pc;

	pc = luaL_checkudata(l, 1, TLS_CONFIGHANDLE);
	config = *pc;
	tls_config_insecure_noverifycert(config);
	return 0;	
}

static int
l_noverifyname(lua_State *l)
{
	struct tls_config *config, **pc;

	pc = luaL_checkudata(l, 1, TLS_CONFIGHANDLE);
	config = *pc;
	tls_config_insecure_noverifyname(config);
	return 0;	
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
l_client(lua_State *l)
{
	struct tls **ctx;

	ctx = lua_newuserdata(l, sizeof *ctx);
	luaL_getmetatable(l, TLS_CONTEXTHANDLE);
	lua_setmetatable(l, -2);
	if ((*ctx = tls_client()) == NULL)
		return luaL_error(l, "ltls: failed to create client context");

	return 1;
}

static int
l_configure(lua_State *l)
{
	struct tls_config	*config, **pc;
	struct tls		*ctx, **pctx;
	int			 r;

	pctx = luaL_checkudata(l, 1, TLS_CONTEXTHANDLE);
	pc = luaL_checkudata(l, 2, TLS_CONFIGHANDLE);
	config = *pc;
	ctx = *pctx;
	r = tls_configure(ctx, config);
	lua_pushboolean(l , r == 0);
	if (r)
		lua_pushstring(l, tls_error(ctx));

	return r == 0 ? 1 : 2;
}

static int
l_connect(lua_State *l)
{
	struct tls	*ctx, **pctx;
	const char	*host, *port;
	int		 r;

	pctx = luaL_checkudata(l, 1, TLS_CONTEXTHANDLE);
	ctx = *pctx;
	host = luaL_checkstring(l, 2);
	port = luaL_checkstring(l, 3);
	r = tls_connect(ctx, host, port);
	lua_pushboolean(l, r == 0);
	if (r)
		lua_pushstring(l, tls_error(ctx));

	return r == 0 ? 1 : 2;
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
	luaL_addsize(&b, r);
	lua_pushinteger(l, r);
	luaL_pushresult(&b);
	if (r == -1)
		lua_pushstring(l, tls_error(ctx));

	return r != -1 ? 2 : 3;
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
	if (r)
		lua_pushstring(l, tls_error(ctx));

	return r == 0 ? 1 : 2;
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
		{"client", l_client},
		{NULL, NULL}
	};

	struct luaL_Reg config_methods[] = {
		{"set_ciphers", l_set_ciphers},
		{"noverifycert", l_noverifycert},
		{"noverifyname", l_noverifyname},
		{"__gc", l_config_gc},
		{NULL, NULL}
	};

	struct luaL_Reg context_methods[] = {
		{"configure", l_configure},
		{"connect", l_connect},
		{"read", l_read},
		{"close", l_close},
		{"__gc", l_context_gc},
		{NULL, NULL}
	};

	if (tls_init() != 0)
		return luaL_error(l, "ltls: failed to initialize library");

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
