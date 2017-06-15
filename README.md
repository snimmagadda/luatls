# Lua wrapper for libtls API (libressl).

This is a *work in progress* code, incomplete and non-portable.
Tested only on OpenBSD with Lua-5.3.4.

## Put these helper functions somewhere accessible.

	local tls = require("ltls")

	local function tls_write(ctx, data)
	   local w, err
	   repeat
	      w, err = ctx:write(data)
	   until w ~= tls.WANT_POLLIN or w~= tls.WANT_POLLOUT
	   return w, err
	end

	local function tls_read(ctx, len)
	   local buf, r, err
	   repeat
	      buf, r, err = ctx:read(len)
	   until r ~= tls.WANT_POLLIN or r ~= tls.WANT_POLLOUT
	   return buf, r, err
	end

	local function tls_close(ctx)
	   local c, err
	   repeat
	      c, err = ctx:close()
	   until c ~= tls.WANT_POLLIN or c ~=tls.WANT_POLLOUT
	   return c, err
	end

## Echo Client:
	local tls = require("ltls")

	local ctx = tls.connect("localhost", 12345, tls.config_new())
	tls_write(ctx, "hello world")
	local buf = tls_read(ctx, 20)
	io.write(buf)

## Echo Server:
