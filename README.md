# Lua module for libtls API (libressl).

This is a *work in progress* code and incomplete.
Slightly tested only with Lua-5.3.4.

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
Using [luaunix](https://github.com/arcapos/luaunix) and
[luanet](https://github.com/arcapos/luanet) modules...

	local net = require("net")
	local tls = require("ltls")
	local unix = require("unix")

	local t = {
	   ["cert"] = "/etc/ssl/server.crt",
	   ["key"] = "/etc/ssl/private/server.key"
	}
	local config = tls.config_new(t)
	local s = net.bind("localhost", "12345")
	unix.signal(unix.SIGINT, function() os.exit(0) end)
	local ctx_server = tls.server(config)
	while true do
	   local s2 = s:accept()
	   local ctx = tls.accept(s2:socket(), ctx_server, config)
	   if unix.fork() == 0 then
	      local buf = tls_read(ctx, 1024)
	      io.write(buf)
	      tls_write(ctx, buf)
	      tls_close(ctx)
	      s2:close()
	      os.exit(0)
	   else
	      s2:close()
	   end
	end
