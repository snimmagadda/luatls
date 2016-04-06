--[[
start a TLS echo server either as
$ echo "hello world" | doas nc -c -C /etc/ssl/server.crt \
  -K /etc/ssl/private/server.key -l 1234

or

$ echo "hello world" | doas openssl s_server -accept 1234 \
  -cert /etc/ssl/server.crt -key /etc/ssl/private/server.key

and run this Lua script.
]]

local tls = require("ltls")

local host = "localhost"
local port = "1234"

local config = tls.config_new()
--*INSECURE* disable cert verification for self signed cert *INSECURE*
--config:noverifycert()
--config:noverifyname()

local ctx = tls.client()
assert(ctx:configure(config))
assert(ctx:connect(host, port))
local buf = assert(ctx:read(1024))
io.write(buf)
assert(ctx:write(buf))
assert(ctx:close())
