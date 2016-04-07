local net = require("net")
local tls = require("ltls")

local host = "localhost"
local port = "1234"
local s = assert(net.bind(host, port))

local t = {
	["verify"] = false,
	["cert"] = "/home/sunil/lualtls/obj/server.crt",
	["key"] = "/home/sunil/lualtls/obj/server.key"
};
config = assert(tls.config_new(t))

--local s2 = s:accept()
--ctx = assert(tls.accept(s2:socket(), config))
ctx = assert(tls.accept(s:accept():socket(), config))

buf = assert(ctx:read(100))
io.write(buf)
assert(ctx:write(buf))

--[[
Alternatively, config param is optional to accept and ltls would make
a default config if not given.
local net = require("net")
local tls = require("ltls")
local s = assert(net.bind("localhost", "1234")
ctx = assert(tls.accept(s:accept():socket())
buf = assert(ctx:read(100))
io.write(buf)
assert(ctx:write(buf))
]]
