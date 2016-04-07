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

local s2 = s:accept()
ctx = assert(tls.accept(s2:socket(), config))

buf = assert(ctx:read(100))
io.write(buf)
assert(ctx:write(buf))

