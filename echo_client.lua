local tls = require("ltls")
local aux = require("tlsaux")

local t = {
	["cert"] = "/home/sunil/lualtls/obj/server.crt",
	["key"] = "/home/sunil/lualtls/obj/server.key",
	["ca"] = "/home/sunil/lualtls/obj/ca.crt"
};
local config = assert(tls.config_new(t))
local ctx = assert(tls.connect("localhost", "1234", config));
aux.write(ctx, "hello world")
buf = aux.read(ctx, 1024)
io.write(buf)
assert(ctx:close())
