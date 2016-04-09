local net = require("net")
local tls = require("ltls")

function tls_assert(f)
::again::
	v, r = assert(f)
	if r == tls.WANT_POLLIN or err == tls.WANT_POLLOUT then
		goto again
	else
		return v
	end
end

local t = {
	["cert"] = "/home/sunil/lualtls/obj/server.crt",
	["key"] = "/home/sunil/lualtls/obj/server.key",
	["ca"] = "/home/sunil/lualtls/obj/ca.crt"
};
local config = assert(tls.config_new(t))
local s = assert(net.bind("localhost", "1234"))
ctx = assert(tls.accept(s:accept():socket(), config))
buf = tls_assert(ctx:read(100))
io.write(buf)
tls_assert(ctx:write(buf))
