local net = require("net")
local tls = require("ltls")

local t = {
	["cert"] = "/home/sunil/lualtls/obj/server.crt",
	["key"] = "/home/sunil/lualtls/obj/server.key",
	["ca"] = "/home/sunil/lualtls/obj/ca.crt"
};
local config = assert(tls.config_new(t))
local s = assert(net.bind("localhost", "1234"))
ctx = assert(tls.accept(s:accept():socket(), config))

::read_again::
buf, r = ctx:read(1024)
if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
	goto read_again
end
io.write(buf)

::write_again::
_, r = ctx:write(buf)
if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
	goto write_again
end
