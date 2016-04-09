local tls = require("ltls")

local t = {
	["cert"] = "/home/sunil/lualtls/obj/server.crt",
	["key"] = "/home/sunil/lualtls/obj/server.key",
	["ca"] = "/home/sunil/lualtls/obj/ca.crt"
};
local config = assert(tls.config_new(t))
local ctx = assert(tls.connect("localhost", "1234", config));

::write_again::
_, r = assert(ctx:write("hello world"))
if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
	goto write_again
end

::read_again::
local buf, r = assert(ctx:read(1024))
if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
	goto read_again
end

io.write(buf)
assert(ctx:close())
