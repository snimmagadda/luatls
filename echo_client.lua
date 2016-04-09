local tls = require("ltls")

function tls_assert(f)
::again::
	v, r = assert(f)
	if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
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
local ctx = assert(tls.connect("localhost", "1234", config));
tls_assert(ctx:write("hello world"))
local buf = tls_assert(ctx:read(1024))
io.write(buf)
assert(ctx:close())
