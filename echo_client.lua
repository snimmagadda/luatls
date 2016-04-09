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

local config = assert(tls.config_new({["verify"] = false}))
local ctx = assert(tls.connect("localhost", "1234", config))
tls_assert(ctx:write("hello world"))
local buf = tls_assert(ctx:read(1024))
io.write(buf)
assert(ctx:close())
