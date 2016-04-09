local net = require("net")
local tls = require("ltls")
local unix = require("unix")

local t = {
	["cert"] = "/home/sunil/lualtls/obj/server.crt",
	["key"] = "/home/sunil/lualtls/obj/server.key",
	["ca"] = "/home/sunil/lualtls/obj/ca.crt"
};
local config = assert(tls.config_new(t))
local s = assert(net.bind("localhost", "1234"))
unix.signal(unix.SIGINT, function() os.exit(0) end);
while true do
	local s2 = s:accept()
	ctx = assert(tls.accept(s2:socket(), config))
	if unix.fork() == 0 then
		::read_again::
		buf, r = assert(ctx:read(1024))
		if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
			goto read_again
		end
		io.write(buf)
		::write_again::
		_, r = assert(ctx:write(buf))
		if r == tls.WANT_POLLIN or r == tls.WANT_POLLOUT then
			goto write_again
		end
		assert(ctx:close())
		s2:close()
		os.exit(0)
	else
		s2:close()
	end
end
s:close()
