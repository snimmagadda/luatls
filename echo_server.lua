local net = require("net")
local tls = require("ltls")
local unix = require("unix")
local aux = require("tlsaux")

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
		buf = aux.read(ctx, 1024)
		io.write(buf)
		aux.write(ctx, buf)
		assert(ctx:close())
		s2:close()
		os.exit(0)
	else
		s2:close()
	end
end
