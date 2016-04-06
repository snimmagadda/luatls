local tls = require("ltls")

local host = "localhost"
local port = "1234"

local config = tls.config_new()
config:noverifycert()
config:noverifyname()

local ctx = tls.client()
assert(ctx:configure(config))
assert(ctx:connect(host, port))
local r, buf, err_msg = ctx:read(1024)
print(r, buf, err_msg)

--assert(ctx:close())
