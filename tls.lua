local tls = require("ltls")

local host = "localhost"
local port = "1234"

local config = tls.config_new()
config:noverifycert()
config:noverifyname()

local ctx = tls.client()
assert(ctx:configure(config))
assert(ctx:connect(host, port))
--assert(ctx:close())
