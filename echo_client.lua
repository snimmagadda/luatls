local tls = require("ltls")

local host = "localhost"
local port = "1234"

local config = tls.config_new()
--*INSECURE* disable cert verification for self signed cert *INSECURE*
config:noverifycert()
config:noverifyname()

local ctx = tls.connect(config, host, port)
local buf = assert(ctx:read(1024))
io.write(buf)
assert(ctx:write(buf))
assert(ctx:close())
