local tls = require("ltls")

local host = "localhost"
local port = "1234"

local config = assert(tls.config_new({["verify"] = false}))
local ctx = assert(tls.connect(host, port, config))
assert(ctx:write("hello world"))
local buf = assert(ctx:read(1024))
io.write(buf)
assert(ctx:close())

--[[
Alternatively, config param is optional which would make ltls to
create a new default config and apply to the context.
local tls = require("ltls")
local ctx = tls.connect("localhost", "port")
assert(ctx:write("hello world")
local buf = assert(ctx:read(1024))
io.write(buf)
assert(ctx:close())
]]
