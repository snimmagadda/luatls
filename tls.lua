local tls = require("ltls")

local host = "localhost"
local port = "1234"

local config = tls.config_new()
local ctx = tls.client()

assert(tls.configure(ctx, config))
assert(tls.connect(ctx, host, port))

-- assert(tls.close(ctx)) -- SSL_shutdown:uninitialized??
tls.close(ctx)
tls.free(ctx)
