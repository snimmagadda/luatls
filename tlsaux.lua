local tls = require("ltls")

local function tls_read(ctx, l)
	::again::
	buf, l = assert(ctx:read(l))
	if l == tls.WANT_POLLIN or l == tls.WANT_POLLOUT then
		goto again
	end
	return buf
end

local function tls_write(ctx, s)
	::again::
	_, r = assert(ctx:write(s))
	if l == tls.WANT_POLLIN or l == tls.WANT_POLLOUT then
		goto again
	end
	return ctx, r
end

return {
	read = tls_read,
	write = tls_write
}
