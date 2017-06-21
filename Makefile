LUA_VERSION?=	5.3
LOCALBASE?=	/usr/local

LIB=		ltls
SRCS=		lualtls.c

CFLAGS+=	-I${LOCALBASE}/include/lua-${LUA_VERSION}
LDADD+=		-ltls -lssl -lcrypto -L${LOCALBASE}/lib -llua${LUA_VERSION}

.include <bsd.lib.mk>
