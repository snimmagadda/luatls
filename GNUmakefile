LIB=	ltls
SRCS=	lualtls.c

CFLAGS=	-I/usr/include/lua5.3/
LDADD=	-L/usr/lib/lua5.3/ -lcrypto -lssl -ltls -llua

${LIB}.so: ${SRCS:.c=.o}
	${CC} -shared -o ${LIB}.so ${CFLAGS} ${SRCS:.c=.o} ${LDADD}
clean:
	rm -f ${LIB}.so *.o
