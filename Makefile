all:
	gcc -g -Wall -o sample sample.c net.c tls.c -Ilibuv-1.10.2/include -Iopenssl-1.1.0c/include -Llibuv-1.10.2/.libs -Lopenssl-1.1.0c/ -Wl,-Bstatic -luv -lssl -lcrypto -Wl,-Bdynamic -lpthread -ldl
