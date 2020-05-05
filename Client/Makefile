all:
	mkdir -p bin/
	cc src/client.c -o bin/client -lzstd -lpcap -lpthread
	cc src/client.c -o bin/client_s --static -lzstd -lpcap -lpthread
