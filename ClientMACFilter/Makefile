all:
	mkdir -p bin/
	cc src/client_mac.c -o bin/client_mac -lzstd -lpcap -lpthread
	cc src/client_mac.c -o bin/client_mac_s --static -lzstd -lpcap -lpthread
