#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>

//ref: https://facebook.github.io/zstd/zstd_manual.html
//can change the compression level for CPU/bandwidth tradeoff
#define COMPRESSION_LEVEL 1
//set to some sane level based on max packet size (probably ~2312 + radiotap header len)
//7981 bytes + overhead (according to IEEE documentation, DOI 10.1109/IEEESTD.2012.6361248)
#define CAPTURE_BUFFER_SIZE 9500
#define COMPRESSION_BUFFER_BOUND ZSTD_compressBound(CAPTURE_BUFFER_SIZE)
#define MACOFFSET 46 //offset for the source address in the pcap captured packet
#define MAC1 0x6C
#define MAC2 0xB0
#define MAC3 0xCE
#define MAC4 0xB0
#define MAC5 0x01
#define MAC6 0x00

//statically allocated buffers to prevent allocation/free overhead during runtime
char *SendDBuffer;

struct ThreadParameters
{
	//WiFi card capture interface
	pcap_t *Cap;
	//TCP socket for communicating with server
	int Tcp;
	//recycle buffer so we don't need to malloc for every packet
	char *CompressedBuffer;
};

//mostly for debugging
void PrintBuffer(char *toPrint, int length)
{
	for (int i = 0; i < length; ++i)
	{
		printf("%02X", toPrint[i]);
	}
}

int CompressBuffer(const u_char *toCompress, size_t toCompressSize, char *compressed, size_t *compressedSize)
{
	*compressedSize = ZSTD_compress(compressed, COMPRESSION_BUFFER_BOUND,
									toCompress, toCompressSize,
									COMPRESSION_LEVEL);
	if (ZSTD_isError(*compressedSize))
	{
		fprintf(stderr, "Got error in ZSTD_compress: %s\n", ZSTD_getErrorName(*compressedSize));
		fprintf(stderr, "To compress size: %ld\n", toCompressSize);
		return 1;
	}
	return 0;
}
int SendFrameToServer(int socket, int frameLength, const u_char *frame)
{
	int writeLen;
	writeLen = send(socket, &frameLength, sizeof(int), 0);
	if (writeLen != sizeof(int))
	{
		fprintf(stderr, "Could not write frame length to server: %d != %d\n", writeLen, 4);
		return 1;
	}
	writeLen = send(socket, frame, frameLength, MSG_MORE);
	if (writeLen != frameLength)
	{
		fprintf(stderr, "Could not write frame to server: %d != %d\n", writeLen, frameLength);
		return 1;
	}

	return 0;
}
void *PcapLoop(void *arg)
{
	struct pcap_stat stats;
	struct ThreadParameters *params = (struct ThreadParameters *)arg;
	params->CompressedBuffer = malloc(COMPRESSION_BUFFER_BOUND);
	struct pcap_pkthdr *header;
	const u_char *frame;
	int returnValue;
	size_t compressedSize;

	for (; (returnValue = pcap_next_ex(params->Cap, &header, &frame)) == 1;)
	{
		//new for MAC filter, needs to have source field
		if (header->caplen < MACOFFSET + 6)
		{
			//fprintf(stderr, "Got small packet (%d), skipping\n", header->caplen);
			continue;
		}
		if (frame[MACOFFSET] != MAC1 ||
			frame[MACOFFSET + 1] != MAC2 ||
			frame[MACOFFSET + 2] != MAC3 ||
			frame[MACOFFSET + 3] != MAC4 ||
			frame[MACOFFSET + 4] != MAC5 ||
			frame[MACOFFSET + 5] != MAC6)
		{
			//fprintf(stderr, "Got wrong MAC, skipping\n");
			continue;
		}
		if (header->caplen != header->len)
		{
			fprintf(stderr, "Got small packet (snaplen = %d, actual length = %d)\n", header->caplen, header->len);
			return NULL;
		}
		if (CompressBuffer(frame, header->caplen, params->CompressedBuffer, &compressedSize))
		{
			fprintf(stderr, "Got error compressing buffer in CaptureTraffic\n");
			return NULL;
		}
		if (SendFrameToServer(params->Tcp, compressedSize, params->CompressedBuffer))
		{
			fprintf(stderr, "Got error sending frame in CaptureTraffic\n");
			return NULL;
		}
	}
	if (returnValue == PCAP_ERROR)
	{
		pcap_perror(params->Cap, "pcap_next_ex: ");
	}
	//TODO: close server socket and exit program
}
//TODO: maybe make this take the interface as an argument, for multiple clients on one device
int SetupPcap(pcap_t **cap)
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	*cap = pcap_create("wlan0mon", errorBuffer);
	if (*cap == NULL)
	{
		fprintf(stderr, "Could not open capture interface: %s\n", errorBuffer);
		return 1;
	}
	//immediate mode is used for lower latency
	//may get better performance / overall throughput without it
	if (pcap_set_immediate_mode(*cap, 1) != 0)
	{
		fprintf(stderr, "Could not enable immediate mode\n");
		return 2;
	}
	if (pcap_set_promisc(*cap, 1) != 0)
	{
		fprintf(stderr, "Could not enable promiscuous mode\n");
		return 3;
	}
	if (pcap_set_rfmon(*cap, 1) != 0)
	{
		fprintf(stderr, "Could not enable monitor mode\n");
		return 4;
	}
	//should be sufficiently large to capture any wireless packet
	if (pcap_set_snaplen(*cap, CAPTURE_BUFFER_SIZE) != 0)
	{
		fprintf(stderr, "Could not set snapshot length\n");
		return 5;
	}
	int activateResult = pcap_activate(*cap);
	if (activateResult != 0)
	{
		fprintf(stderr, "Could not activate capture interface (error %d)\n", activateResult);
		switch (activateResult)
		{
		case PCAP_WARNING_PROMISC_NOTSUP:
		case PCAP_ERROR_NO_SUCH_DEVICE:
		case PCAP_ERROR_PERM_DENIED:
			pcap_perror(*cap, "pcap_activate: ");
			break;
		default:
			break;
		}
		return 999;
	}
	if (pcap_setdirection(*cap, PCAP_D_IN) != 0)
	{
		fprintf(stderr, "WARNING: Could not set capture direction; use a MAC whitelist to prevent packet duplication\n");
		pcap_perror(*cap, "pcap_setdirection: ");
	}
	return 0;
}

int DecompressBuffer(u_char *toDecompress, size_t toDecompressSize, char *decompressed, size_t *decompressedSize)
{
	*decompressedSize = ZSTD_decompress(decompressed, CAPTURE_BUFFER_SIZE,
										toDecompress, toDecompressSize);
	if (ZSTD_isError(*decompressedSize))
	{
		fprintf(stderr, "Got error in ZSTD_decompress: %s\n", ZSTD_getErrorName(*decompressedSize));
		return 1;
	}
	return 0;
}
int BroadcastTraffic(pcap_t *cap, long frameLength, u_char *frame)
{
	int injectLength;
	injectLength = pcap_inject(cap, frame, frameLength);
	if (injectLength != frameLength)
	{
		fprintf(stderr, "Injection length was not the same as frame length (%d != %ld)\n", injectLength, frameLength);
		return 1;
	}
	return 0;
}
void *ServerLoop(void *arg)
{
	struct ThreadParameters *params = (struct ThreadParameters *)arg;
	char *compressedBuffer = malloc(COMPRESSION_BUFFER_BOUND);
	char *broadcastBuffer = malloc(CAPTURE_BUFFER_SIZE);
	size_t recvSize, decompressedSize, readOffset, readLength;
	for (;;)
	{
		//TODO: move to function
		readOffset = 0;
		while (readOffset < 4)
		{
			readLength = read(params->Tcp, compressedBuffer, 4 - readOffset);
			//printf("Read: %d\n", readLength);
			if (readLength == 0)
			{
				//end of file, not expected
				fprintf(stderr, "Small read in ServerLoop for frame length\n");
				goto cleanup;
			}
			if (readLength < 0)
			{
				perror("Error reading from socket in ServerLoop: ");
				goto cleanup;
			}
			readOffset += readLength;
		}
		recvSize = *((int *)compressedBuffer);
		readOffset = 0;
		while (readOffset < recvSize)
		{
			readLength = read(params->Tcp, compressedBuffer, recvSize - readOffset);
			if (readLength == 0)
			{
				//end of file, not expected
				fprintf(stderr, "Small read in ServerLoop for frame\n");
				goto cleanup;
			}
			if (readLength < 0)
			{
				perror("Error reading from socket in ServerLoop: ");
				goto cleanup;
			}
			readOffset += readLength;
		}
		//printf("Got packet from server, length = %d\n", recvSize);
		if (DecompressBuffer(compressedBuffer, recvSize, broadcastBuffer, &decompressedSize))
		{
			fprintf(stderr, "Got error decompressing buffer in BroadcastTraffic, skipping packet\n");
			//assume broken data and keep going?
			continue;
		}
		//printf("Broadcast Packet: length = %d\n", decompressedSize);
		if (BroadcastTraffic(params->Cap, decompressedSize, broadcastBuffer))
		{
			fprintf(stderr, "Got error sending buffer in BroadcastTraffic, stopping\n");
			goto cleanup;
		}
	}
cleanup:
	//close socket?
	free(compressedBuffer);
	free(broadcastBuffer);
}
int SetupServerConnection(int *tcpfd, char *server, int port)
{
	struct sockaddr_in serverSA = {0};
	int i;

	serverSA.sin_family = AF_INET;
	serverSA.sin_port = htons(port);
	i = inet_pton(AF_INET, server, &serverSA.sin_addr);
	if (i != 1)
	{
		fprintf(stderr, "Could not convert server address\n");
		return 1;
	}
	*tcpfd = socket(AF_INET, SOCK_STREAM, 0);
	if (*tcpfd == -1)
	{
		perror("Could not create socket: ");
		return 2;
	}
	i = connect(*tcpfd, (struct sockaddr *)&serverSA, sizeof(serverSA));
	if (i == -1)
	{
		perror("Could not connect to remote server: ");
		return 3;
	}

	int flag = 1;
	if (setsockopt(*tcpfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) == -1)
	{
		perror("setsockopt");
	}

	return 0;
}

int main()
{
	pcap_t *captureInterface;
	int tcpFD, i;
	pthread_t getWifiPacketThread;
	pthread_t getServerPacketThread;
	struct ThreadParameters threadParams;
	//TODO: specify capture device on command line
	if (SetupPcap(&captureInterface))
	{
		fprintf(stderr, "Error setting up pcap, stopping\n");
		return 1;
	}
	threadParams.Cap = captureInterface;
	//TODO: specify IP and port on command line or something
	if (SetupServerConnection(&tcpFD, "127.0.0.1", 7777))
	{
		fprintf(stderr, "Error setting up tcp, stopping\n");
		return 2;
	}
	threadParams.Tcp = tcpFD;
	SendDBuffer = malloc(COMPRESSION_BUFFER_BOUND);

	pthread_create(&getServerPacketThread, NULL, &ServerLoop, &threadParams);
	pthread_create(&getWifiPacketThread, NULL, &PcapLoop, &threadParams);

	printf("Enter 'q' to stop, or 'p' to get current capture status\n");
	struct pcap_stat stats;
	int c;
	for (; (c = getc(stdin)) != EOF;)
	{
		if (c == 'p')
		{
			pcap_stats(captureInterface, &stats);
			printf("Frames: %d / %d (%d dropped from interface)\n", stats.ps_recv - stats.ps_drop, stats.ps_recv, stats.ps_ifdrop);
		}
		else if (c == 'q')
			break;
	}

	i = shutdown(tcpFD, SHUT_RDWR);
	if (i == -1)
	{
		perror("shutdown");
		exit(7);
	}
	i = close(tcpFD);
	if (i == -1)
	{
		perror("close tcpfd");
		exit(8);
	}

	pthread_join(getServerPacketThread, NULL);
	pcap_breakloop(captureInterface);
	pthread_join(getWifiPacketThread, NULL);
	pcap_close(captureInterface);

	free(SendDBuffer);
	return 0;
}
