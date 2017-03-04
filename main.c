#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void listDevice(pcap_if_t *alldevsp);
void connectDevice(pcap_if_t *alldevsp, int number);
void print_Net_Mask(bpf_u_int32 net, bpf_u_int32 mask);

//#pragma pack(push, 1)
struct packet_test {
	unsigned short ch;
	unsigned short i;
	unsigned short j;
	unsigned short fgh;
	//short j;
}test;
//#pragma pack(pop)

void my_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) { 
	int i = 0;
	static int count = 0;
	printf("Packet Count: %d\n", ++count);
	printf("Recieved Packet Size: %d\n", pkthdr->len);
	printf("Payload:\n");
	for (i = 0; i < pkthdr->len; i++) {
		if (isprint(packet[i]))
			printf("%c ",packet[i]);
		else
			printf(" . ");
		if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
			printf("\n");
	}
}

int main() {
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		perror("pcap_findalldevs error");
		exit(1);
	}
	listDevice(alldevsp);
	int number;
	printf("\nInput number device: ");
	if ((scanf("%d", &number)) == -1) {
		perror("scanf error");
		exit(1);
	}
	connectDevice(alldevsp, number);
	pcap_freealldevs(alldevsp);
	printf("\nSIZE = %zu\n", sizeof(test));
	return 0;
}

void listDevice(pcap_if_t *alldevsp) {
	pcap_if_t *device;
	int i = 0;
	printf("\nDEVICE LIST\n\n");
	for (device = alldevsp; device != NULL; device = device->next) {
		printf("%d) Device name: %s\n", i, device->name);
		++i;
	}
}

void print_Net_Mask(bpf_u_int32 net, bpf_u_int32 mask) {
	struct in_addr addr;
	addr.s_addr = net;
	printf("NET: %s\n", inet_ntoa(addr));
	addr.s_addr = mask;
	printf("MASK: %s\n", inet_ntoa(addr));
}

void connectDevice(pcap_if_t *alldevsp, int number) {
	pcap_if_t *device;
	pcap_t *handle;
	bpf_u_int32 net, mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	int count = 0;
	device = alldevsp;
	while (device != NULL) {
		if (number == count) {
			pcap_lookupnet(device->name, &net, &mask, errbuf);
			print_Net_Mask(net, mask);
			if ((handle = pcap_open_live(device->name, 65536, 1, 0, errbuf)) == NULL) {
				perror("pcap_open_live error");
				exit(1);
			} else {
				printf("\nConnect to %s - done\n", device->name);
				pcap_loop(handle, -1, my_callback, NULL);
			}
		}
		device = device->next;
		++count;
	}
}
