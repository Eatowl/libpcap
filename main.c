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

#define ETHER_ADDR_LEN	6

struct ethernet {
 	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
 	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
 	u_short ether_type; /* IP? ARP? RARP? etc */
} __attribute__((packed));

void my_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) { 
	static int count = 0;
	const struct ethernet *ether;
	ether = (struct ethernet*)(packet);
	printf("\nSIZE = %zu\n", sizeof(ether));
	for (unsigned char j = 0; j < 7; j++) {
		printf("%02X", ether->ether_dhost[j]);
		if (j != 6)
			printf(":");
	}
	printf("\n");
	for (unsigned char j = 0; j < 7; j++) {
		printf("%02X", ether->ether_shost[j]);
		if (j != 6)
			printf(":");
	}
	printf("\n->%X\n", ether->ether_dhost);
	printf("Packet Count: %d\n", ++count);
	printf("Recieved Packet Size: %d\n", pkthdr->len);
	printf("Recieved Size caplen: %d\n", pkthdr->caplen);
	printf("Payload:\n");
	for (int i = 28; i < pkthdr->len; i++) {
		if (isprint(packet[i]))
			printf("%c ",packet[i]);
		else
			printf("%02X", packet[i]);
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
