#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sniff_func.h"
#include "sniff_head.h"

void print_base_packet_info(const struct ethernetHeader *ether) {
	printf("Destination: ");
	print_Ethernet_data(ether->ether_dhost, ETHER_ADDR_LEN);
	printf("Source: ");
	print_Ethernet_data(ether->ether_shost, ETHER_ADDR_LEN);
	printf("Type: ");
	print_Ethernet_data(ether->ether_type, ETHER_TYPE_LEN);
}

void packet_processing(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) { 
	static int count = 0;
	printf("Packet Count: %d\n", ++count);
	printf("Recieved Packet Size: %d\n", pkthdr->len);
	const struct ethernetHeader *ether;
	const struct IPHeader *iphead;
	ether = (struct ethernetHeader*)(packet);
	iphead = (struct IPHeader*)(packet + sizeof(struct ethernetHeader));
	printf("TTL %d\n", iphead->iph_ttl);
	printf("Protocol %02X\n", iphead->iph_protocol);
	printf("CRC %d\n", iphead->iph_chksum);
	print_base_packet_info(ether);
	printf("Payload: ");
	for (int i = 28; i < pkthdr->len; ++i) {
		if (isprint(packet[i]))
			printf("%c ",packet[i]);
		else
			printf("%02X", packet[i]);
		if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
			printf("\n");
	}
	printf("---------------------------------\n");
}

void connectDevice(pcap_if_t *alldevsp, char *name) {
	pcap_if_t *device;
	pcap_t *handle;
	bpf_u_int32 net, mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	int count = 0;
	device = alldevsp;
	while (device != NULL) {
		if (strcmp(name, device->name) == 0) {
			pcap_lookupnet(device->name, &net, &mask, errbuf);
			print_Net_Mask(net, mask);
			free(name);
			if ((handle = pcap_open_live(device->name, 65536, 1, 0, errbuf)) == NULL) {
				perror("pcap_open_live error");
				exit(1);
			} else {
				printf("\nConnect to %s - done\n", device->name);
				pcap_loop(handle, -1, packet_processing, NULL);
			}
		}
		device = device->next;
		++count;
	}
	free(name);
}

int main() {
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		perror("pcap_findalldevs error");
		exit(1);
	}
	list_Device(alldevsp);
	char *name;
	printf("\nInput name device: ");
	if (scanf("%m[a-z,A-Z,0-9]", &name) == -1) {
		perror("scanf error");
		exit(1);
	}
	connectDevice(alldevsp, name);
	pcap_freealldevs(alldevsp);
	return 0;
}
