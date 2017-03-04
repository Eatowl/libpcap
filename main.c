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

void my_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) { 
	static int count = 0;
	const struct ethernet *ether;
	ether = (struct ethernet*)(packet);
	printf("Destination: ");
	print_mac(ether->ether_dhost);
	printf("Source: ");
	print_mac(ether->ether_shost);
	printf("Packet Count: %d\n", ++count);
	printf("Recieved Packet Size: %d\n", pkthdr->len);
	printf("Payload:\n");
	for (int i = 28; i < pkthdr->len; ++i) {
		if (isprint(packet[i]))
			printf("%c ",packet[i]);
		else
			printf("%02X", packet[i]);
		if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
			printf("\n");
	}
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
