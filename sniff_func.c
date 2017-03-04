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

void print_mac(u_char *mac) {
	for (int i = 0; i < 7; ++i) {
		printf("%02X", mac[i]);
		if (i != 6)
			printf(":");
	}
	printf("\n");
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