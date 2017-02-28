#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void listDevice(pcap_if_t *alldevsp);
void connectDevice(pcap_if_t *alldevsp, int number);

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

void connectDevice(pcap_if_t *alldevsp, int number) {
	pcap_if_t *device;
	pcap_t *handle;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	int count = 0;
	device = alldevsp;
	while (device != NULL) {
		if (number == count) {
			if ((handle = pcap_open_live(device->name, 65536, 1, 0, errbuf)) == NULL) {
				perror("pcap_open_live error");
				exit(1);
			} else {
				printf("\nConnect to %s - done\n", device->name);
				pcap_lookupnet(device->name, &net, &mask, errbuf);

			}
		}
		device = device->next;
		++count;
	}
}
