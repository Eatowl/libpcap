#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_BUF 32

void listDevice(pcap_if_t *alldevsp);

int main() {
	pcap_if_t *alldevsp, *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		perror("pcap_findalldevs error");
		exit(1);
	}
	listDevice(alldevsp);
	pcap_t *handle;
	int number, count = 0;
	printf("\nInput number device: ");
	if ((scanf("%d", &number)) == -1) {
		perror("scanf error");
		exit(1);
	}
	device = alldevsp;
	while (device != NULL) {
		if (number == count) {
			if ((handle = pcap_open_live(device->name, 65536, 1, 0, errbuf)) == NULL) {
				perror("pcap_open_live error");
				exit(1);
			} else {
				printf("Connect to %s - done\n", device->name);
			}
		}
		device = device->next;
		++count;
	}
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
