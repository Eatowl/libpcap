#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
	pcap_if_t *alldevsp, *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
		perror("pcap_findalldevs error");
		exit(1);
	}
	for (device = alldevsp; device != NULL; device = device->next) {
		printf("DEVICE: %s - %s \n", device->name, device->description);
	}
	char work_dev[] = "eth0";
	pcap_t *handle;
	if ((handle = pcap_open_live(work_dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		perror("pcap_open_live error");
		exit(1);
	}
	return 0;
}
