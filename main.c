#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	if ((dev = pcap_lookupdev(errbuf)) == NULL) {
		perror("pcap_lookupdev error");
		exit(1);
	}
	printf("DEV: %s\n", dev);
	return 0;
}
