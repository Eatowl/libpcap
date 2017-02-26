#include <pcap.h>
#include <stdlib.h>

int main() {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);
	printf("DEV: %s\n", dev);
	return 0;
}
