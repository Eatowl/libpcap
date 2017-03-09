#ifndef SNIFF_HEAD_H
#define SNIFF_HEAD_H

#define ETHER_ADDR_LEN	6
#define ETHER_TYPE_LEN	2

struct ethernetHeader {
 	u_char ether_dhost[ETHER_ADDR_LEN];
 	u_char ether_shost[ETHER_ADDR_LEN];
 	u_char ether_type[ETHER_TYPE_LEN];
} __attribute__((packed));

struct IPHeader {
	u_char  version;
	u_char  len;
	u_char  tos;
	u_short length; 
	u_short id;
	u_short offset;
	u_char  ttl;
	u_char  protocol;
	u_short xsum;
	unsigned long  src;
	unsigned long  dest;
} __attribute__((packed));

#endif
