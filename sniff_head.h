#ifndef SNIFF_HEAD_H
#define SNIFF_HEAD_H

#define ETHER_ADDR_LEN	6
#define ETHER_TYPE_LEN	2

struct ethernet {
 	u_char ether_dhost[ETHER_ADDR_LEN];
 	u_char ether_shost[ETHER_ADDR_LEN];
 	u_char ether_type[ETHER_TYPE_LEN];
} __attribute__((packed));

#endif