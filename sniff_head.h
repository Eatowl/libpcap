#ifndef SNIFF_HEAD_H
#define SNIFF_HEAD_H

#define ETHER_ADDR_LEN	6

struct ethernet {
 	u_char ether_dhost[ETHER_ADDR_LEN];
 	u_char ether_shost[ETHER_ADDR_LEN];
 	u_short ether_type;
} __attribute__((packed));

#endif