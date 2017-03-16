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
	u_char             iph_ihl:4;
	u_char             iph_ver:4;
	u_char             iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_offset;
	u_char             iph_ttl;
	u_char             iph_protocol;
	unsigned short int iph_chksum;
	u_int              iph_sourceip;
	u_int              iph_destip;
} __attribute__((packed));


struct UDPHeader {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
}__attribute__((packed));

#endif
