#ifndef SNIFF_FUNC_H
#define SNIFF_FUNC_H

void print_Ethernet_data(const u_char* mac, int max_i);
void list_Device(pcap_if_t *alldevsp);
void print_Net_Mask(bpf_u_int32 net, bpf_u_int32 mask);

#endif