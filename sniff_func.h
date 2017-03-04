#ifndef SNIFF_FUNC_H
#define SNIFF_FUNC_H

void print_mac(u_char *mac);
void listDevice(pcap_if_t *alldevsp);
void print_Net_Mask(bpf_u_int32 net, bpf_u_int32 mask);

#endif