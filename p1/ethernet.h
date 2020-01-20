#ifndef ETHERNET_H
#define ETHERNET_H

typedef struct ethernet_struct Ethernet;

int e_init(struct pcap_pkthdr *head, const u_char *packet, Ethernet **result);
void e_print(Ethernet *e);
int ethernet(struct pcap_pkthdr *head, const u_char *packet, u_char **data, int *data_length);

#endif
