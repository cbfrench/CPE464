#ifndef ARP_H
#define ARP_H

typedef struct arp_struct Arp;

u_int16_t arp_init(u_char *packet, int packet_length, Arp **result);
void arp_print(Arp a);
void arp_free(Arp **a);
int arp(u_char **packet, int *packet_length);

#endif
