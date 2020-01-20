#ifndef IP_H
#define IP_H

typedef struct ip_struct Ip;

u_int16_t ip_init(u_char *packet, int packet_length, Ip **result);
void check_against_checksum(Ip *i);
void ip_print(Ip *i);
u_char *ip_data(Ip *i);
int ip_data_length(Ip *i);
int ip_protocol(Ip *i);
u_char *ip_generate_psuedoheader(Ip *i);
void ip_free(Ip **i);
int ip(u_char **packet, int *packet_length, u_char **pseudoheader);

#endif
