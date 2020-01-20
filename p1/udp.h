#ifndef UDP_H
#define UDP_H

typedef struct udp_struct Udp;

u_int16_t udp_init(u_char *packet, int packet_length, Udp **result);
void udp_print(Udp *u);
void udp_free(Udp **u);
int udp(u_char **data, int *data_length);

#endif
