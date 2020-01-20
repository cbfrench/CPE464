#ifndef TCP_H
#define TCP_H

typedef struct tcp_struct{
   u_char *packet;
   int packet_length;
   u_int16_t src_port;
   u_int16_t dest_port;
   u_int16_t seq_um;
   u_int16_t ack_num;
   u_int16_t window_size;
   u_int16_t checksum;
   u_char pseudoheader[12];
   u_char flags;
} Tcp;

u_int16_t tcp_init(u_char *packet, int packet_size, Tcp **result, u_char *pseudoheader);
void tcp_print(Tcp *t);
void tcp_free(Tcp *t);
int tcp(u_char **data, int *data_length, u_char **pseudoheader);

#endif
