#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include "checksum.h"
#include "helper.h"

#define PSEUDOHEADER_SIZE  12
#define SRC_PORT_B0         0
#define DEST_PORT_B0        1
#define SEQ_B0              1
#define ACK_B0              2
#define ACK_FLAG_B0        13
#define ACK_FLAG         0x10
#define WINDOW_B0           7
#define FLAGS_B0           13
#define SYN               0x2
#define RST               0x4
#define FIN               0x1
#define DATA                9

typedef struct tcp_struct{
   u_char *packet;
   int packet_length;
   u_int16_t src_port;
   u_int16_t dest_port;
   u_int32_t seq_num;
   u_int32_t ack_num;
   u_char ack_flag;
   u_int16_t window_size;
   u_int16_t checksum;
   u_char pseudoheader[PSEUDOHEADER_SIZE];
   u_char flags;
} Tcp;

u_int16_t tcp_init(u_char *packet, int packet_length, Tcp **result, u_char *pseudoheader){
   Tcp *t;
   u_char *check;
   t = calloc(1, sizeof(Tcp));
   if(!t){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   t->packet_length = packet_length;
   t->packet = calloc(packet_length, sizeof(u_char));
   if(!t->packet){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(t->packet, packet, t->packet_length);
   memcpy(t->pseudoheader, pseudoheader, PSEUDOHEADER_SIZE);
   t->pseudoheader[PSEUDOHEADER_SIZE - 1] = packet_length & 0x00FF;
   t->src_port = ntohs(((u_int16_t *) t->packet)[SRC_PORT_B0]);
   t->dest_port = ntohs(((u_int16_t *) t->packet)[DEST_PORT_B0]);
   t->seq_num = ntohl(((u_int32_t *) t->packet)[SEQ_B0]);
   t->ack_num = ntohl(((u_int32_t *) t->packet)[ACK_B0]);
   t->ack_flag = t->packet[ACK_FLAG_B0];
   t->window_size = ntohs(((u_int16_t *) t->packet)[WINDOW_B0]);
   t->flags = t->packet[FLAGS_B0];
   check = calloc(t->packet_length + PSEUDOHEADER_SIZE, sizeof(u_char));
   if(!check){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(check, t->pseudoheader, PSEUDOHEADER_SIZE);
   memcpy(check + PSEUDOHEADER_SIZE, t->packet, t->packet_length);
   t->checksum = in_cksum((u_int16_t *) check, t->packet_length + PSEUDOHEADER_SIZE);
   *result = t;
   return 0;
}

void check_against_checksum_tcp(Tcp *t){
   char *pre = "Inc";
   u_int16_t correct_checksum = ntohs(((u_int16_t *) t->packet)[8]);
   if(!t->checksum){
      pre = "C";
   }
   printf("\t\tChecksum: %sorrect (0x%x)\n", pre, correct_checksum);
}

void tcp_print(Tcp *t){
   printf("\n\tTCP Header\n");
   printf("\t\tSource Port: ");
   print_port(t->src_port);
   printf("\t\tDest Port: ");
   print_port(t->dest_port);
   printf("\t\tSequence Number: %u\n", t->seq_num);
   t->ack_flag & ACK_FLAG ? 
      printf("\t\tACK Number: %u\n", t->ack_num) :
      printf("\t\tACK Number: <not valid>\n");
   printf("\t\tACK Flag: %s\n", check_flags(t->ack_flag, ACK_FLAG));     
   printf("\t\tSYN Flag: %s\n", check_flags(t->flags, SYN));
   printf("\t\tRST Flag: %s\n", check_flags(t->flags, RST));
   printf("\t\tFIN Flag: %s\n", check_flags(t->flags, FIN));
   printf("\t\tWindow Size: %u\n", t->window_size);
   check_against_checksum_tcp(t);  
}

void tcp_free(Tcp **t){
   if(!t || !(*t) || !(*t)->packet)
      return;
   free((*t)->packet);
   free(*t);
}

int tcp(u_char **data, int *data_length, u_char **pseudoheader){
   Tcp *t;
   tcp_init(*data, *data_length, &t, *pseudoheader);
   tcp_print(t);
   tcp_free(&t);
   return DATA;
}
