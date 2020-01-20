#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include "helper.h"

#define SRC_B0  0
#define DEST_B0 1
#define DATA    9

typedef struct udp_struct{
   u_char *packet;
   int packet_length;
   u_int16_t src_port;
   u_int16_t dest_port; 
} Udp;

u_int16_t udp_init(u_char *packet, int packet_length, Udp **result){
   Udp *u;
   u = calloc(1, sizeof(Udp));
   if(!u){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   u->packet_length = packet_length;
   u->packet = calloc(u->packet_length, sizeof(u_char));
   if(!u->packet){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(u->packet, packet, u->packet_length);
   u->src_port = ntohs(((u_int16_t *) u->packet)[SRC_B0]);
   u->dest_port = ntohs(((u_int16_t *) u->packet)[DEST_B0]);
   *result = u;
   return 0;
}

void udp_print(Udp *u){
   printf("\n\tUDP Header\n");
   printf("\t\tSource Port: ");
   print_port(u->src_port);
   printf("\t\tDest Port: ");
   print_port(u->dest_port);
}

void udp_free(Udp **u){
   if(!u || !(*u) || !(*u)->packet)
      return;
   free((*u)->packet);
   free(*u);
}

int udp(u_char **data, int *data_length){
   Udp *u;
   udp_init(*data, *data_length, &u);
   udp_print(u);
   udp_free(&u);
   return DATA;
}
