#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "helper.h"

#define MAC_LEN     6
#define ARP_TYPE    0x0806
#define IP_TYPE     0x0800
#define HEADER_SIZE 14

typedef struct ethernet_struct{
   u_char *packet;
   int packet_length;
   u_char destMAC[MAC_LEN];
   u_char srcMAC[MAC_LEN];
   u_int16_t type;
   u_char *data;
   int data_length;
} Ethernet;

u_int16_t e_init(struct pcap_pkthdr *head, const u_char *packet, Ethernet **result){
   Ethernet *e;
   e  = calloc(1, sizeof(Ethernet));
   if(!e){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   e->packet_length = head->caplen;
   e->packet = calloc(e->packet_length, sizeof(u_char));
   if(!e->packet){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(e->packet, packet, e->packet_length);
   memcpy(e->destMAC, packet, MAC_LEN);
   memcpy(e->srcMAC, packet + MAC_LEN, MAC_LEN);
   e->type = ntohs(((u_int16_t *) e->packet)[MAC_LEN]);
   e->data_length = e->packet_length - HEADER_SIZE;
   e->data = calloc(e->data_length, sizeof(u_char));
   if(!e->data){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(e->data, e->packet + HEADER_SIZE, e->data_length);
   *result = e;
   return e->type;
}

void e_print(Ethernet *e){
   printf("\tEthernet Header\n");
   printf("\t\tDest MAC: ");
   print_MAC(e->destMAC);
   printf("\t\tSource MAC: ");
   print_MAC(e->srcMAC);  
   printf("\t\tType: ");
   switch(e->type){
      case ARP_TYPE:
         printf("ARP");
         break;
      case IP_TYPE:
         printf("IP");
         break;
      default:
         printf("Unknown");
         break;
   }
   printf("\n");
}

void e_free(Ethernet **e){
   if(!e || !(*e) || !(*e)->packet)
      return;
   free((*e)->packet);
   free((*e)->data);
   free(*e);
}

u_char * e_data(Ethernet *e){
   u_char *data;
   data = calloc(e->data_length, sizeof(u_char));
   if(!data){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(data, e->data, e->data_length);
   return data;
}

int e_data_length(Ethernet *e){
   return e->data_length;
}

int ethernet(struct pcap_pkthdr *head, const u_char *packet, u_char **data, int *data_length){
   Ethernet *e;
   u_int16_t contained_type = e_init(head, packet, &e);
   e_print(e);
   *data = e_data(e);
   *data_length = e_data_length(e);
   e_free(&e);
   switch(contained_type){
      case ARP_TYPE:
         return 0;
      case IP_TYPE:
         return 1;
      default:
         return -1;
   }
}  
