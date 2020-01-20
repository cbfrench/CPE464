#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include "checksum.h"
#include "helper.h"

#define TOS_B0             1
#define TTL_B0             8
#define PROTOCOL_B0        9
#define IHL_MULT           4
#define CHECKSUM_B0        5
#define SRC_IP_B0         12
#define DEST_IP_B0        16
#define IP_LENGTH          4
#define PSEUDOHEADER_SIZE 12

#define TCP_PROTOCOL   6
#define UDP_PROTOCOL  17
#define ICMP_PROTOCOL  1

typedef struct ip_struct{
   u_char *packet;
   int packet_length;
   u_char tos;
   u_char ttl;
   u_char ihl;
   u_char protocol;
   u_int16_t total_length;
   u_int16_t checksum;
   u_char srcIP[4];
   u_char destIP[4];
   u_char *data;
   int data_length;
} Ip;

u_int16_t ip_init(u_char *packet, int packet_length, Ip **result){
   Ip *i;
   i = calloc(1, sizeof(Ip));
   if(!i){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   i->packet_length = packet_length;
   i->packet = calloc(i->packet_length, sizeof(u_char));
   if(!i->packet){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(i->packet, packet, i->packet_length);
   i->tos = i->packet[TOS_B0];
   i->ttl = i->packet[TTL_B0];
   i->protocol = i->packet[PROTOCOL_B0];
   i->ihl = IHL_MULT * (i->packet[0] & 0x0F);
   i->total_length = ntohs(((u_int16_t *) packet)[1]);
   i->checksum = in_cksum((u_int16_t *) i->packet, i->ihl);
   memcpy(i->srcIP, i->packet + SRC_IP_B0, IP_LENGTH);
   memcpy(i->destIP, i->packet + DEST_IP_B0, IP_LENGTH);
   i->data_length = i->total_length - i->ihl;
   i->data = calloc(i->data_length, sizeof(u_char));
   if(!i->data){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(i->data, i->packet + i->ihl, i->data_length);     
   *result = i;
   return 0;
}

void check_against_checksum(Ip *i){
   char *pre = "Inc";
   u_int16_t correct_checksum = ((u_int16_t *) i->packet)[CHECKSUM_B0];
   if(!i->checksum){
      pre = "C";
   }
   printf("\t\tChecksum: %sorrect (0x%x)\n", pre, correct_checksum);
}

void ip_print(Ip *i){
   printf("\n\tIP Header\n");
   printf("\t\tHeader Len: %d (bytes)\n", i->ihl);
   printf("\t\tTOS: 0x%x\n", i->tos);
   printf("\t\tTTL: %d\n", i->ttl);
   printf("\t\tIP PDU Len: %d (bytes)\n", i->total_length);
   printf("\t\tProtocol: ");
   switch(i->protocol){
      case TCP_PROTOCOL:
         printf("TCP\n");
         break;
      case UDP_PROTOCOL:
         printf("UDP\n");
         break;
      case ICMP_PROTOCOL:
         printf("ICMP\n");
         break;
      default:
         printf("Unknown\n");
         break;
   }
   check_against_checksum(i);
   printf("\t\tSender IP: ");
   print_IP(i->srcIP);
   printf("\t\tDest IP: ");
   print_IP(i->destIP);
}

u_char *ip_data(Ip *i){
   u_char *data;
   data = calloc(i->data_length, sizeof(u_char));
   if(!data){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(data, i->data, i->data_length);
   return data;
}

int ip_data_length(Ip *i){
   return i->data_length;
}

int ip_protocol(Ip *i){
   return i->protocol;
}

u_char *ip_generate_pseudoheader(Ip *i){
   u_char *result;
   result = calloc(PSEUDOHEADER_SIZE, sizeof(u_char));
   if(!result){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(result, i->srcIP, IP_LENGTH);
   memcpy(result + IP_LENGTH, i->destIP, IP_LENGTH);
   result[9] = i->protocol;
   result[10] = (i->data_length & 0xFF00) >> 8;
   result[11] = i->data_length & 0x00FF;
   return result;
}

void ip_free(Ip **i){
   if(!i || !(*i) || !(*i)->packet)
      return;
   free((*i)->packet);
   free((*i)->data);
   free(*i);
}

int ip(u_char **data, int *data_length, u_char **pseudoheader){
   Ip *i;
   ip_init(*data, *data_length, &i);
   ip_print(i);
   free(*data);
   *data = ip_data(i);
   *data_length = ip_data_length(i);
   *pseudoheader = ip_generate_pseudoheader(i);
   ip_free(&i);
   switch(ip_protocol(i)){
      case TCP_PROTOCOL:
         return 2;
      case UDP_PROTOCOL:
         return 3;
      case ICMP_PROTOCOL:
         return 4;
      default:
         return -1;
   }
}
