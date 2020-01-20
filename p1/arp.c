#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include "helper.c"

#define MAC_LENGTH     6
#define IP_LENGTH      4
#define OPCODE_B0      6
#define SENDER_MAC_B0  8
#define TARGET_MAC_B0 18
#define SENDER_IP_B0  14
#define TARGET_IP_B0  24

#define DATA    9
#define REQUEST 1
#define REPLY   2

typedef struct arp_struct{
   u_char *packet;
   int packet_length;
   u_int16_t opcode;
   u_char senderMAC[MAC_LENGTH];
   u_char targetMAC[MAC_LENGTH];
   u_char senderIP[IP_LENGTH];
   u_char targetIP[IP_LENGTH];
} Arp;

u_int16_t arp_init(u_char *packet, int packet_length, Arp **result){
   Arp *a;
   a = calloc(1, sizeof(Arp));
   if(!a){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   a->packet_length = packet_length;
   a->packet = calloc(a->packet_length, sizeof(u_char));
   if(!a->packet){
      perror(NULL);
      exit(EXIT_FAILURE);
   }
   memcpy(a->packet, packet, a->packet_length);
   a->opcode = (a->packet[OPCODE_B0] << 8) | (a->packet[OPCODE_B0 + 1]);
   memcpy(a->senderMAC, a->packet + SENDER_MAC_B0, MAC_LENGTH);
   memcpy(a->targetMAC, a->packet + TARGET_MAC_B0, MAC_LENGTH);
   memcpy(a->senderIP, a->packet + SENDER_IP_B0, IP_LENGTH);
   memcpy(a->targetIP, a->packet + TARGET_IP_B0, IP_LENGTH);
   *result = a;
   return a->opcode;
}

void arp_print(Arp *a){
   printf("\n\tARP header\n");
   printf("\t\tOpcode: ");
   switch(a->opcode){
      case REQUEST:
         printf("Request\n");
         break;
      case REPLY:
         printf("Reply\n");
   }
   printf("\t\tSender MAC: ");
   print_MAC(a->senderMAC);
   printf("\t\tSender IP: ");
   print_IP(a->senderIP);
   printf("\t\tTarget MAC: ");
   print_MAC(a->targetMAC);
   printf("\t\tTarget IP: ");
   print_IP(a->targetIP);
   printf("\n");
}

void arp_free(Arp **a){
   if(!a || !(*a) || !(*a)->packet)
      return;
   free((*a)->packet);
   free(*a);
}

int arp(u_char **packet, int *packet_length){
   Arp *a;
   arp_init(*packet, *packet_length, &a);
   arp_print(a);
   arp_free(&a);
   return DATA;
}
