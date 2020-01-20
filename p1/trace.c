#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#define UNKNOWN -1
#define ARP      0
#define IP       1
#define TCP      2
#define UDP      3
#define ICMP     4
#define DATA     9

int main(int argc, char *argv[]){
   pcap_t *pcap_file;
   struct pcap_pkthdr *head;
   const u_char *packet;
   u_char *data;
   int data_length;
   char errorBuffer[PCAP_ERRBUF_SIZE];
   int count = 0;
   int contained_type;
   u_char *pseudoheader;
   if(argc < 2){
      fprintf(stderr, "Usage: trace [input_file]\n");
      exit(EXIT_FAILURE);
   }
   pcap_file = pcap_open_offline(argv[1], errorBuffer);
   if(pcap_file == NULL){
      fprintf(stderr, errorBuffer);
      exit(EXIT_FAILURE);
   }
   while(pcap_next_ex(pcap_file, &head, &packet) == 1){
      printf("\nPacket number: %d  Frame Len: %d\n\n", ++count, head->caplen); 
      contained_type = ethernet(head, packet, &data, &data_length);
      while(contained_type != UNKNOWN && contained_type != DATA){
         switch(contained_type){
            case ARP:
               contained_type = arp(&data, &data_length);
               break;
            case IP:
               contained_type = ip(&data, &data_length, &pseudoheader);
               break;
            case TCP:
               contained_type = tcp(&data, &data_length, &pseudoheader);
               break;
            case UDP:
               contained_type = udp(&data, &data_length);
               break;
            case ICMP:
               contained_type = icmp(&data);
            default:
               break;
         }
      }
   }
   pcap_close(pcap_file);
   return 0;
}
