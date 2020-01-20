#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include "helper.h"

#define REQUEST 8
#define REPLY   0
#define DATA    9

void icmp_print(u_char **packet){
   int icmp_type = (int)(**packet);
   char *type = "Request";
   int unknown = 0;
   printf("\n\tICMP Header\n");
   switch(icmp_type){
      case REQUEST:
         break;
      case REPLY:
         type = "Reply";
         break;
      default:
         unknown = 1;
         break;
   }
   if(!unknown){
      printf("\t\tType: %s\n", type);

   }
   else{
      printf("\t\tType: %u\n", icmp_type);
   }
}

int icmp(u_char **packet){
   icmp_print(packet);  
   free(*packet);
   return DATA;
}
