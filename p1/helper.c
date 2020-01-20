#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAC_LENGTH 6
#define IP_LENGTH  4

#define HTTP 80

void print_MAC(u_char *input){
   int i;
   for(i = 0; i < MAC_LENGTH; i++){
      if(i){
         printf(":");
      }
      printf("%x", input[i]);
   }
   printf("\n");
}

void print_IP(u_char *input){
   int i;
   for(i = 0; i < IP_LENGTH; i++){
      if(i){
         printf(".");
      }
      printf("%d", input[i]);
   }
   printf("\n");
}

void print_port(u_int16_t input){
   switch(input){
      case HTTP:
         printf(" HTTP\n");
         break;
      default:
         printf(": %u\n", input);
         break;
   } 
}

char *check_flags(u_int16_t flags, u_int16_t mask){
   return flags & mask ? "Yes" :  "No";
}
