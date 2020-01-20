#ifndef HELPER_H
#define HELPER_H

void print_MAC(u_char *input);
void print_IP(u_char *input);
void print_port(u_int16_t input);
char *check_flags(u_int16_t flags, u_int16_t mask);

#endif
