#ifndef utils_h
#define utils_h

#include <stdbool.h>
#include <stdint.h>

// Funções de impressão
void print_banner();
void print_help();
void print_error(char *message);

// Funções de parsing
void parse_cidr(char *cidr, char *ip_address, int *mask);

// Funções de validação
void validate_ip(char *ip, bool ipv6);
void validate_mask(int mask, bool ipv6);
void validate_port(int port);
void validate_timeout(int timeout);

// Funções de handling
void handle_timeout(int signal);

// Função de checksum
unsigned short checksum(unsigned short *b, uint16_t len);

#endif