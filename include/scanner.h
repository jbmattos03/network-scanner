#ifndef scanner_h
#define scanner_h

#include <stdbool.h>

void scan_network(char *prefix, char *start_ip, char *end_ip, int timeout);
void scan_ports(char *ip, int *ports, int timeout);

#endif