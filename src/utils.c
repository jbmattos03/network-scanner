// Declaração das funções
#include "utils.h"

// Bibliotecas padrão do C
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <regex.h>

// ============== Funções de impressão ==============

void print_banner() {
    printf("====================================================\n");
    printf("||                                                ||\n");
    printf("||             Network Scanner v1.0               ||\n");
    printf("||                                                ||\n");
    printf("====================================================\n");
}

void print_help() {
    printf("Usage: make run ARGS=\"[OPTIONS]\"\n");
    printf("Options:\n");
    printf("  -h, --help\t\t\tShow this help message and exit\n");
    printf("  -v, --version\t\t\tShow program's version number and exit\n");
    printf("  -n, --network\t\t\tScan a network\n");
    printf("  -i, --ip\t\t\tIP address\n");
    printf("  -6, --ipv6\t\t\tUse IPv6\n"); // TODO: Implementar suporte a IPv6
    printf("  -p, --ports\t\t\tScan ports of a host\n");
    printf("  -s, --start\t\t\tStart ip\n");
    printf("  -e, --end\t\t\tEnd ip\n");
    printf("  -t, --timeout\t\t\tTimeout (in seconds)\n");
    printf("  -V, --verbose\t\t\tVerbose mode\n"); // TODO: Implementar modo verbose

    printf("Examples:\n");
    printf("  make run ARGS=\"-n 192.168.1.0/24 -t 30\"\n");
    printf("  make run ARGS=\"-n -s 192.168.1.10 -e 192.168.1.20 -t 10\"\n");
    printf("  make run ARGS=\"-p 192.168.187.1 -t 5\"\n");
}

void print_error(char *message) {
    printf("Error: %s\n", message);
    exit(1); // Saída com erro
}

// ============== Funções de parsing ==============

void parse_cidr(char *cidr, char *ip_address, int *mask) {
    char *token = strtok(cidr, "/"); // Separar o IP da máscara
    strcpy(ip_address, token); // Copiar o IP para a variável ip_address

    token = strtok(NULL, "/"); // Pegar a máscara
    *mask = atoi(token); // Converter a máscara para inteiro
}

// ============== Funções de validação ==============

void validate_ip(char *ip, bool ipv6) {
    regex_t regex;
    char* pattern;

    // Checar se o IP é IPv4 ou IPv6
    if (!ipv6) { // IPv4
        pattern = "^((25[0-5]|(2[0-4]|1[0-9]|[1-9])[0-9])(\\.(?!$)|$)){4}$";
    } else { // IPv6
        pattern = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
    }

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        print_error("Error matching regex");
    }

    int status = regexec(&regex, ip, 0, NULL, 0);
    regfree(&regex); // Liberar espaço na memória

    if (status == 0) {
        print_error("Invalid IP address");
    }
}

void validate_mask(int mask, bool ipv6) {
    if (!ipv6) { // IPv4
        if (mask < 0 || mask > 32) {
            print_error("Invalid mask");
        }
    } 
    else { // IPv6
        if (mask < 0 || mask > 128) {
            print_error("Invalid mask");
        }
    }
}

void validate_port(int port) {
    if (port < 1 || port > 65535) {
        print_error("Invalid port");
    }
}

void validate_timeout(int timeout) {
    if (timeout < 1) {
        print_error("Invalid timeout");
    }
}

// ============== Funções de handling ==============

void handle_timeout(int signal) {
    printf("Scan timed out (signal %d)\n", signal);
    exit(0);
}

// ============== Função de checksum ==============
unsigned short checksum(unsigned short *b, uint16_t len) {
    register long sum = 0; // Soma de 32 bits
    unsigned short result; // Resultado de 16 bits

    // Somar palavras de 16 bits
    while (len > 1) {
        sum += *(unsigned short *) b++; // Somar a palavra de 16 bits
        len -= 2; // Decrementar o tamanho em 2 bytes
    }

    // Se houver um byte restante, somar
    if (len > 0) {
        sum += * (unsigned char *) b;
    }

    // Adicionar carry bits à soma
    while (sum >> 16) { // Verificar carry bits ao deslocar 16 bits para a direita
        // (sum & 0xFFFF) pega os 16 bits menos significativos
        // (sum >> 16) pega os 16 bits mais significativos
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Complementar a soma
    result = ~sum; // Pegar complemento de 1 da soma

    return result;
}