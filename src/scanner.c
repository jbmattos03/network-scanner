// Declaração das funções
#include "scanner.h" 
#include "utils.h"

// Bibliotecas padrão do C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Bibliotecas padrão do C: timeout
#include <unistd.h> // Controle de processos
#include <signal.h> // Tratamento de sinais

// Bibliotecas de rede
#include <arpa/inet.h> // Conversão de endereços de rede
#include <sys/socket.h> // Criação de sockets
#include <netinet/ip.h> // Criação de pacotes IP
#include <netinet/ip_icmp.h> // Criação de pacotes ICMP

// ================= Função de escaneamento de rede =================

void scan_network(char *prefix, char *start_ip, char *end_ip, int timeout) {
    // Variáveis
    int sockfd; // Socket
    struct sockaddr_in dest; // Endereço de destino
    struct iphdr *ip_header; // Cabeçalho IP
    struct icmphdr *icmp_header; // Cabeçalho ICMP
    char packet[4096]; // Pacote
    int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr); // Tamanho do pacote
    char recv_buffer[4096]; // Buffer para receber pacotes
    struct sockaddr_in recv_addr; // Endereço de origem do pacote recebido
    socklen_t addr_len = sizeof(recv_addr);

    // Variáveis relacionadas ao prefixo
    char *ip_address; // Endereço IP
    int *mask; // Máscara

    // Pegar HOST_IP
    char *host_ip = getenv("HOST_IP");

    // Inicializar tratamento de sinais
    signal(SIGALRM, handle_timeout);

    // Criar socket para comunicação ICMP
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");

        // Liberar memória alocada e fechar o socket
        if (prefix) {
            free(ip_address);
            free(mask);
        }

        close(sockfd);

        // Encerrar o programa com erro
        exit(1);
    }

    // Configurar endereço de destino
    dest.sin_family = AF_INET; // IPv4
    dest.sin_port = 0; // ICMP não usa porta

    // Configurar cabeçalho IP
    ip_header = (struct iphdr *) packet;
    ip_header->ihl = 5; // Internet Header Length = 5; 20 bytes
    ip_header->version = 4; // IPv4
    ip_header->tos = 0; // Type of Service = 0
    ip_header->tot_len = packet_size; // Tamanho total do pacote
    ip_header->id = htons(54321); // ID do pacote
    ip_header->frag_off = 0; // Fragment Offset = 0; Sem fragmentação
    ip_header->ttl = 255; // Time to Live = 255
    ip_header->protocol = IPPROTO_ICMP; // Protocolo = ICMP
    ip_header->check = checksum((unsigned short *) packet, ip_header->tot_len); // Calcular checksum

    // Configurar endereço de origem
    if (host_ip) {
        ip_header->saddr = inet_addr(host_ip);
    } 
    else {
        ip_header->saddr = INADDR_ANY;
    }

    // Configurar cabeçalho ICMP
    icmp_header = (struct icmphdr *) (packet + sizeof(struct iphdr));
    icmp_header->type = ICMP_ECHO; // Tipo = ECHO
    icmp_header->code = 0; // Código = 0
    icmp_header->un.echo.id = htons(1234); // ID do ECHO
    icmp_header->un.echo.sequence = htons(1); // Sequência do ECHO
    icmp_header->checksum = checksum((unsigned short *) icmp_header, sizeof(struct icmphdr)); // Calcular checksum

    // Começar scan
    if (start_ip && end_ip) {
        // Validar ip e máscara
        validate_ip(start_ip, false);
        validate_ip(end_ip, false);

        // Converter start e end para representações numéricas
        unsigned long start = ntohl(inet_addr(start_ip));
        unsigned long end = ntohl(inet_addr(end_ip));

        alarm(timeout); // Iniciar alarme

        // Enviar pacote ICMP
        for (unsigned long ip = start; ip <= end; ip++) {
            dest.sin_addr.s_addr = htonl(ip);
            sendto(sockfd, packet, packet_size, 0, (struct sockaddr *) &dest, sizeof(dest));
            printf("Sending packet to %s\n", inet_ntoa(dest.sin_addr));

            // Receber resposta ICMP
            if (recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *) &recv_addr, &addr_len) > 0) {
                struct iphdr *recv_ip_header = (struct iphdr *) recv_buffer;
                struct icmphdr *recv_icmp_header = (struct icmphdr *) (recv_buffer + (recv_ip_header->ihl * 4));

                if (recv_icmp_header->type == ICMP_ECHOREPLY) {
                    printf("Received reply from %s\n", inet_ntoa(recv_addr.sin_addr));
                } 
                else { // Resposta não é um ECHO REPLY
                    printf("No reply from %s\n", inet_ntoa(dest.sin_addr));
                }
            } 
            else { // Não houve resposta
                printf("No reply from %s\n", inet_ntoa(dest.sin_addr));
            }
        }
    }
    else if (prefix) {
        // Alocar espaço na memória para o endereço IP e a máscara
        ip_address = malloc(sizeof(char) * 16); // Endereço IP
        mask = malloc(sizeof(int)); // Máscara

        // Separar endereço ip da máscara
        parse_cidr(prefix, ip_address, mask);

        // Validar ip e máscara
        validate_ip(ip_address, false);
        validate_mask(*mask, false);

        alarm(timeout); // Iniciar alarme

        // Enviar pacote ICMP
        for (int i=0; i < (1 << (32 - *mask)); i++) {
            dest.sin_addr.s_addr = htonl(ntohl(inet_addr(ip_address)) + i);
            sendto(sockfd, packet, packet_size, 0, (struct sockaddr *) &dest, sizeof(dest));
            printf("Sending packet to %s\n", inet_ntoa(dest.sin_addr));

            // Receber resposta ICMP
            if (recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *) &recv_addr, &addr_len) > 0) {
                struct iphdr *recv_ip_header = (struct iphdr *) recv_buffer;
                struct icmphdr *recv_icmp_header = (struct icmphdr *) (recv_buffer + (recv_ip_header->ihl * 4));

                if (recv_icmp_header->type == ICMP_ECHOREPLY) {
                    printf("Received reply from %s\n", inet_ntoa(recv_addr.sin_addr));
                } 
                else { // Resposta não é um ECHO REPLY
                    printf("No reply from %s\n", inet_ntoa(dest.sin_addr));
                }
            } 
            else { // Não houve resposta
                printf("No reply from %s\n", inet_ntoa(dest.sin_addr));
            }
        }
    }
    else {
        print_error("Invalid arguments");
    }

    // Liberar espaço na memória e fechar o socket
    free(ip_address);
    free(mask);
    close(sockfd);
}

// ================= Função de escaneamento de portas =================