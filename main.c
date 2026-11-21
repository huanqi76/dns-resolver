#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "dns.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    printf("Socket number: %d\n", fd);

    struct sockaddr_in addr; // defined in netinet/in.h
    memset(&addr, 0, sizeof(addr)); // zero out address. different from {0} initializer
                                    // can be used anywhere, not only on stack
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(5300); // macOS runs the mDNSResponder daemon on UDP port 5353 by default

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("listening on port 5300\n");

    // block program until packet arrives
    uint8_t buf[4096];
    struct sockaddr_in  client;
    socklen_t clen = sizeof(client);

    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client, &clen);
    
    // print packet
    for (int i = 0; i < n; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");

    // 3b d3                    ID
    // 01 20                    flags: RD=1, AD=1
    // 00 01                    1 question
    // 00 00 00 00              0 answers, 0 authority
    // 00 01                    1 additional record (EDN)
    // 07 65 78 61 6d 70 6c 65  "example"
    // 03 63 6f 6d              "com"
    // 00                       end of name
    // 00 01                    type A
    // 00 01                    class IN
    // 00                       OPT name = root
    // 00 29                    type 41 (OPT)
    // 10 00                    UDP payload size
    // 00 00 00 00
    // 00 00                    

    printf("received %zd bytes\n", n);

    uint16_t ID = read16(buf);
    uint16_t flags = read16(buf + 2);
    uint16_t QDCOUNT = read16(buf + 4);
    uint16_t ANCOUNT = read16(buf + 6);
    uint16_t NSCOUNT = read16(buf + 8); 
    uint16_t ARCOUNT = read16(buf + 10);

    char QR = (flags >> 15) & 1;
    uint16_t opcode = (flags >> 11) & 0xF;  // right data type?
    char AA = (flags >> 10) & 1;
    char TC = (flags >> 9) & 1;
    char RD = (flags >> 8) & 1;
    char RA = (flags >> 7) & 1;
    uint16_t RCODE = flags & 0xF;


    return 0;
}