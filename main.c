#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "dns.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    printf("Socket number: %d\n", fd);

    struct sockaddr_in addr; // defined in netinet/in.h
    memset(&addr, 0, sizeof(addr)); // zero out address. different from {0} initializer
                                    // can be used anywhere, not only on stack

    int port = 53;
    if (argc > 1) port = atoi(argv[1]); 
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port); // macOS runs the mDNSResponder daemon on UDP port 5353 by default

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("listening on port %d\n", port);

    // block program until packet arrives
    uint8_t buf[4096];
    struct sockaddr_in  client;
    socklen_t clen = sizeof(client);
    
    while (1) {
        clen = sizeof(client);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client, &clen);

        if (n < 12) continue;
        
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

        uint8_t QR = (flags >> 15) & 1;
        if (QR != 0) continue;

        uint16_t opcode = (flags >> 11) & 0xF; 
        uint8_t AA = (flags >> 10) & 1;
        uint8_t TC = (flags >> 9) & 1;
        uint8_t RD = (flags >> 8) & 1;
        uint8_t RA = (flags >> 7) & 1;
        uint16_t RCODE = flags & 0xF;

        // parse name
        char name[256];
        int next = parse_name(buf, n, 12, name, sizeof(name));
        if (next < 0) {printf("bad name\n"); continue;}
        printf("name: %s, next offset: %d\n", name, next);

        if (next + 4 > n) continue;
        uint16_t qtype = read16(buf + next);
        uint16_t qclass = read16(buf + next + 2);
        printf("qtype: %d, qclass: %d\n", qtype, qclass);

        uint8_t out[512];
        size_t pos = 0;

        uint16_t rflags = 0x8000      // QR = 1: this is a response
                | (opcode << 11)      
                | (RD << 8)           
                | 0x0080;             // RA = 1: we offer recursion

        write16(out + pos, ID);         pos += 2;
        write16(out + pos, rflags);     pos += 2;
        write16(out + pos, QDCOUNT);    pos += 2;
        write16(out + pos, 1);          pos += 2;   // adding one answer count
        write16(out + pos, NSCOUNT);    pos += 2;
        write16(out + pos, 0);    pos += 2;

        size_t qlen = (next + 4) - 12;
        memcpy(out + pos, buf + 12, qlen);
        pos += qlen;

        write16(out + pos, 0xC00C);     pos += 2;
        write16(out + pos, 1);          pos += 2;
        write16(out + pos, 1);          pos += 2;
        write32(out + pos, 60);         pos += 4;
        write16(out + pos, 4);          pos += 2;
        out[pos++] = 1;
        out[pos++] = 2;
        out[pos++] = 3;
        out[pos++] = 4;
        sendto(fd, out, pos, 0, (struct sockaddr *)&client, clen);
    }

    return 0;
}