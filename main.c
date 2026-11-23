#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "dns.h"
#include "cache.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#define EDNS_SIZE 4096 
#define QUERY_BUDGET_MS 4000

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);    // fd takes queries from clients
    if (fd < 0) {perror("socket"); return 1;}

    printf("Socket number: %d\n", fd);

    struct sockaddr_in addr; 
    memset(&addr, 0, sizeof(addr));

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

    // upstream
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);   // ufd talks to the server forwarded to
    if (ufd < 0) {perror("socket"); return 1;}

    struct timeval tv; 
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(ufd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // struct sockaddr_in upstream;
    // memset(&upstream, 0, sizeof(upstream));
    // upstream.sin_family = AF_INET;
    // upstream.sin_port = htons(53);  // port 53 is where 8.8.8.8 listens
    // inet_pton(AF_INET, "198.41.0.4", &upstream.sin_addr);
    // inet_pton(AF_INET, "8.8.8.8", &upstream.sin_addr);  // Google's DNS server
    // inet_pton(AF_INET, "192.0.2.1", &upstream.sin_addr);     // belongs to a block of addresses that is reserved for documentation

    // block program until packet arrives
    uint8_t buf[4096];
    struct sockaddr_in  client;
    socklen_t clen = sizeof(client);

    srand(time(NULL));
    
    while (1) {
        clen = sizeof(client);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client, &clen);

        if (n < 12) continue;
        
        // print packet
        for (int i = 0; i < n; i++) {
            printf("%02x ", buf[i]);
        }
        printf("------------------------\n");

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
        if ((flags >> 15) & 1) continue;                         // QR must be 0 (a query)
        if (((flags >> 11) & 0xF) != 0) continue;                // opcode must be QUERY
        uint8_t RD = (flags >> 8) & 1;
        if (read16(buf + 4) != 1) continue;                      // exactly one question
        if (read16(buf + 6) != 0 || read16(buf + 8) != 0) continue;   // no answer/authority records in a query

        // parse name
        char name[256];
        int next = parse_name(buf, n, 12, name, sizeof(name));
        if (next < 0) {printf("bad name\n"); continue;}
        printf("name: %s, next offset: %d\n", name, next);

        if (next + 4 > n) continue;
        uint16_t qtype = read16(buf + next);
        uint16_t qclass = read16(buf + next + 2);
        printf("qtype: %d, qclass: %d\n", qtype, qclass);

        // hardcoded response
        // uint8_t out[512]; 
        // size_t pos = 0;
        // uint16_t rflags = 0x8000      // QR = 1: this is a response
        //         | (opcode << 11)      
        //         | (RD << 8)           
        //         | 0x0080;             // RA = 1: we offer recursion
        // write16(out + pos, ID);         pos += 2;
        // write16(out + pos, rflags);     pos += 2;
        // write16(out + pos, QDCOUNT);    pos += 2;
        // write16(out + pos, 1);          pos += 2;   // adding one answer count
        // write16(out + pos, NSCOUNT);    pos += 2;
        // write16(out + pos, 0);    pos += 2;
        // size_t qlen = (next + 4) - 12;
        // memcpy(out + pos, buf + 12, qlen);
        // pos += qlen;
        // write16(out + pos, 0xC00C);     pos += 2;
        // write16(out + pos, 1);          pos += 2;
        // write16(out + pos, 1);          pos += 2;
        // write32(out + pos, 60);         pos += 4;
        // write16(out + pos, 4);          pos += 2;
        // out[pos++] = 1;
        // out[pos++] = 2;
        // out[pos++] = 3;
        // out[pos++] = 4;
        // sendto(fd, out, pos, 0, (struct sockaddr *)&client, clen);

        size_t qend = (size_t)next + 4;                          // end of the question section
        const uint8_t *question = buf + 12;
        size_t qlen = qend - 12;

        // edns
        int has_opt, edns_version;
        uint16_t udp_size;
        if (parse_query_edns(buf, n, qend, &has_opt, &udp_size, &edns_version) < 0) {
            printf("bad additional section\n");
            continue;
        }

        uint8_t small[512];

        if (has_opt && edns_version != 0) { 
            int en = build_reply_header_only(small, sizeof small, ID, RD, question, qlen,
                                             0, 0, 1, 1, EDNS_SIZE);
            if (en > 0) sendto(fd, small, en, 0, (struct sockaddr *)&client, clen);
            continue;
        }

        uint8_t resp[4096];
        int rn = cache_get(name, qtype, qclass, resp, sizeof(resp));
        if (rn > 0) {
            printf("cache hit\n");
        } else {
            rn = resolve(ufd, name, qtype, qclass, resp, sizeof(resp), 0, now_ms() + QUERY_BUDGET_MS);
            if (rn < 0) {
                printf("resolve failed, sending SERVFAIL\n");
                int en = build_reply_header_only(small, sizeof small, ID, RD, question, qlen,
                                                 2, 0, has_opt, 0, EDNS_SIZE);
                if (en > 0) sendto(fd, small, en, 0, (struct sockaddr *)&client, clen);
                continue;
            }
            rn = strip_opt(resp, rn);
            cache_put(name, qtype, qclass, resp, rn);
        }

        write16(resp, ID); 
        uint16_t rf = read16(resp + 2);
        rf = (rf & 0x020F)
           | 0x8000
           | (RD << 8)
           | 0x0080;
        write16(resp + 2, rf);

        int out_n = rn;
        if (has_opt) {                           // answer EDNS with our own OPT record
            int an = append_opt(resp, out_n, sizeof(resp), EDNS_SIZE);
            if (an > 0) out_n = an;
        }

        size_t limit = has_opt ? udp_size : 512; // the biggest UDP reply this client accepts
        if ((size_t)out_n > limit) {             // too big: send a truncated reply (TC=1)
            printf("reply of %d bytes exceeds client limit %zu, truncating\n", out_n, limit);
            int en = build_reply_header_only(small, sizeof small, ID, RD, question, qlen,
                                             rf & 0xF, 1, has_opt, 0, EDNS_SIZE);
            if (en > 0) sendto(fd, small, en, 0, (struct sockaddr *)&client, clen);
            continue;
        }
        printf("reply: %d bytes, TC=%d\n", out_n, (rf >> 9) & 1);

        sendto(fd, resp, out_n, 0, (struct sockaddr *)&client, clen);
    }

    return 0;
}