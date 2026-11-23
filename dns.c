#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"

uint16_t read16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
}

uint32_t read32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void write16(uint8_t *p, uint16_t v) {
    p[0] = v >> 8;
    p[1] = v & 0xFF;
}


void write32(uint8_t*p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = v >> 8;
    p[3] = v & 0xFF;
}

int parse_name(const uint8_t *msg, size_t msglen, size_t offset, char* out, size_t outlen) {
    size_t outpos = 0;
    size_t total = 0;
    int ret = -1;

    while (1) {
        if (offset >= msglen || outlen == 0) return -1;
        int len = msg[offset];
        if (len == 0) {
            out[outpos] = '\0';
            return (ret >= 0) ? ret : (int)(offset + 1); 
        }

        // take care of dns name feature
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= msglen) return -1;
            size_t target = ((len & 0x3F) << 8) | msg[offset + 1];
            if (target >= offset) return -1;
            if (ret < 0) ret = offset + 2;
            offset = target;
            continue;
        }

        if (len > 63 || offset + 1 + len > msglen) return -1;

        total += 1 + len;
        if (total > 255) {return -1;}

        int dot = (outpos > 0) ? 1 : 0;
        if (outpos + dot + len + 1 > outlen) return -1;

        if (dot) out[outpos++] = '.';
        memcpy(out + outpos, msg + offset + 1, len);
        outpos += len;

        offset += 1 + len;

    }
}

int parse_rr(const uint8_t *msg, size_t msglen, size_t offset, rr_t *rr) {
    int off = parse_name(msg, msglen, offset, rr->name, sizeof(rr->name));
    if (off < 0) return -1;

    if ((size_t)off + 10 > msglen) return -1;

    rr->type      = read16(msg + off);
    rr->class     = read16(msg + off + 2);
    rr->ttl       = read32(msg + off + 4);
    rr->rdlength  = read16(msg + off + 8);
    rr->rdata_off = off + 10;

    // exit if data does not fit inside packet
    if (rr->rdata_off + rr->rdlength > msglen) return -1;

    return (int)(rr->rdata_off + rr->rdlength);

}

int encode_name(const char *name, uint8_t *out, size_t outlen) {
    size_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63) return -1;
        if (pos + 1 + len + 1 > outlen) return -1;   // length byte + label + final 0
        out[pos++] = (uint8_t)len;
        memcpy(out + pos, p, len);
        pos += len;
        p += len;
        if (*p == '.') p++;
    }
    out[pos++] = 0;
    return (int)pos;
}

int build_query(uint8_t *out, size_t outlen, uint16_t id, const char *name, uint16_t qtype, uint16_t qclass) {
    if (outlen < 12) return -1;
    size_t pos = 0;
    write16(out + pos, id);      pos += 2;
    write16(out + pos, 0x0000);  pos += 2;
    write16(out + pos, 1);       pos += 2;
    write16(out + pos, 0);       pos += 2;
    write16(out + pos, 0);       pos += 2;
    write16(out + pos, 1);       pos += 2;

    int nlen = encode_name(name, out + pos, outlen - pos);
    if (nlen < 0) return -1;
    pos += nlen;

    if (pos + 4 + 11 > outlen) return -1;
    write16(out + pos, qtype);   pos += 2;
    write16(out + pos, qclass);  pos += 2;

    out[pos++] = 0;                         
    write16(out + pos, 41);      pos += 2;
    write16(out + pos, 4096);    pos += 2;
    write32(out + pos, 0);       pos += 4;
    write16(out + pos, 0);       pos += 2;
    return (int)pos;
}

int find_glue(const uint8_t *msg, size_t len, uint32_t *ip) {
    if (len < 12) return 0;
    int qd = read16(msg + 4), an = read16(msg + 6);
    int ns = read16(msg + 8), ar = read16(msg + 10);
    size_t off = 12;
    char tmp[256];
    rr_t rr;

    for (int i = 0; i < qd; i++) {                 // skip questions
        int r = parse_name(msg, len, off, tmp, sizeof tmp);
        if (r < 0 || (size_t)r + 4 > len) return 0;
        off = r + 4;
    }
    for (int i = 0; i < an; i++) {                 // skip answers
        int r = parse_rr(msg, len, off, &rr);
        if (r < 0) return 0;
        off = r;
    }
    char nsnames[16][256];
    int nn = 0;
    for (int i = 0; i < ns; i++) {                 // collect NS targets
        int r = parse_rr(msg, len, off, &rr);
        if (r < 0) return 0;
        if (rr.type == 2 && nn < 16 &&
            parse_name(msg, len, rr.rdata_off, nsnames[nn], 256) >= 0)
            nn++;
        off = r;
    }
    for (int i = 0; i < ar; i++) {                 // find a matching A record
        int r = parse_rr(msg, len, off, &rr);
        if (r < 0) return 0;
        if (rr.type == 1 && rr.rdlength == 4) {
            for (int k = 0; k < nn; k++) {
                if (strcasecmp(rr.name, nsnames[k]) == 0) {
                    memcpy(ip, msg + rr.rdata_off, 4);
                    return 1;
                }
            }
        }
        off = r;
    }
    return 0;
}

// Returns the length of the final response (in resp), or -1 on failure.
int resolve(int ufd, const char *name, uint16_t qtype, uint16_t qclass,
            uint8_t *resp, size_t cap) {
    struct sockaddr_in server;

    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    inet_pton(AF_INET, "198.41.0.4", &server.sin_addr);     // start at a root server

    for (int hop = 0; hop < 16; hop++) {                    // hop limit
        uint8_t q[512];
        uint16_t qid = rand() & 0xFFFF;
        int qn = build_query(q, sizeof q, qid, name, qtype, qclass);
        if (qn < 0) return -1;

        sendto(ufd, q, qn, 0, (struct sockaddr *)&server, sizeof server);
        ssize_t rn = recvfrom(ufd, resp, cap, 0, NULL, NULL);
        if (rn < 12 || read16(resp) != qid) return -1;      // timeout or bad reply

        uint16_t flags = read16(resp + 2);
        int rcode = flags & 0xF;
        int aa = (flags >> 10) & 1;
        if (rcode != 0 || read16(resp + 6) > 0 || aa)       // error, answer, or authoritative "no data"
            return (int)rn;

        uint32_t ip;
        if (!find_glue(resp, rn, &ip)) return -1;           // glueless referral: handled later
        server.sin_addr.s_addr = ip;
    }
    return -1;
}
