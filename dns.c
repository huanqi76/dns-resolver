#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dns.h"

uint16_t read16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
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

    while (1) {
        if (offset >= msglen || outlen == 0) return -1;
        int len = msg[offset];
        if (len == 0) {
            out[outpos] = '\0';
            return offset + 1;
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