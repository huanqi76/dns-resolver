#ifndef DNS_H
#define DNS_H

#include <stdint.h>

typedef struct {
    char        name[256];
    uint16_t    type;
    uint16_t    class;
    uint32_t    ttl;
    uint16_t    rdlength;
    size_t      rdata_off;
} rr_t;

uint16_t read16(const uint8_t *p);
uint32_t read32(const uint8_t *p);

void write16(uint8_t *p, uint16_t v);
void write32(uint8_t*p, uint32_t v);

/* 
 * Reads a name starting at msg[offset]. Write it into out. 
 * Returns the offset of the first byte after the name, or -1 if invalid
 */

int parse_name(const uint8_t *msg, size_t msglen, size_t offset, char* out, size_t outlen);
int parse_rr(const uint8_t *msg, size_t msglen, size_t offset, rr_t *rr);

// Returns bytes written, or -1 if invalid / doesn't fit.
int encode_name(const char *name, uint8_t *out, size_t outlen);

// Returns the query length, or -1.
int build_query(uint8_t *out, size_t outlen, uint16_t id, const char *name, uint16_t qtype, uint16_t qclass);

// Returns 1 and fills *ip (network byte order) if a glue address is found, else 0.
int find_glue(const uint8_t *msg, size_t len, uint32_t *ip);

// Returns the length of the final response (in resp), or -1 on failure.
int resolve(int ufd, const char *name, uint16_t qtype, uint16_t qclass, uint8_t *resp, size_t cap);

#endif