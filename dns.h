#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     name[256];
    uint16_t type;
    uint16_t class;      // for an OPT record this field holds the sender's UDP payload size
    uint32_t ttl;        // for an OPT record this field holds ext-RCODE / version / flags
    uint16_t rdlength;
    size_t   rdata_off;  // offset of the RDATA inside the message
} rr_t;

/* ---- big-endian helpers ---- */
uint16_t read16(const uint8_t *p);
uint32_t read32(const uint8_t *p);
void write16(uint8_t *p, uint16_t v);
void write32(uint8_t *p, uint32_t v);

// Reads a (possibly compressed) name at msg[offset] into out as "a.b.c".
// Returns the offset just past the name in its ORIGINAL position, or -1 if invalid.
int parse_name(const uint8_t *msg, size_t msglen, size_t offset,
               char *out, size_t outlen);

// Writes "a.b.c" as [1]a[1]b[1]c[0]. Returns bytes written, or -1.
int encode_name(const char *name, uint8_t *out, size_t outlen);

// Builds a query with RD=0 and one question; adds an EDNS OPT record if edns != 0.
// Returns its length, or -1.
int build_query(uint8_t *out, size_t outlen, uint16_t id,
                const char *name, uint16_t qtype, uint16_t qclass, int edns);

// Parses one resource record. Returns the offset of the next record, or -1.
int parse_rr(const uint8_t *msg, size_t msglen, size_t offset, rr_t *rr);

// Offset of the first record (just past the question section), or -1.
int records_start(const uint8_t *msg, size_t len);

// Validates the additional section of a CLIENT query (which starts at qend) and reports
// its OPT record, if any. Returns 0 if valid, -1 if the query must be dropped.
int parse_query_edns(const uint8_t *msg, size_t len, size_t qend,
                     int *has_opt, uint16_t *udp_size, int *version);

// Removes a trailing OPT record from a message. Returns the new length.
int strip_opt(uint8_t *msg, size_t len);

// Appends an OPT record (no options). Returns the new length, or -1 if it doesn't fit.
int append_opt(uint8_t *msg, size_t len, size_t cap, uint16_t udp_size);

// Builds a reply that has only the header + the client's question (+ optional OPT).
// Used for SERVFAIL, BADVERS and truncated (TC) replies. Returns its length, or -1.
int build_reply_header_only(uint8_t *out, size_t cap, uint16_t id, int rd,
                            const uint8_t *question, size_t qlen,
                            int rcode, int tc,
                            int with_opt, int ext_rcode, uint16_t opt_size);

// IPv4 glue addresses (network byte order) for the NS names in a referral. Returns the count.
int find_glue_all(const uint8_t *msg, size_t len, uint32_t *ips, int max);
// Copies the NS target names from the authority section. Returns the count.
int collect_ns_names(const uint8_t *msg, size_t len, char names[][256], int max);
// First A record in the answer section (network byte order). Returns 1 if found.
int first_answer_a(const uint8_t *msg, size_t len, uint32_t *ip);

long long now_ms(void);

// Resolves name/qtype/qclass iteratively starting at the root servers, following
// referrals and CNAME chains. The result (a complete DNS message) goes in resp.
// deadline_ms is an absolute now_ms() value. Returns the length, or -1 on failure.
int resolve(int ufd, const char *name, uint16_t qtype, uint16_t qclass,
            uint8_t *resp, size_t cap, int depth, long long deadline_ms);

#endif