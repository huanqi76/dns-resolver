#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "dns.h"

#ifndef DNS_UPSTREAM_PORT
#define DNS_UPSTREAM_PORT 53
#endif

#ifdef ROOT_IP                                   /* tests point this at a local mock server */
static const char *ROOTS[] = { ROOT_IP };
#else
static const char *ROOTS[] = {
    "198.41.0.4",     // a.root-servers.net
    "170.247.170.2",  // b
    "192.33.4.12",    // c
    "199.7.91.13",    // d
    "192.203.230.10", // e
    "192.5.5.241",    // f
    "192.112.36.4",   // g
    "198.97.190.53",  // h
    "192.36.148.17",  // i
    "192.58.128.30",  // j
    "193.0.14.129",   // k
    "199.7.83.42",    // l
    "202.12.27.33",   // m
};
#endif
#define NROOTS ((int)(sizeof ROOTS / sizeof ROOTS[0]))
#define MAX_CANDS 16
#define MAX_DEPTH 8                              // nested lookups (CNAME targets, glueless NS names)

long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

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
    if (pos + 1 > outlen) return -1; 
    out[pos++] = 0;
    return (int)pos;
}

int build_query(uint8_t *out, size_t outlen, uint16_t id,
                const char *name, uint16_t qtype, uint16_t qclass, int edns) {
    if (outlen < 12) return -1;
    size_t pos = 0;
    write16(out + pos, id);      pos += 2;
    write16(out + pos, 0x0000);  pos += 2;   // flags: query, RD = 0
    write16(out + pos, 1);       pos += 2;   // QDCOUNT
    write16(out + pos, 0);       pos += 2;   // ANCOUNT
    write16(out + pos, 0);       pos += 2;   // NSCOUNT
    write16(out + pos, edns ? 1 : 0); pos += 2;   // ARCOUNT (the OPT record)

    int nlen = encode_name(name, out + pos, outlen - pos);
    if (nlen < 0) return -1;
    pos += (size_t)nlen;

    if (pos + 4 + (edns ? 11 : 0) > outlen) return -1;
    write16(out + pos, qtype);   pos += 2;
    write16(out + pos, qclass);  pos += 2;

    if (edns) {
        out[pos++] = 0;                          // OPT: name = root
        write16(out + pos, 41);      pos += 2;   // TYPE = OPT
        write16(out + pos, 4096);    pos += 2;   // CLASS = our UDP payload size
        write32(out + pos, 0);       pos += 4;   // ext RCODE / version / flags
        write16(out + pos, 0);       pos += 2;   // RDLENGTH = 0
    }
    return (int)pos;
}

int records_start(const uint8_t *msg, size_t len) {
    if (len < 12) return -1;
    char tmp[256];
    size_t off = 12;
    int qd = read16(msg + 4);
    for (int i = 0; i < qd; i++) {
        int r = parse_name(msg, len, off, tmp, sizeof tmp);
        if (r < 0 || (size_t)r + 4 > len) return -1;
        off = (size_t)r + 4;
    }
    return (int)off;
}

int parse_query_edns(const uint8_t *msg, size_t len, size_t qend,
                     int *has_opt, uint16_t *udp_size, int *version) {
    *has_opt = 0;
    *udp_size = 512;
    *version = 0;
    int ar = read16(msg + 10);
    size_t off = qend;
    rr_t rr;
    for (int i = 0; i < ar; i++) {
        int r = parse_rr(msg, len, off, &rr);
        if (r < 0) return -1;
        if (rr.type == 41) {
            if (*has_opt || rr.name[0] != '\0') return -1;   // one OPT only, owner must be the root
            *has_opt = 1;
            *udp_size = rr.class < 512 ? 512 : rr.class;     // sizes below 512 are treated as 512
            *version = (rr.ttl >> 16) & 0xFF;
        }
        off = (size_t)r;
    }
    return off == len ? 0 : -1;                              // no trailing garbage
}

int strip_opt(uint8_t *msg, size_t len) {
    int off = records_start(msg, len);
    if (off < 0) return (int)len;
    int an_ns = read16(msg + 6) + read16(msg + 8);
    int total = an_ns + read16(msg + 10);
    rr_t rr;
    for (int i = 0; i < total; i++) {
        size_t start = (size_t)off;
        int r = parse_rr(msg, len, start, &rr);
        if (r < 0) return (int)len;
        if (i >= an_ns && rr.type == 41 && (size_t)r == len) {   // OPT as the very last record
            write16(msg + 10, (uint16_t)(read16(msg + 10) - 1));
            return (int)start;
        }
        off = r;
    }
    return (int)len;
}

int append_opt(uint8_t *msg, size_t len, size_t cap, uint16_t udp_size) {
    if (len < 12 || len + 11 > cap) return -1;
    uint8_t *p = msg + len;
    p[0] = 0;                                // name = root
    write16(p + 1, 41);                      // TYPE = OPT
    write16(p + 3, udp_size);                // CLASS = our UDP payload size
    write32(p + 5, 0);                       // ext RCODE 0, version 0, no flags
    write16(p + 9, 0);                       // RDLENGTH = 0
    write16(msg + 10, (uint16_t)(read16(msg + 10) + 1));
    return (int)(len + 11);
}

int build_reply_header_only(uint8_t *out, size_t cap, uint16_t id, int rd,
                            const uint8_t *question, size_t qlen,
                            int rcode, int tc,
                            int with_opt, int ext_rcode, uint16_t opt_size) {
    size_t need = 12 + qlen + (with_opt ? 11 : 0);
    if (need > cap) return -1;
    uint16_t flags = (uint16_t)(0x8000 | (rd ? 0x0100 : 0) | 0x0080 |
                                (tc ? 0x0200 : 0) | (rcode & 0xF));
    write16(out, id);
    write16(out + 2, flags);
    write16(out + 4, 1);
    write16(out + 6, 0);
    write16(out + 8, 0);
    write16(out + 10, with_opt ? 1 : 0);
    memcpy(out + 12, question, qlen);
    size_t pos = 12 + qlen;
    if (with_opt) {
        out[pos++] = 0;
        write16(out + pos, 41);   pos += 2;
        write16(out + pos, opt_size); pos += 2;
        write32(out + pos, (uint32_t)(ext_rcode & 0xFF) << 24); pos += 4;
        write16(out + pos, 0);    pos += 2;
    }
    return (int)pos;
}

// Offset after the question section and `count` records; -1 if anything doesn't parse.
static int skip_records(const uint8_t *msg, size_t len, int count) {
    int off = records_start(msg, len);
    rr_t rr;
    for (int i = 0; off >= 0 && i < count; i++)
        off = parse_rr(msg, len, (size_t)off, &rr);
    return off;
}

// Copies the NS target names from the authority section. Returns how many.
int collect_ns_names(const uint8_t *msg, size_t len, char names[][256], int max) {
    if (len < 12) return 0;
    int an = read16(msg + 6), ns = read16(msg + 8);
    int off = skip_records(msg, len, an);
    if (off < 0) return 0;
    int n = 0;
    rr_t rr;
    for (int i = 0; i < ns && n < max; i++) {
        int r = parse_rr(msg, len, (size_t)off, &rr);
        if (r < 0) break;
        if (rr.type == 2 && parse_name(msg, len, rr.rdata_off, names[n], 256) >= 0) n++;
        off = r;
    }
    return n;
}

// IPv4 glue addresses (network byte order) for the NS names in a referral. Returns how many.
int find_glue_all(const uint8_t *msg, size_t len, uint32_t *ips, int max) {
    char names[16][256];
    int nn = collect_ns_names(msg, len, names, 16);
    if (nn == 0) return 0;
    int an = read16(msg + 6), ns = read16(msg + 8), ar = read16(msg + 10);
    int off = skip_records(msg, len, an + ns);
    if (off < 0) return 0;
    int n = 0;
    rr_t rr;
    for (int i = 0; i < ar && n < max; i++) {
        int r = parse_rr(msg, len, (size_t)off, &rr);
        if (r < 0) break;
        if (rr.type == 1 && rr.rdlength == 4) {
            for (int k = 0; k < nn; k++) {
                if (strcasecmp(rr.name, names[k]) == 0) {
                    memcpy(&ips[n++], msg + rr.rdata_off, 4);
                    break;
                }
            }
        }
        off = r;
    }
    return n;
}

// Finds the first A record in the answer section. *ip is in network byte order.
int first_answer_a(const uint8_t *msg, size_t len, uint32_t *ip) {
    int off = records_start(msg, len);
    if (off < 0) return 0;
    int an = read16(msg + 6);
    rr_t rr;
    for (int i = 0; i < an; i++) {
        int r = parse_rr(msg, len, (size_t)off, &rr);
        if (r < 0) return 0;
        if (rr.type == 1 && rr.rdlength == 4) {
            memcpy(ip, msg + rr.rdata_off, 4);
            return 1;
        }
        off = r;
    }
    return 0;
}

static int query_server(int ufd, uint32_t ip, const char *name, uint16_t qtype,
                        uint16_t qclass, uint8_t *resp, size_t cap, int edns,
                        long long deadline_ms) {
    struct sockaddr_in server;
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_port = htons(DNS_UPSTREAM_PORT);
    server.sin_addr.s_addr = ip;

    uint8_t q[512];
    uint16_t qid = (uint16_t)(rand() & 0xFFFF);
    int qn = build_query(q, sizeof q, qid, name, qtype, qclass, edns);
    if (qn < 0) return -1;

    sendto(ufd, q, (size_t)qn, 0, (struct sockaddr *)&server, sizeof server);

    ssize_t rn;
    do {
        if (now_ms() > deadline_ms) return -1;
        rn = recvfrom(ufd, resp, cap, 0, NULL, NULL);
    } while (rn >= 12 && read16(resp) != qid);               // ignore stray / late replies
    return rn < 12 ? -1 : (int)rn;
}


static int cname_target(const uint8_t *msg, size_t len, const char *name,
                        uint16_t qtype, char *target, size_t tlen);
static int merge_cname(const uint8_t *r1, size_t l1, const uint8_t *r2, size_t l2,
                       uint8_t *out, size_t cap);

static int follow_cname(int ufd, const char *name, uint16_t qtype, uint16_t qclass,
                        uint8_t *resp, size_t rn, size_t cap, int depth,
                        long long deadline_ms) {
    int rcode = read16(resp + 2) & 0xF;
    if (rcode != 0 || read16(resp + 6) == 0 || qtype == 5 || qtype == 255) return (int)rn;

    char target[256];
    if (!cname_target(resp, rn, name, qtype, target, sizeof target)) return (int)rn;

    uint8_t tail[4096], comb[4096];
    int tn = resolve(ufd, target, qtype, qclass, tail, sizeof tail, depth + 1, deadline_ms);
    if (tn < 12) return -1;
    int cn = merge_cname(resp, rn, tail, (size_t)tn, comb, sizeof comb);
    if (cn < 0 || (size_t)cn > cap) return -1;
    memcpy(resp, comb, (size_t)cn);
    return cn;
}


// Returns the length of the final response (in resp), or -1 on failure.
int resolve(int ufd, const char *name, uint16_t qtype, uint16_t qclass,
            uint8_t *resp, size_t cap, int depth, long long deadline_ms) {
    if (depth > MAX_DEPTH) return -1;

    // candidate servers: all roots, starting at a random one to spread the load
    uint32_t cands[MAX_CANDS];
    int ncand = 0;
    int start = rand() % NROOTS;
    for (int i = 0; i < NROOTS && ncand < MAX_CANDS; i++) {
        struct in_addr a;
        if (inet_pton(AF_INET, ROOTS[(start + i) % NROOTS], &a) == 1)
            cands[ncand++] = a.s_addr;
    }

    for (int hop = 0; hop < 16; hop++) {                     // referral hop limit
        int rn = -1;
        for (int c = 0; c < ncand; c++) {                    // try each candidate until one answers
            if (now_ms() > deadline_ms) return -1;
            rn = query_server(ufd, cands[c], name, qtype, qclass, resp, cap, 1, deadline_ms);
            if (rn >= 12 && (read16(resp + 2) & 0xF) == 1)   // FORMERR: retry without EDNS
                rn = query_server(ufd, cands[c], name, qtype, qclass, resp, cap, 0, deadline_ms);
            if (rn < 12) { rn = -1; continue; }              // timeout
            int rc = read16(resp + 2) & 0xF;
            if (rc == 0 || rc == 3) break;                   // NOERROR / NXDOMAIN: usable
            rn = -1;                                         // SERVFAIL, REFUSED, ...: next server
        }
        if (rn < 0) return -1;

        uint16_t flags = read16(resp + 2);
        int rcode = flags & 0xF;
        int aa = (flags >> 10) & 1;
        if (rcode != 0 || read16(resp + 6) > 0 || aa)        // answer, error, or authoritative "no data"
            return follow_cname(ufd, name, qtype, qclass, resp, (size_t)rn, cap, depth, deadline_ms);

        // otherwise it's a referral: collect the next servers to ask
        ncand = find_glue_all(resp, (size_t)rn, cands, MAX_CANDS);
        if (ncand == 0) {                                    // no glue: look up name server addresses ourselves
            char names[8][256];
            int nn = collect_ns_names(resp, (size_t)rn, names, 8);
            for (int k = 0; k < nn && ncand < 2; k++) {
                uint8_t tmp[4096];
                uint32_t ip;
                int tn = resolve(ufd, names[k], 1, 1, tmp, sizeof tmp, depth + 1, deadline_ms);
                if (tn >= 12 && first_answer_a(tmp, (size_t)tn, &ip)) cands[ncand++] = ip;
            }
        }
        if (ncand == 0) return -1;
    }
    return -1;
}

static int cname_target(const uint8_t *msg, size_t len, const char *name,
                        uint16_t qtype, char *target, size_t tlen) {
    char owners[16][256], targets[16][256];
    int nc = 0;
    int off = records_start(msg, len);
    if (off < 0) return 0;
    int an = read16(msg + 6);
    rr_t rr;
    for (int i = 0; i < an; i++) {
        int r = parse_rr(msg, len, (size_t)off, &rr);
        if (r < 0) return 0;
        if (rr.type == qtype) return 0;                      // already has what was asked for
        if (rr.type == 5 && nc < 16 &&
            parse_name(msg, len, rr.rdata_off, targets[nc], 256) >= 0) {
            snprintf(owners[nc], 256, "%s", rr.name);
            nc++;
        }
        off = r;
    }

    char cur[256];
    snprintf(cur, sizeof cur, "%s", name);
    int moved = 0;
    for (int step = 0; step < 16; step++) {
        int found = -1;
        for (int k = 0; k < nc; k++) {
            if (strcasecmp(owners[k], cur) == 0) { found = k; break; }
        }
        if (found < 0) break;
        snprintf(cur, sizeof cur, "%s", targets[found]);
        moved = 1;
    }
    if (!moved) return 0;
    snprintf(target, tlen, "%s", cur);
    return 1;
}

typedef struct { uint8_t *buf; size_t cap; size_t pos; } wbuf_t;

// Copies the (possibly compressed) name at msg[*off] into w, UNcompressed; advances *off.
static int copy_name(wbuf_t *w, const uint8_t *msg, size_t len, size_t *off) {
    char tmp[256];
    int next = parse_name(msg, len, *off, tmp, sizeof tmp);
    if (next < 0) return -1;
    int n = encode_name(tmp, w->buf + w->pos, w->cap - w->pos);
    if (n < 0) return -1;
    w->pos += (size_t)n;
    *off = (size_t)next;
    return 0;
}

// Re-encodes one record into w. Names (owner and, for the classic types, inside the
// RDATA) are written uncompressed so the record is valid in any message.
static int append_rr(wbuf_t *w, const uint8_t *msg, size_t len, const rr_t *rr) {
    int n = encode_name(rr->name, w->buf + w->pos, w->cap - w->pos);
    if (n < 0) return -1;
    w->pos += (size_t)n;
    if (w->pos + 10 > w->cap) return -1;
    write16(w->buf + w->pos, rr->type);
    write16(w->buf + w->pos + 2, rr->class);
    write32(w->buf + w->pos + 4, rr->ttl);
    size_t rdlen_at = w->pos + 8;
    w->pos += 10;
    size_t rd_start = w->pos;

    size_t off = rr->rdata_off;
    size_t end = rr->rdata_off + rr->rdlength;
    switch (rr->type) {
    case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12:   // NS MD MF CNAME MB MG MR PTR
        if (copy_name(w, msg, len, &off) < 0 || off != end) return -1;
        break;
    case 14:                                                            // MINFO: two names
        if (copy_name(w, msg, len, &off) < 0 ||
            copy_name(w, msg, len, &off) < 0 || off != end) return -1;
        break;
    case 15:                                                            // MX: preference + name
        if (rr->rdlength < 2 || w->pos + 2 > w->cap) return -1;
        memcpy(w->buf + w->pos, msg + off, 2);
        w->pos += 2;
        off += 2;
        if (copy_name(w, msg, len, &off) < 0 || off != end) return -1;
        break;
    case 6:                                                             // SOA: two names + 5 numbers
        if (copy_name(w, msg, len, &off) < 0 ||
            copy_name(w, msg, len, &off) < 0 ||
            off + 20 != end || w->pos + 20 > w->cap) return -1;
        memcpy(w->buf + w->pos, msg + off, 20);
        w->pos += 20;
        break;
    default:                                                            // everything else: raw RDATA
        if (w->pos + rr->rdlength > w->cap) return -1;
        memcpy(w->buf + w->pos, msg + off, rr->rdlength);
        w->pos += rr->rdlength;
    }
    write16(w->buf + rdlen_at, (uint16_t)(w->pos - rd_start));
    return 0;
}

// Combines the first response (which holds the CNAME records) with the response for the
// CNAME target. Question = the original one; answers = r1's answers + r2's answers;
// authority/additional + RCODE come from r2. Returns the new length, or -1.
static int merge_cname(const uint8_t *r1, size_t l1, const uint8_t *r2, size_t l2,
                       uint8_t *out, size_t cap) {
    int q1 = records_start(r1, l1);
    int q2 = records_start(r2, l2);
    if (q1 < 0 || q2 < 0 || cap < (size_t)q1) return -1;

    wbuf_t w = { out, cap, (size_t)q1 };
    memcpy(out, r2, 12);                              // header of the final response (flags, RCODE)
    memcpy(out + 12, r1 + 12, (size_t)q1 - 12);       // the ORIGINAL question

    int an1 = read16(r1 + 6);
    int an2 = read16(r2 + 6), ns2 = read16(r2 + 8), ar2 = read16(r2 + 10);
    int ar_out = 0;
    rr_t rr;

    int off = q1;
    for (int i = 0; i < an1; i++) {
        int r = parse_rr(r1, l1, (size_t)off, &rr);
        if (r < 0 || append_rr(&w, r1, l1, &rr) < 0) return -1;
        off = r;
    }
    off = q2;
    for (int i = 0; i < an2 + ns2 + ar2; i++) {
        int r = parse_rr(r2, l2, (size_t)off, &rr);
        if (r < 0) return -1;
        if (rr.type != 41) {                          // OPT is added back per client later
            if (append_rr(&w, r2, l2, &rr) < 0) return -1;
            if (i >= an2 + ns2) ar_out++;
        }
        off = r;
    }
    write16(out + 4, 1);
    write16(out + 6, (uint16_t)(an1 + an2));
    write16(out + 8, (uint16_t)ns2);
    write16(out + 10, (uint16_t)ar_out);
    return (int)w.pos;
}
