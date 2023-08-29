#include "udp.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ip.h"
#include "util.h"

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

// inout: 0: none, > 0: in, < 0: out
static void udp_dump(const uint8_t* data, size_t len, int inout) {
    struct udp_hdr* hdr;
    char arrows[3][5] = {"    ", "I>> ", "O<< "};
    char* arrow;
    if (inout < 0)
        arrow = arrows[2];
    else
        arrow = arrows[inout > 0];

    hdr = (struct udp_hdr*)data;
    flockfile(stderr);
    {
        fprintf(stderr, "%s UDP |      src: %u\n", arrow, ntoh16(hdr->src));
        fprintf(stderr, "%s UDP |      dst: %u\n", arrow, ntoh16(hdr->dst));
        fprintf(stderr, "%s UDP |      len: %u\n", arrow, ntoh16(hdr->len));
        fprintf(stderr, "%s UDP |      sum: 0x%04x\n", arrow, ntoh16(hdr->sum));
#ifdef HEXDUMP
        hexdump(stderr, data, len);
#endif
    }
    funlockfile(stderr);
}

static void udp_input(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr* hdr;
    char addr[2][IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("data length %zu too small (< UDP header size = %zu)", len, sizeof(*hdr));
        return;
    }
    hdr = (struct udp_hdr*)data;
    if (len != ntoh16(hdr->len)) {
        errorf("length mismatched: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }

    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t*)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t*)hdr, len, psum) != 0) {
        errorf("checksum mismatched: sum=0x%04x, verify=0x%04x",
               ntoh16(hdr->sum),
               ntoh16(cksum16((uint16_t*)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr[0], sizeof(addr[0])), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr[1], sizeof(addr[1])), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    udp_dump(data, len, 1);
}

ssize_t udp_output(struct ip_endpoint* src, struct ip_endpoint* dst, const uint8_t* data, size_t len) {
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr* hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep[2][IP_ENDPOINT_STR_LEN];

    // IP のペイロードに載らない
    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
        errorf("payload size %u too large (> IP maximum payload size - UDP header size = %u)",
               len, IP_PAYLOAD_SIZE_MAX - sizeof(*hdr));
        return -1;
    }

    hdr = (struct udp_hdr*)buf;

    // Exercise 18-1: UDP データグラム生成
    total = len + sizeof(*hdr);
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);

    psum = ~cksum16((uint16_t*)&pseudo, sizeof(pseudo), 0);

    hdr->src = src->port;
    hdr->dst = dst->port;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    
    hdr->sum = cksum16((uint16_t*)hdr, total, psum);
    // Exercise 18-1

    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(src, ep[0], sizeof(ep[0])),
           ip_endpoint_ntop(dst, ep[1], sizeof(ep[1])),
           total, len);
    udp_dump((uint8_t*)hdr, total, -1);

    // Exercise 18-2: IP の送信関数呼び出し
    if (ip_output(IP_PROTOCOL_UDP, (uint8_t*)hdr, total, src->addr, dst->addr) == -1) {
        errorf("ip_output() failed");
        return -1;
    }
    // Exercise 18-2

    return len;
}

int udp_init(void) {
    if(ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1){
        errorf("ip_protocol_register() failed");
        return -1;
    }

    return 0;
}