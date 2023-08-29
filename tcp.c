#include "tcp.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "util.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

struct pseudo_hdr {
    uint32_t src;      // Source Address
    uint32_t dst;      // Destination Address
    uint8_t zero;      // Zero
    uint8_t protocol;  // Protocol
    uint16_t len;      // TCP Length
};

struct tcp_hdr {
    uint16_t src;  // Source Port
    uint16_t dst;  // Destination Port
    uint32_t seq;  // Sequence Number
    uint32_t ack;  // Acknouledgment Number
    uint8_t off;   // Data Offset
    uint8_t flg;   // Flags
    uint16_t wnd;  // Window
    uint16_t sum;  // Checksum
    uint16_t up;   // Urgent Pointer
};

static char* tcp_flg_ntoa(uint8_t flg) {
    static char str[9];  // must be static to keep this ptr not freed

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

static void tcp_dump(const uint8_t* data, size_t len, int inout) {
    struct tcp_hdr* hdr;
    char arrows[3][5] = {"    ", "I>> ", "O<< "};
    char* arrow;
    if (inout < 0)
        arrow = arrows[2];
    else
        arrow = arrows[inout > 0];

    hdr = (struct tcp_hdr*)data;
    flockfile(stderr);
    {
        fprintf(stderr, "%s TCP |      src: %u\n", arrow, ntoh16(hdr->src));
        fprintf(stderr, "%s TCP |      dst: %u\n", arrow, ntoh16(hdr->dst));
        fprintf(stderr, "%s TCP |      seq: %u\n", arrow, ntoh32(hdr->seq));
        fprintf(stderr, "%s TCP |      ack: %u\n", arrow, ntoh32(hdr->ack));
        fprintf(stderr, "%s TCP |      off: 0x%02x (%d)\n", arrow, hdr->off, (hdr->off >> 4) << 2);
        fprintf(stderr, "%s TCP |      flg: 0x%02x (%s)\n", arrow, hdr->flg, tcp_flg_ntoa(hdr->flg));
        fprintf(stderr, "%s TCP |      wnd: %u\n", arrow, ntoh16(hdr->wnd));
        fprintf(stderr, "%s TCP |      sum: 0x%04x\n", arrow, ntoh16(hdr->sum));
        fprintf(stderr, "%s TCP |       up: %u\n", arrow, ntoh16(hdr->up));
#ifdef HEXDUMP
        hexdump(stderr, data, len);
#endif
    }
    funlockfile(stderr);
}

static void tcp_input(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface) {
    struct tcp_hdr* hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr[2][IP_ADDR_STR_LEN];

    if(len < sizeof(*hdr)) {
        errorf("length %u too small (< TCP header size = %u)", len, sizeof(*hdr));
        return;
    }

    hdr = (struct tcp_hdr*)data;

    // Exercise 22-3: チェックサムの検証
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t*)&pseudo, sizeof(pseudo), 0);
    if(cksum16((uint16_t*)hdr, len, psum)) {
        errorf("checksum mismatched, sum=0x%04x", cksum16((uint16_t*)data, len, psum));
        return;
    }
    // Exercise 22-3

    // Exercise 22-4: アドレスのチェック
    if(src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST) {
        errorf("neither src nor dst can be broadcast address in TCP, %s => %s",
               ip_addr_ntop(src, addr[0], sizeof(addr[0])),
               ip_addr_ntop(dst, addr[1], sizeof(addr[1])));
        return;
    }
    // Exercise 22-4

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr[0], sizeof(addr[0])), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr[1], sizeof(addr[1])), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));

    tcp_dump(data, len, 1);
    return;
}

int tcp_init(void) {
    // Exercise 22-1: IP の上位プロトコルとして TCP を登録
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failed");
        return -1;
    }
    // Exercise 22-1
    return 0;
}