#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr {
    uint8_t vhl;    // Version (4bit), IHL (4bit)
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset;    // flags (3bit), fragment offset (13bit)
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[];
};

const ip_addr_t IP_ADDR_ANY = 0x00000000; // 0.0.0.0
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; // 255.255.255.255

// You need to protect the lists with mutex if you add/delete entries after net_run()
static struct ip_iface* ifaces;

// Printable text TO Network binary
int ip_addr_pton(const char* p, ip_addr_t *n){
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char*)p;
    for (idx = 0; idx < 4; ++idx){
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) return -1;
        if (ep == sp) return -1;
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) return -1;
        ((uint8_t*)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

// Network binary TO Printable text
char* ip_addr_ntop(ip_addr_t n, char* p, size_t size){
    uint8_t* u8;
    u8 = (uint8_t*)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

void ip_dump(const uint8_t* data, size_t len){
    struct ip_hdr* hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr*)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;  // 32bit unit -> 8bit unit
    total = ntoh16(hdr->total);
    offset = ntoh16(hdr->offset);
    flockfile(stderr);
    {
        fprintf(stderr, "      vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
        fprintf(stderr, "      tos: 0x%02x\n", hdr->tos);
        fprintf(stderr, "    total: %u (payload: %u)\n", total, total - hlen);
        fprintf(stderr, "       id: %u\n", ntoh16(hdr->id));
        fprintf(stderr, "   offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
        fprintf(stderr, "      ttl: %u\n", hdr->ttl);
        fprintf(stderr, " protocol: %u\n", hdr->protocol);
        fprintf(stderr, "      sum: 0x%04x\n", ntoh16(hdr->sum));
        fprintf(stderr, "      src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
        fprintf(stderr, "      dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
        #ifdef HEXDUMP
        hexdump(stderr, data, len);
        #endif
    }
    funlockfile(stderr);
}

struct ip_iface* ip_iface_alloc(const char* unicast, const char* netmask){
    struct ip_iface* iface;

    iface = memory_alloc(sizeof(*iface));
    if(!iface){
        errorf("memory_alloc() failed");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    // Exercise 7-3: IP インタフェースにアドレス情報を設定
    if(ip_addr_pton(unicast, &iface->unicast)){
        errorf("ip_addr_pton() failed");
        memory_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask)) {
        errorf("ip_addr_pton() failed");
        memory_free(iface);
        return NULL;
    }
    ip_addr_t net_addr = iface->unicast & iface->netmask;
    iface->broadcast = net_addr | ~iface->netmask;
    // Exercise 7-3

    return iface;
}

// This should not be called after net_run()
int ip_iface_register(struct net_device* dev, struct ip_iface* iface){
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    // Exercise 7-4: IP インタフェースの登録
    if(net_device_add_iface(dev, NET_IFACE(iface)) == -1){
        errorf("net_device_add_iface() failed");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;
    // Exercise 7-4

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s",
        dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3))
    );
    return 0;
}

struct ip_iface* ip_iface_select(ip_addr_t addr){
    // Exercise 7-5: IP インタフェースの検索
    struct ip_iface* iface;
    for (iface = ifaces; iface; iface = iface->next){
        if (iface->unicast == addr) return iface;
    }
    return NULL;
    // Exercise 7-5
}

static void ip_input(const uint8_t* data, size_t len, struct net_device* dev){
    struct ip_hdr* hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface* iface;
    char addr[IP_ADDR_STR_LEN];

    if(len < IP_HDR_SIZE_MIN){
        errorf("length too short (< IP_HDR_SIZE_MIN)");
        return;
    }
    hdr = (struct ip_hdr*)data;

    v = (hdr->vhl & 0xf0) >> 4;
    hlen = (hdr->vhl & 0x0f) << 2;
    total = ntoh16(hdr->total);

    // Exercise 6-1: IP データグラム検証
    // version
    if(v != IP_VERSION_IPV4){
        errorf("version not supported");
        return;
    }
    // header length
    if(len < hlen){
        errorf("length %d too short (< header length = %d)", len, hlen);
        return;
    }
    // total length
    if(len < total){
        errorf("length %d too short (< total length = %d)", len, total);
        return;
    }
    // check sum
    if (cksum16((uint16_t*)hdr, sizeof(*hdr), 0)) {
        errorf("checksum mismatched");
        return;
    }
    // Exercise 6-1

    offset = ntoh16(hdr->offset);
    if(offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments not supported");
        return;
    }

    // Exercise 7-6: IP データグラムのフィルタリング
    iface = (struct ip_iface*)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (!iface) {
        errorf("IP interface not found");
        return;
    }
    if(
        hdr->dst != iface->unicast &&
        hdr->dst != IP_ADDR_BROADCAST &&
        hdr->dst != iface->broadcast
    ) { return; } // filtering out the IP datagram
    // Exercise 7-6

    debugf("dev=%s, iface=%s, protocol=%u, total=%u",
           dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);
}

int ip_init(void){
    if(net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failed");
        return -1;
    }
    return 0;
}
