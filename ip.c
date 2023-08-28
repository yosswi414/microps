#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"

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

struct ip_protocol {
    struct ip_protocol* next;
    uint8_t type;
    void (*handler)(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface);
};

const ip_addr_t IP_ADDR_ANY = 0x00000000; // 0.0.0.0
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; // 255.255.255.255

// You need to protect the lists with mutex if you add/delete entries after net_run()
static struct ip_iface* ifaces;
static struct ip_protocol* protocols;

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

// void ip_dump(const uint8_t* data, size_t len){
//     struct ip_hdr* hdr;
//     uint8_t v, hl, hlen;
//     uint16_t total, offset;
//     char addr[IP_ADDR_STR_LEN];
//
//     hdr = (struct ip_hdr*)data;
//     v = (hdr->vhl & 0xf0) >> 4;
//     hl = hdr->vhl & 0x0f;
//     hlen = hl << 2;  // 32bit unit -> 8bit unit
//     total = ntoh16(hdr->total);
//     offset = ntoh16(hdr->offset);
//     flockfile(stderr);
//     {
//         fprintf(stderr, "  IP |      vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
//         fprintf(stderr, "  IP |      tos: 0x%02x\n", hdr->tos);
//         fprintf(stderr, "  IP |    total: %u (payload: %u)\n", total, total - hlen);
//         fprintf(stderr, "  IP |       id: %u\n", ntoh16(hdr->id));
//         fprintf(stderr, "  IP |   offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
//         fprintf(stderr, "  IP |      ttl: %u\n", hdr->ttl);
//         fprintf(stderr, "  IP | protocol: %u\n", hdr->protocol);
//         fprintf(stderr, "  IP |      sum: 0x%04x\n", ntoh16(hdr->sum));
//         fprintf(stderr, "  IP |      src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
//         fprintf(stderr, "  IP |      dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
// #ifdef HEXDUMP
//         hexdump(stderr, data, len);
//         #endif
//     }
//     funlockfile(stderr);
// }

// inout: 0: none, > 0: in, < 0: out
void ip_dump(const uint8_t* data, size_t len, int inout) {
    struct ip_hdr* hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];
    char arrows[3][5] = {"    ", "I>> ", "O<< "};
    char* arrow;
    if (inout < 0)
        arrow = arrows[2];
    else
        arrow = arrows[inout > 0];

    hdr = (struct ip_hdr*)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;  // 32bit unit -> 8bit unit
    total = ntoh16(hdr->total);
    offset = ntoh16(hdr->offset);

    flockfile(stderr);
    {
        fprintf(stderr, "%s  IP |      vhl: 0x%02x [v: %u, hl: %u (%u)]\n", arrow, hdr->vhl, v, hl, hlen);
        fprintf(stderr, "%s  IP |      tos: 0x%02x\n", arrow, hdr->tos);
        fprintf(stderr, "%s  IP |    total: %u (payload: %u)\n", arrow, total, total - hlen);
        fprintf(stderr, "%s  IP |       id: %u\n", arrow, ntoh16(hdr->id));
        fprintf(stderr, "%s  IP |   offset: 0x%04x [flags=%x, offset=%u]\n", arrow, offset, (offset & 0xe000) >> 13, offset & 0x1fff);
        fprintf(stderr, "%s  IP |      ttl: %u\n", arrow, hdr->ttl);
        fprintf(stderr, "%s  IP | protocol: %u\n", arrow, hdr->protocol);
        fprintf(stderr, "%s  IP |      sum: 0x%04x\n", arrow, ntoh16(hdr->sum));
        fprintf(stderr, "%s  IP |      src: %s\n", arrow, ip_addr_ntop(hdr->src, addr, sizeof(addr)));
        fprintf(stderr, "%s  IP |      dst: %s\n", arrow, ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
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

int ip_protocol_register(
    uint8_t type,
    void (*handler)(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface)
){
    struct ip_protocol* entry;

    // Exercise 9-1: 重複登録の確認
    for (entry = protocols; entry; entry = entry->next){
        if(entry->type == type){
            errorf("protocol with given type already exists, type=%u", type);
            return -1;
        }
    }
    // Exercise 9-1
    // Exercise 9-2: プロトコルの登録
    if(!(entry = memory_alloc(sizeof(*entry)))){
        errorf("memory_alloc() failed");
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;
    // Exercise 9-2

    infof("registered, type=%u", entry->type);
    return 0;
}

static void ip_input(const uint8_t* data, size_t len, struct net_device* dev){
    struct ip_hdr* hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface* iface;
    char addr[IP_ADDR_STR_LEN];
    const int inout = 1; // input

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
    ip_dump(data, total, inout);

    // Exercise 9-3: プロトコルの検索
    struct ip_protocol* proto;
    for (proto = protocols; proto; proto = proto->next){
        if(proto->type == hdr->protocol){
            proto->handler(data + hlen, len - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
    // Exercise 9-3

    // unsupported protocol
}

static int ip_output_device(struct ip_iface* iface, const uint8_t* data, size_t len, ip_addr_t dst){
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;

    // ARP によるアドレス解決が必要な場合
    if(NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP){
        // 宛先がブロードキャスト IP アドレスの場合は解決を行わず、
        // そのデバイスのブロードキャスト HW アドレスを用いる
        if(dst == iface->broadcast || dst == IP_ADDR_BROADCAST){
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        }
        else{
            // Exercise 14-5: arp_resolve() を呼び出してアドレス解決
            if ((ret = arp_resolve(NET_IFACE(iface), dst, hwaddr)) != ARP_RESOLVE_FOUND) return ret;
            // Exercise 14-5
        }
    }

    // Exercise 8-4: デバイスから送信
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
    // Exercise 8-4
}

static ssize_t ip_output_core(struct ip_iface* iface, uint8_t protocol, const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset){
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr* hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];
    const int inout = -1; // output

    hdr = (struct ip_hdr*)buf;
    // Exercise 8-3: IP データグラム生成
    // IP ヘッダの各フィールドに値を設定
    hlen = IP_HDR_SIZE_MIN;
    total = IP_HDR_SIZE_MIN + len;
    hdr->vhl = IP_VERSION_IPV4 << 4 | hlen >> 2;
    hdr->tos = 0;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 255;
    hdr->protocol = protocol;
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = 0;
    hdr->sum = cksum16((uint16_t*)hdr, sizeof(*hdr), 0);
    // IP ヘッダの直後にデータを配置
    memcpy(hdr + 1, data, len);
    // Exercise 8-3
    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
           NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total, inout);
    // 生成した IP データグラムを実際にデバイスから送信するための関数に渡す
    return ip_output_device(iface, buf, total, dst);
}

static uint16_t ip_generate_id(void){
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst){
    struct ip_iface* iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if(src == IP_ADDR_ANY){
        errorf("ip routing to be supported");
        return -1;
    }
    else {  // to be revised
        // Exercise 8-1: IP インタフェースの検索
        if(!(iface = ip_iface_select(src))){
            errorf("IP interface not found, src: %s", ip_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
        // Exercise 8-1
        // Exercise 8-2: 宛先へ到達可能か確認
        if((iface->unicast & iface->netmask) ^ (dst & iface->netmask) && dst != IP_ADDR_BROADCAST){
            errorf("unreachable IP, dst=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
            return -1;
        }
        // Exercise 8-2
    }
    // フラグメンテーションをサポートしないので、MTU を超える場合はエラー
    if(NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too large, dev=%s, mtu=%u < %zu",
               NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id();  // IP データグラムの ID を採番
    // IP データグラムを生成して出力するための関数を呼び出す
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1){
        errorf("ip_output_core() failed");
        return -1;
    }
    return len;
}

int ip_init(void){
    if(net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failed");
        return -1;
    }
    return 0;
}
