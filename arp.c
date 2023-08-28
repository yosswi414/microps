#include "arp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ether.h"
#include "ip.h"
#include "net.h"
#include "util.h"

// ref: https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
#define ARP_HRD_ETHER 0x0001
// Use same value as the Ethernet types
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct arp_hdr {
    uint16_t hrd;  // hardware type
    uint16_t pro;  // protocol type
    uint8_t hln;   // hardware length
    uint8_t pln;   // protocol length
    uint16_t op;   // operation (request / reply)
};

struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];  // sender hardware address
    // ip_addr_t にすると spa が 32 bit アラインメントされてしまい sha との間にパディングが入ってしまう
    uint8_t spa[IP_ADDR_LEN];     // sender protocol address
    uint8_t tha[ETHER_ADDR_LEN];  // target hardware address
    uint8_t tpa[IP_ADDR_LEN];     // target protocol address
};

static char* arp_opcode_ntoa(uint16_t opcode) {
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

// inout: 0: none, > 0: in, < 0: out
static void arp_dump(const uint8_t* data, size_t len, int inout) {
    struct arp_ether_ip* message;
    ip_addr_t spa, tpa;
    char addr[128];
    char arrows[3][5] = {"    ", "I>> ", "O<< "};
    char* arrow;
    if (inout < 0)
        arrow = arrows[2];
    else
        arrow = arrows[inout > 0];

    message = (struct arp_ether_ip*)data;
    memcpy(&spa, message->spa, sizeof(spa));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    flockfile(stderr);
    {
        fprintf(stderr, "%s ARP |      hrd: 0x%04x\n", arrow, ntoh16(message->hdr.hrd));
        fprintf(stderr, "%s ARP |      pro: 0x%04x\n", arrow, ntoh16(message->hdr.pro));
        fprintf(stderr, "%s ARP |      hln: %u\n", arrow, message->hdr.hln);
        fprintf(stderr, "%s ARP |      pln: %u\n", arrow, message->hdr.pln);
        fprintf(stderr, "%s ARP |       op: %u (%s)\n", arrow, ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
        fprintf(stderr, "%s ARP |      sha: %s\n", arrow, ether_addr_ntop(message->sha, addr, sizeof(addr)));
        fprintf(stderr, "%s ARP |      spa: %s\n", arrow, ip_addr_ntop(spa, addr, sizeof(addr)));
        fprintf(stderr, "%s ARP |      tha: %s\n", arrow, ether_addr_ntop(message->tha, addr, sizeof(addr)));
        fprintf(stderr, "%s ARP |      tpa: %s\n", arrow, ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
        hexdump(stderr, data, len);
#endif
    }
    funlockfile(stderr);
}

static int arp_reply(struct net_iface* iface, const uint8_t* tha, ip_addr_t tpa, const uint8_t* dst){
    struct arp_ether_ip reply;

    // Exercise 13-3: ARP 応答メッセージの生成
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);

    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface*)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);
    // Exercise 13-3

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t*)&reply, sizeof(reply), -1);
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t*)&reply, sizeof(reply), dst);
}

static void arp_input(const uint8_t* data, size_t len, struct net_device* dev){
    struct arp_ether_ip* msg;
    ip_addr_t spa, tpa;
    struct net_iface* iface;

    if(len<sizeof(*msg)){
        errorf("message length %u too small (< arp_ether_ip size = %u)", len, sizeof(*msg));
        return;
    }
    msg = (struct arp_ether_ip*)data;

    // Exercise 13-1: 対応可能なアドレスペアのメッセージのみ受け入れる
    // ハードウェアアドレスチェック
    if(ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN){
        // not Ethernet
        errorf("ARP only supports Ethernet as available hardware");
        return;
    }
    // プロトコルアドレスチェック
    if(ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("ARP only supports IP as available protocol");
        return;
    }
    // Exercise 13-1

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len, 1);
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP); // IP インタフェース
    if(iface && ((struct ip_iface*)iface)->unicast == tpa) {
        // Exercise 13-2: ARP 要求への応答
        if(ntoh16(msg->hdr.op) == ARP_OP_REQUEST){
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
        // Exercise 13-2
    }
}

int arp_init(void){
    // Exercise 13-4: プロトコルスタックに ARP を登録
    if(net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1){
        errorf("net_protocol_register() failed");
        return -1;
    }
    // Exercise 13-4

    return 0;
}