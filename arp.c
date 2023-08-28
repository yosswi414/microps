#include "arp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

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

#define ARP_CACHE_SIZE      32
#define ARP_CACHE_TIMEOUT   30  // [sec]

#define ARP_CACHE_STATE_FREE        0
#define ARP_CACHE_STATE_INCOMPLETE  1
#define ARP_CACHE_STATE_RESOLVED    2
#define ARP_CACHE_STATE_STATIC      3

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

struct arp_cache {
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETHER_ADDR_LEN];
    struct timeval timestamp;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];

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

/*
 *  ARP Cache
 *
 *  ARP cache functions must be called always with mutex protection
 */
static void arp_cache_delete(struct arp_cache* cache) {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s",
           ip_addr_ntop(cache->pa, addr1, sizeof(addr1)),
           ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));
    
    // Exercise 14-1: キャッシュのエントリを削除
    memset(cache, 0, sizeof(*cache));
    // cache->state = ARP_CACHE_STATE_FREE;
    // Exercise 14-1
}

static struct arp_cache* arp_cache_alloc(void) {
    struct arp_cache *entry, *oldest = NULL;

    for (entry = caches; entry < tailof(caches); ++entry){
        if (entry->state == ARP_CACHE_STATE_FREE) return entry;
        if(!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)){
            oldest = entry;
        }
    }
    arp_cache_delete(oldest);
    return oldest;
}

static struct arp_cache* arp_cache_select(ip_addr_t pa) {
    // Exercise 14-2: キャッシュの中からプロトコルアドレスが一致するエントリを探して返す
    struct arp_cache* entry;
    for (entry = caches; entry < tailof(caches); ++entry) {
        if (entry->pa == pa) return entry;
    }
    return NULL;
    // Exercise 14-2
}

static struct arp_cache* arp_cache_update(ip_addr_t pa, const uint8_t* ha) {
    struct arp_cache* cache;
    char addr1[IP_ADDR_STR_LEN], addr2[ETHER_ADDR_STR_LEN];

    // Exercise 14-3: キャッシュに登録されている情報を更新する
    if (!(cache = arp_cache_select(pa))) return NULL;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    cache->state = ARP_CACHE_STATE_RESOLVED;
    gettimeofday(&cache->timestamp, NULL);
    // Exercise 14-3

    debugf("UPDATE: pa=%s, ha=%s",
           ip_addr_ntop(pa, addr1, sizeof(addr1)),
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

static struct arp_cache* arp_cache_insert(ip_addr_t pa, const uint8_t* ha) {
    struct arp_cache* cache;
    char addr1[IP_ADDR_STR_LEN], addr2[ETHER_ADDR_STR_LEN];

    // Exercise 14-4: キャッシュに新しくエントリを追加
    if(!(cache = arp_cache_alloc())){
        errorf("arp_cache_alloc() failed");
        return NULL;
    }
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    cache->pa = pa;
    cache->state = ARP_CACHE_STATE_RESOLVED;
    gettimeofday(&cache->timestamp, NULL);
    // Exercise 14-4

    debugf("INSERT: pa=%s, ha=%s",
           ip_addr_ntop(pa, addr1, sizeof(addr1)),
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

static int arp_request(struct net_iface* iface, ip_addr_t tpa){
    struct arp_ether_ip request;

    // Exercise 15-2: ARP 要求のメッセージを生成
    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface*)iface)->unicast, IP_ADDR_LEN);
    memcpy(request.tha, ETHER_ADDR_ANY, ETHER_ADDR_LEN);
    memcpy(request.tpa, &tpa, IP_ADDR_LEN);
    // Exercise 15-2

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
    arp_dump((uint8_t*)&request, sizeof(request), -1);

    // Exercise 15-3: デバイスの送信関数を呼び出して ARP 要求のメッセージを送信する
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t*)&request, sizeof(request), ETHER_ADDR_BROADCAST);
    // Exercise 15-3
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
    int merge = 0;  // 更新の可否のフラグ

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

    mutex_lock(&mutex);
    {
        if (arp_cache_update(spa, msg->sha)) merge = 1;  // updated
    }
    mutex_unlock(&mutex);

    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP); // IP インタフェース
    if(iface && ((struct ip_iface*)iface)->unicast == tpa) {
        if(!merge){ // not updated -> unregistered
            mutex_lock(&mutex);
            {
                arp_cache_insert(spa, msg->sha);
            }
            mutex_unlock(&mutex);
        }
        // Exercise 13-2: ARP 要求への応答
        if(ntoh16(msg->hdr.op) == ARP_OP_REQUEST){
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
        // Exercise 13-2
    }
}

int arp_resolve(struct net_iface* iface, ip_addr_t pa, uint8_t* ha) {
    struct arp_cache* cache;
    char addr1[IP_ADDR_STR_LEN], addr2[ETHER_ADDR_STR_LEN];

    if(iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if(iface->family != NET_IFACE_FAMILY_IP){
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }

    mutex_lock(&mutex);
    {
        if (!(cache = arp_cache_select(pa))){
            debugf("cache miss, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
            // Exercise 15-1: ARP キャッシュに問い合わせ中のエントリ作成
            if(!(cache = arp_cache_alloc())){
                errorf("arp_cache_alloc() failed");
                return ARP_RESOLVE_ERROR;
            }
            cache->state = ARP_CACHE_STATE_INCOMPLETE;
            // cache->ha;
            cache->pa = pa;
            gettimeofday(&cache->timestamp, NULL);
            // Exercise 15-1
            mutex_unlock(&mutex);
            arp_request(iface, pa);
            return ARP_RESOLVE_INCOMPLETE;  // 問い合わせ中なので INCOMPLETE
        }
        if(cache->state == ARP_CACHE_STATE_INCOMPLETE){
            // ARP 要求を再送
            mutex_unlock(&mutex);
            arp_request(iface, pa);
            return ARP_RESOLVE_INCOMPLETE;  // 問い合わせ中なので INCOMPLETE
        }
        memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    }
    mutex_unlock(&mutex);

    debugf("resolved, pa=%s, ha=%s",
           ip_addr_ntop(pa, addr1, sizeof(addr1)),
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

static void arp_timer_handler(void) {
    struct arp_cache* entry;
    struct timeval now, diff, to = {ARP_CACHE_TIMEOUT, 0};

    gettimeofday(&now, NULL);
    // ARP キャッシュアクセス
    mutex_lock(&mutex);
    {
        for (entry = caches; entry < tailof(caches); ++entry){
            // 未使用 / 静的エントリは除外
            if(entry->state!=ARP_CACHE_STATE_FREE && entry->state!=ARP_CACHE_STATE_STATIC) {
                // Exercise 16-3: タイムアウトしたエントリの削除
                timersub(&now, &entry->timestamp, &diff);
                if (timercmp(&diff, &to, >=)) arp_cache_delete(entry);
                // Exercise 16-3
            }
        }
    }
    mutex_unlock(&mutex);
}

int arp_init(void){
    struct timeval interval = {1, 0};   // 1s

    // Exercise 13-4: プロトコルスタックに ARP を登録
    if(net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1){
        errorf("net_protocol_register() failed");
        return -1;
    }
    // Exercise 13-4

    // Exercise 16-4: ARP のタイマーハンドラを登録
    if(net_timer_register(interval, arp_timer_handler) == -1){
        errorf("net_timer_register() failed");
        return -1;
    }
    // Exercise 16-4

    return 0;
}