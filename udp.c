#include "udp.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ip.h"
#include "platform.h"
#include "udp.h"
#include "util.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

// ref: https://tools.ietf.org/html/rfc6335
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

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

struct udp_pcb {
    int state;
    struct ip_endpoint local;  // 自分のアドレス/ポート番号
    struct queue_head queue;
    // int wc; // wait count (PCB を使用中のスレッド数)
    struct sched_ctx ctx;  // スケジューラが使うコンテキスト
};

struct udp_queue_entry {
    struct ip_endpoint foreign;  // 送信元のアドレス/ポート番号
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

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

/*
 *  UDP Protocol Control Block (PCB)
 *
 *  UDP PCB functions need mutex lock before calling
 */
static struct udp_pcb* udp_pcb_alloc(void) {
    struct udp_pcb* pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); ++pcb) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            sched_ctx_init(&pcb->ctx);  // コンテキスト初期化
            return pcb;
        }
    }
    return NULL;
}

static void udp_pcb_release(struct udp_pcb* pcb) {
    struct queue_entry* entry;

    /*
    // 使用中スレッドが存在するためクローズを保留
    if(pcb->wc){
        pcb->state = UDP_PCB_STATE_CLOSING;
        return;
    }
    */
    pcb->state = UDP_PCB_STATE_CLOSING;  // すぐに FREE になるとは限らない
    // エラー(-1) なら休止中のタスクが存在するので起床させてクローズ中であることを知らせる
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }

    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;

    while ((entry = queue_pop(&pcb->queue))) memory_free(entry);
}

static struct udp_pcb* udp_pcb_select(ip_addr_t addr, uint16_t port) {
    struct udp_pcb* pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); ++pcb) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            if ((pcb->local.addr == IP_ADDR_ANY ||  // IP_ADDR_ANY: wildcard(*)
                 addr == IP_ADDR_ANY ||
                 pcb->local.addr == addr) &&
                pcb->local.port == port) return pcb;
        }
    }
    return NULL;
}

static struct udp_pcb* udp_pcb_get(int id) {
    struct udp_pcb* pcb;

    if (id < 0 || id >= (int)countof(pcbs)) return NULL;  // out of range
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) return NULL;
    return pcb;
}

static int udp_pcb_id(struct udp_pcb* pcb) {
    return indexof(pcbs, pcb);
}

#define MEXIT(x)              \
    do {                      \
        mutex_unlock(&mutex); \
        return x;             \
    } while (0)

static void udp_input(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface) {
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr* hdr;
    char addr[2][IP_ADDR_STR_LEN];
    struct udp_pcb* pcb;
    struct udp_queue_entry* entry;

    // assert(len - sizeof(*hdr) >= 0);
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

    mutex_lock(&mutex);  // PCB へのアクセス
    {
        if (!(pcb = udp_pcb_select(dst, hdr->dst))) {  // 宛先アドレスとポート番号に対応する PCB を検索
            // port is not in use
            MEXIT();
        }

        // Exercise 19-1: 受信キューへデータを格納
        // 受信キューのエントリのメモリ確保
        if (!(entry = memory_alloc(sizeof(*entry) + len - sizeof(*hdr)))) {
            errorf("memory_alloc() failed");
            MEXIT();
        }
        // エントリの各項目に値を設定し、データをコピー
        entry->foreign.addr = pseudo.src;
        entry->foreign.port = hdr->src;
        entry->len = len - sizeof(*hdr);
        memcpy(entry->data, hdr + 1, entry->len);
        // PCB の受信キューにエントリをプッシュ
        if (!queue_push(&pcb->queue, entry)) {
            errorf("queue_push() failed");
            MEXIT();
        }
        // Exercise 19-1

        debugf("[PCB] queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
        sched_wakeup(&pcb->ctx);  // 受信キューへのエントリ追加を通知するため起床させる
    }
    mutex_unlock(&mutex);
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

static void event_handler(void* arg) {
    struct udp_pcb* pcb;

    (void)arg;
    mutex_lock(&mutex);
    {
        for (pcb = pcbs; pcb < tailof(pcbs); ++pcb) {
            // 有効な PCB のコンテキスト全てに割り込み発生
            if (pcb->state == UDP_PCB_STATE_OPEN) sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int udp_init(void) {
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
        errorf("ip_protocol_register() failed");
        return -1;
    }
    // イベントの講読 (ハンドラを設定)
    if (net_event_subscribe(event_handler, NULL) == -1) {
        errorf("net_event_subscribe() failed");
        return -1;
    }

    return 0;
}

/*
 *  UDP User Commands
 */
int udp_open(void) {
    // Exercise 19-2: UDP ソケットのオープン
    struct udp_pcb* pcb;
    mutex_lock(&mutex);  // PCB access
    {
        if (!(pcb = udp_pcb_alloc())) {
            errorf("udp_pcb_alloc() failed");
            MEXIT(-1);
        }
    }
    mutex_unlock(&mutex);
    // Exercise 19-2
    return udp_pcb_id(pcb);
}

int udp_bind(int id, struct ip_endpoint* local) {
    struct udp_pcb *pcb, *exist;
    char ep[2][IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    {
        // Exercise 19-4: UDP ソケットへアドレスとポート番号を紐付け
        if (!(pcb = udp_pcb_get(id))) {
            errorf("[PCB] id=%d not yet allocated");
            MEXIT(-1);
        }
        if ((exist = udp_pcb_select(local->addr, local->port))) {
            errorf("[PCB] pair of IP and port already in use: endpoint=%s, id=%d",
                   ip_endpoint_ntop(&exist->local, ep[0], sizeof(ep[0])),
                   udp_pcb_id(exist));
            MEXIT(-1);
        }
        pcb->local.addr = local->addr;
        pcb->local.port = local->port;

        // Exercise 19-4
    }
    mutex_unlock(&mutex);

    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep[0], sizeof(ep[0])));
    return 0;
}

ssize_t udp_sendto(int id, uint8_t* data, size_t len, struct ip_endpoint* foreign) {
    struct udp_pcb* pcb;
    struct ip_endpoint local;
    struct ip_iface* iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);
    {
        if (!(pcb = udp_pcb_get(id))) {
            errorf("pcb not found, id=%d", id);
            MEXIT(-1);
        }
        local.addr = pcb->local.addr;
        // 自分の使用アドレスがワイルドカードの場合、宛先アドレスに応じて送信元アドレスを自動的に選択
        if (local.addr == IP_ADDR_ANY) {
            // IP の経路情報から宛先に到達可能なインタフェースを取得
            if (!(iface = ip_route_get_iface(foreign->addr))) {
                errorf("iface by which foreign address is reachable not found, addr=%s",
                       ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
                MEXIT(-1);
            }
            // 取得したインタフェースのアドレスを使用
            local.addr = iface->unicast;
            debugf("selected local address, addr=%s",
                   ip_addr_ntop(local.addr, addr, sizeof(addr)));
        }

        // 自分の使用ポートが設定されていない場合、送信元ポート番号を自動的に選択
        if (!pcb->local.port) {
            // 未使用ポートを線形探索して使用ポートに設定
            for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; ++p) {
                if (!udp_pcb_select(local.addr, hton16(p))) {
                    pcb->local.port = hton16(p);
                    debugf("local port dynamically assigned, port=%d", p);
                    break;
                }
            }
            // 未使用ポート無しの場合
            if (!pcb->local.port) {
                debugf("failed to find assignable local port, addr=%s",
                       ip_addr_ntop(local.addr, addr, sizeof(addr)));
                MEXIT(-1);
            }
        }
        local.port = pcb->local.port;
    }
    mutex_unlock(&mutex);
    return udp_output(&local, foreign, data, len);
}

ssize_t udp_recvfrom(int id, uint8_t* buf, size_t size, struct ip_endpoint* foreign) {
    struct udp_pcb* pcb;
    struct udp_queue_entry* entry;
    ssize_t len;
    int err;

    mutex_lock(&mutex);  // PCB access
    {
        if (!(pcb = udp_pcb_get(id))) {
            errorf("pcb not found, id=%d", id);
            MEXIT(-1);
        }
        // 受信キューからエントリを取り出す
        while (!(entry = queue_pop(&pcb->queue))) {
            /*
            ++pcb->wc;
            // 受信キューへのエントリ追加を待つ
            {
                mutex_unlock(&mutex);
                sleep(1);
                mutex_lock(&mutex);
            }
            --pcb->wc;
            */

            // sched_wakeup() または sched_interrupt() が呼ばれるまで休止
            // エラー -> sched_interrupt() による起床なので EINTR を返す
            if ((err = sched_sleep(&pcb->ctx, &mutex, NULL))) {
                debugf("interrupted");
                errno = EINTR;
                MEXIT(-1);
            }

            if (pcb->state == UDP_PCB_STATE_CLOSING) {
                debugf("PCB closed");
                udp_pcb_release(pcb);
                MEXIT(-1);
            }
        }
    }
    mutex_unlock(&mutex);

    if (foreign) *foreign = entry->foreign;  // 送信元のアドレス/ポートをコピー
    len = MIN(size, entry->len);             // truncate
    memcpy(buf, entry->data, len);
    memory_free(entry);
    return len;
}

int udp_close(int id) {
    // Exercise 19-3: UDP ソケットのクローズ
    struct udp_pcb* pcb;
    mutex_lock(&mutex);
    {
        if (!(pcb = udp_pcb_get(id))) {
            errorf("[PCB] id=%d not yet allocated");
            MEXIT(-1);
        }
        udp_pcb_release(pcb);
    }
    mutex_unlock(&mutex);
    return 0;
    // Exercise 19-3
}