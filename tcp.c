#include "tcp.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ip.h"
#include "platform.h"
#include "util.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

#define MEXIT(x)              \
    do {                      \
        mutex_unlock(&mutex); \
        return x;             \
    } while (0)

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

struct tcp_segment_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

struct tcp_pcb {
    int state;  // コネクションの状態
    struct ip_endpoint local;
    struct ip_endpoint foreign;
    struct {
        uint32_t nxt;  // 次に送信するシーケンス番号
        uint32_t una;  // ACK が返ってきていない最後のシーケンス番号
        uint16_t wnd;  // 相手の受信ウィンドウ (受信バッファの空き状況)
        uint16_t up;   // 緊急ポインタ (今回未使用)
        uint32_t wl1;  // snd.wnd を更新した時の受信セグメントのシーケンス番号
        uint32_t wl2;  // snd.wnd を更新した時の受信セグメントの ACK 番号
    } snd;             // 送信時必要な情報
    uint32_t iss;      // 自分の初期シーケンス番号
    struct {
        uint32_t nxt;    // 次に受信を期待するシーケンス番号 (ACK で使われる)
        uint16_t wnd;    // 自分の受信ウィンドウ (受信バッファの空き状況)
        uint16_t up;     // 緊急ポインタ (今回未使用)
    } rcv;               // 受信時必要な情報
    uint32_t irs;        // 相手の初期シーケンス番号
    uint16_t mtu;        // 送信デバイスの MTU
    uint16_t mss;        // 最大セグメントサイズ
    uint8_t buf[65535];  // receive buffer
    struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

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

/*
 *  TCP Protocol Control Block (PCB)
 *  These should be called after mutex lock
 */
static struct tcp_pcb* tcp_pcb_alloc(void) {
    struct tcp_pcb* pcb;

    // CLOSED で初期化して返す
    for (pcb = pcbs; pcb < tailof(pcbs); ++pcb) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void tcp_pcb_release(struct tcp_pcb* pcb) {
    char ep[2][IP_ENDPOINT_STR_LEN];

    // PCB 利用中のタスクがいれば起床させる (解放を他のタスクに任せる)
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }

    debugf("released, local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep[0], sizeof(ep[0])),
           ip_endpoint_ntop(&pcb->foreign, ep[1], sizeof(ep[1])));
    memset(pcb, 0, sizeof(*pcb));  // pcb->state = TCP_PCB_STATE_FREE (0)
}

static struct tcp_pcb* tcp_pcb_select(struct ip_endpoint* local, struct ip_endpoint* foreign) {
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); ++pcb) {
        // ローカルアドレスがマッチ
        if ((pcb->local.addr == IP_ADDR_ANY ||
             pcb->local.addr == local->addr) &&
            pcb->local.port == local->port) {
            // ローカルアドレスに bind 可能かどうか調べるとき外部アドレスを指定せずに呼ばれる
            // ローカルアドレスがマッチしているので、そのまま pcb を返す
            if (!foreign) return pcb;
            // 外部アドレスもマッチ
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) return pcb;
            // 外部アドレスを指定せずに LISTEN しているなら任意の外部アドレスにマッチ (ローカル/外部ともにマッチしたものが優先)
            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                // LISTEN with wildcard foreign endpoint
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) listen_pcb = pcb;
            }
        }
    }
    return listen_pcb;
}

static struct tcp_pcb* tcp_pcb_get(int id) {
    struct tcp_pcb* pcb;

    if (id < 0 || id >= (int)countof(pcbs)) return NULL;  // out of range
    pcb = &pcbs[id];
    return pcb->state == TCP_PCB_STATE_FREE ? NULL : pcb;
}

static int tcp_pcb_id(struct tcp_pcb* pcb) {
    return indexof(pcbs, pcb);
}

static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t* data, size_t len, struct ip_endpoint* local, struct ip_endpoint* foreign) {
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr* hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep[2][IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr*)buf;

    // Exercise 23-1: TCP セグメント生成
    total = len + sizeof(*hdr);
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t*)&pseudo, sizeof(pseudo), 0);

    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;

    memcpy(hdr + 1, data, len);

    hdr->sum = cksum16((uint16_t*)hdr, total, psum);
    // Exercise 23-1

    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(local, ep[0], sizeof(ep[0])),
           ip_endpoint_ntop(foreign, ep[1], sizeof(ep[1])),
           total, len);
    tcp_dump((uint8_t*)hdr, total, -1);

    // Exercise 23-2: IP の送信関数呼び出し
    if (ip_output(IP_PROTOCOL_TCP, buf, total, local->addr, foreign->addr) == -1) {
        errorf("ip_output() failed");
        return -1;
    }
    // Exercise 23-2

    return len;
}

static ssize_t tcp_output(struct tcp_pcb* pcb, uint8_t flg, uint8_t* data, size_t len) {
    uint32_t seq;

    seq = pcb->snd.nxt;
    // SYN が指定されるのは初回送信時なので初期送信シーケンス番号を使用
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) seq = pcb->iss;
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        // TODO: add retransmission queue
    }
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

// rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES]
static void tcp_segment_arrives(struct tcp_segment_info* seg, uint8_t flags, uint8_t* data, size_t len, struct ip_endpoint* local, struct ip_endpoint* foreign) {
    struct tcp_pcb* pcb;
    int acceptable = 0;

    // 使用していないポート宛に届いた TCP セグメントの処理
    if (!(pcb = tcp_pcb_select(local, foreign)) || pcb->state == TCP_PCB_STATE_CLOSED) {
        // RST: 無視
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) return;
        // ACK なし: こちらからは何も送信していないと思われる 相手が送ってきたデータへの ACK 番号 (seg->seq + seg->len) を設定して RST 送信
        // ACK あり: こちらから何か送信していると思われる (以前に存在していたコネクションのセグメントが遅れて到着など) 相手から伝えられた ACK 番号を SEQ 番号に設定して RST 送信
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        else
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        return;
    }

    switch (pcb->state) {
        case TCP_PCB_STATE_LISTEN:
            // 1st check for RST
            if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) return;  // 無視
            // 2nd check for ACK
            if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
                // ACK が来たら RST を送信
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            // 3rd check for SYN
            if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
                // ignore: security/compartment check
                // ignore: precedence check
                pcb->local = *local;
                pcb->foreign = *foreign;
                pcb->rcv.wnd = sizeof(pcb->buf);
                pcb->rcv.nxt = seg->seq + 1;                          // 次に受信を期待するシーケンス番号 (ACK で使用される)
                pcb->irs = seg->seq;                                  // 初期受信シーケンス番号の保存
                pcb->iss = random();                                  // 初期送信シーケンス番号の採番 (乱数)
                tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);  // SYN + ACK
                pcb->snd.nxt = pcb->iss + 1;                          // 次に送信するシーケンス番号
                pcb->snd.una = pcb->iss;                              // ACK が返ってきていない最後のシーケンス番号
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED;              // SYN_RECEIVED へ移行
                /*  ignore: any other incoming control or data (combined with SYN)
                 *          will be processed in the SYN-RECEIVED state, but processing
                 *          of SYN and ACK should not be repeated
                 */
                return;
            }
            // 4th other text or control
            // drop segment
            return;
        case TCP_PCB_STATE_SYN_SENT:
            // 1st check the ACK bit
            // 2nd check the RST bit
            // 3rd check security and precedence (ignored)
            // 4th check the SYN bit
            // 5th drop the segment and return if neither SYN nor RST is set
            // drop segment
            return;
    }
    // Otherwise
    // 1st check sequence number
    switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
        case TCP_PCB_STATE_ESTABLISHED:
            // 受信セグメントにデータが無い場合
            if (!seg->len) {
                if (!pcb->rcv.wnd) {  // 受信バッファに空きが無い場合
                    // 次に期待しているシーケンス番号と一致するなら受け入れる
                    if (seg->seq == pcb->rcv.nxt) acceptable = 1;
                } else {  // 受信バッファに空きがある場合
                    // 次に期待しているシーケンス番号以上かつウィンドウの範囲内なら受け入れる
                    if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) acceptable = 1;
                }
            } else {                  // 受信セグメントにデータがある場合
                if (!pcb->rcv.wnd) {  // 受信バッファに空きが無い場合
                    // not acceptable
                } else {
                    // 新しいデータがウィンドウの範囲内なら受け入れる
                    // 後者: 受信データの中に受信済みデータを含む場合
                    if ((pcb->rcv.nxt <= seg->seq &&
                         seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                        (pcb->rcv.nxt <= seg->seq + seg->len - 1 &&
                         seg->seq + seg->len - 1 < pcb->rcv.nxt + pcb->rcv.wnd)) acceptable = 1;
                }
            }
            if (!acceptable) {  // セグメントを受け入れない
                if (!TCP_FLG_ISSET(flags, TCP_FLG_RST)) tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                return;
            }
            /*  以下ではセグメントは RCV.NXT から始まりウィンドウ内に収まる理想的な
             *  状態であるという仮定のもと扱われる。
             *  実際のセグメントをウィンドウに収まるようトリムし、RCV.NXT 以外から始まる
             *  セグメントは処理を進めないようにすることでこの仮定を満たしてもよい。
             *  RCV.NXT より後から始まるセグメントは後々のため保持されることがある。
             */
            /*  In the following it is assumed that the segment is the idealized
             *  segment that begins at RCV.NXT and does not exceed the window.
             *  One could tailor actual segments to fit this assumption by
             *  trimming off any portions that lie outside the window (including
             *  SYN and FIN), and only processing further if the segment then
             *  begins at RCV.NXT.  Segments with higher beginning sequence
             *  numbers may be held for later processing.
             */
    }
    // 2nd check the RST bit
    // 3rd check security and precedence (ignored)
    // 4th check the SYN bit
    // 5th check the ACK field
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) return;  // drop segment
    switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
            // 送信セグメントに対する妥当な ACK かどうか判断
            if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) {
                pcb->state = TCP_PCB_STATE_ESTABLISHED;
                sched_wakeup(&pcb->ctx);
            } else {  // 妥当な ACK でない場合
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            // fall through
            // ESTABLISHED で処理継続
        case TCP_PCB_STATE_ESTABLISHED:
            /*
             *        snd.una       snd.nxt
             *           v            v
             * ACK 確認済 | ACk 未確認 | 未送信
             * -------------------------------> ACK
             *     ^           ^          ^
             *    (2)         (1)        (3)
             */

            // if (pcb->snd.una <= seg->ack && seg->ack < pcb->snd.nxt) {  // (1) ACK 未確認 に対する ACK
            if (pcb->snd.una < seg->ack && seg->ack <= pcb->snd.nxt) {
                pcb->snd.una = seg->ack;  // ACK 確認済範囲を更新
                // TODO: Any segments on the retransmission queue which are thereby entirely acknowledged are removed
                // ignore: Users should receive positive acknowledgments for buffers
                //         which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" responce)
                // 最後にウィンドウの情報を更新した時より後に送信されたセグメントである場合
                if (pcb->snd.wl1 < seg->seq || (pcb->snd.wl1 == seg->seq && pcb->snd.wl2 <= seg->ack)) {
                    // ウィンドウ情報の更新が必要
                    pcb->snd.wnd = seg->wnd;
                    pcb->snd.wl1 = seg->seq;
                    pcb->snd.wl2 = seg->ack;
                }
            } else if (seg->ack < pcb->snd.una) {  // (2) ACK 確認済 に対する ACK
                // ignore
                // } else if (pcb->snd.nxt <= seg->ack) {  // (3) 未送信 に対する ACK
            } else if (pcb->snd.nxt < seg->ack) {  // (3) 未送信 に対する ACK
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                return;
            }
            break;
    }
    // 6th check the URG bit (ignored)
    // 7th process the segment text
    switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
            if (len) {
                // 受信データをバッファにコピーして ACK を返す
                // pcb->buf 末尾より RCV.WND バイトだけ前の部分からコピー
                memcpy(pcb->buf + (sizeof(pcb->buf) - pcb->rcv.wnd), data, len);
                pcb->rcv.nxt = seg->seq + seg->len;     // 次に期待するシーケンス番号を更新
                pcb->rcv.wnd -= len;                    // データ格納分だけウィンドウサイズを小さくする
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);  // 確認応答 (ACK)
                sched_wakeup(&pcb->ctx);                // 休止中のタスクを起床
            }
            break;
    }
    // 8th check the FIN bit
    return;
}

static void tcp_input(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface) {
    struct tcp_hdr* hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr[2][IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;

    if (len < sizeof(*hdr)) {
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
    if (cksum16((uint16_t*)hdr, len, psum)) {
        errorf("checksum mismatched, sum=0x%04x", cksum16((uint16_t*)data, len, psum));
        return;
    }
    // Exercise 22-3

    // Exercise 22-4: アドレスのチェック
    if (src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST) {
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

    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    hlen = (hdr->off >> 4) << 2;

    // tcp_segment_arrives() で必要な情報 (seg.*) を収集
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) ++seg.len;  // SYN consumes one SEQ number
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) ++seg.len;  // FIN consumes one SEQ number
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    {
        tcp_segment_arrives(&seg, hdr->flg, (uint8_t*)hdr + hlen, len - hlen, &local, &foreign);
    }
    mutex_unlock(&mutex);

    return;
}

static void event_handler(void* arg) {
    struct tcp_pcb* pcb;

    mutex_lock(&mutex);
    {
        for (pcb = pcbs; pcb < tailof(pcbs); ++pcb) {
            if (pcb->state != TCP_PCB_STATE_FREE) sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int tcp_init(void) {
    // Exercise 22-1: IP の上位プロトコルとして TCP を登録
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failed");
        return -1;
    }
    // Exercise 22-1

    net_event_subscribe(event_handler, NULL);
    return 0;
}

/*
 *  TCP User Command (RFC793)
 */
int tcp_open_rfc793(struct ip_endpoint* local, struct ip_endpoint* foreign, int active) {
    struct tcp_pcb* pcb;
    char ep[2][IP_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    {
        if (!(pcb = tcp_pcb_alloc())) {
            errorf("tcp_pcb_alloc() failed");
            MEXIT(-1);
        }
        if (active) {  // active open
            errorf("active open to be implemented");
            tcp_pcb_release(pcb);
            MEXIT(-1);
        } else {  // passive open
            debugf("passive open: local=%s, waiting for connection...",
                   ip_endpoint_ntop(local, ep[0], sizeof(ep[0])));
            pcb->local = *local;
            // RFC 793 では外部アドレスを限定した LISTEN が可能 (ソケット API では出来ない)
            if (foreign) pcb->foreign = *foreign;
            pcb->state = TCP_PCB_STATE_LISTEN;
        }

AGAIN:
        while (1) {
            state = pcb->state;
            // waiting for state to change
            while (pcb->state == state) {
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                    debugf("interrupted");
                    pcb->state = TCP_PCB_STATE_CLOSED;
                    tcp_pcb_release(pcb);
                    errno = EINTR;
                    MEXIT(-1);
                }
            }
            if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
                if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) goto AGAIN;  // リトライ
                errorf("open error: %d", pcb->state);
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
                MEXIT(-1);
            }
            break;
        }
        id = tcp_pcb_id(pcb);
        debugf("connection established: local=%s, foreign=%s",
               ip_endpoint_ntop(&pcb->local, ep[0], sizeof(ep[0])),
               ip_endpoint_ntop(&pcb->foreign, ep[1], sizeof(ep[1])));
    }
    mutex_unlock(&mutex);
    return id;
}

int tcp_close(int id) {
    struct tcp_pcb* pcb;

    mutex_lock(&mutex);
    {
        if (!(pcb = tcp_pcb_get(id))) {
            errorf("pcb not found, id=%d", id);
            MEXIT(-1);
        }
        // 暫定措置として RST を送信してコネクション破棄 (to be revised)
        tcp_output(pcb, TCP_FLG_RST, NULL, 0);
        tcp_pcb_release(pcb);
    }
    mutex_unlock(&mutex);
    return 0;
}

ssize_t tcp_send(int id, uint8_t* data, size_t len) {
    struct tcp_pcb* pcb;
    ssize_t sent = 0;
    struct ip_iface* iface;
    size_t mss, cap, slen;
    char ep[IP_ADDR_STR_LEN];

    mutex_lock(&mutex);
    {
        if(!(pcb=tcp_pcb_get(id))){
            errorf("pcb not found, id=%d", id);
            MEXIT(-1);
        }
RETRY:
        switch(pcb->state){
            case TCP_PCB_STATE_ESTABLISHED:
                // 送信に使われるインタフェースを取得
                if(!(iface = ip_route_get_iface(pcb->foreign.addr))){
                    errorf("iface not found, addr=%s", ip_addr_ntop(pcb->foreign.addr, ep, sizeof(ep)));
                    MEXIT(-1);
                }
                // Max Segment Size
                mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
                while(sent < (ssize_t) len){    // 全て送信し切るまでループ
                    cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una); // 相手の受信バッファ状況予測
                    if(!cap){   // 相手の受信バッファが空くまで待つ
                        if(sched_sleep(&pcb->ctx, &mutex, NULL) == -1){
                            debugf("interrupted");
                            if (sent > 0) break;    // 送信済バイトがある場合戻り値を返すため break
                            errno = EINTR;
                            MEXIT(-1);
                        }
                        goto RETRY; // スリープ後の状態変化を期待して再試行
                    }
                    slen = MIN(MIN(mss, len - sent), cap);  // MSS のサイズで分割して送信
                    // ACK は必要 PSH は飾り
                    if(tcp_output(pcb,TCP_FLG_ACK | TCP_FLG_PSH, data+sent, slen) == -1){
                        errorf("tcp_output() failed");
                        pcb->state = TCP_PCB_STATE_CLOSED;
                        tcp_pcb_release(pcb);
                        MEXIT(-1);
                    }
                    pcb->snd.nxt += slen;   // 次に送信するシーケンス番号更新
                    sent += slen;   // 送信済バイト数更新
                }
                break;
            default:
                errorf("unknown state '%u'", pcb->state);
                MEXIT(-1);
        }
    }
    mutex_unlock(&mutex);

    return sent;
}

ssize_t tcp_receive(int id, uint8_t* buf, size_t size) {
    struct tcp_pcb* pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    {
        if (!(pcb = tcp_pcb_get(id))) {
            errorf("pcb not found, id=%d", id);
            MEXIT(-1);
        }
RETRY:
        switch (pcb->state) {
            case TCP_PCB_STATE_ESTABLISHED:
                remain = sizeof(pcb->buf) - pcb->rcv.wnd;
                // 受信バッファにデータが存在しない場合はタスクを休止
                if (!remain) {
                    if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                        debugf("interrupted");
                        errno = EINTR;
                        MEXIT(-1);
                    }
                    goto RETRY;  // 状態変化を期待し再試行
                }
                break;
            default:
                errorf("unknown state '%u'", pcb->state);
                MEXIT(-1);
        }
        // buf に収まる分だけコピー
        len = MIN(size, remain);
        memcpy(buf, pcb->buf, len);
        // コピー済のデータを受信バッファから削除
        memmove(pcb->buf, pcb->buf + len, remain - len);
        pcb->rcv.wnd += len;
    }
    mutex_unlock(&mutex);
    return len;
}