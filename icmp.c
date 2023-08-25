#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ip.h"
#include "util.h"
#include "icmp.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t values;
};

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

static char* icmp_type_ntoa(uint8_t type) {
    switch (type) {
        case ICMP_TYPE_ECHOREPLY:
            return "EchoReply";
        case ICMP_TYPE_DEST_UNREACH:
            return "DestinationUnreachable";
        case ICMP_TYPE_SOURCE_QUENCH:
            return "SourceQuench";
        case ICMP_TYPE_REDIRECT:
            return "Redirect";
        case ICMP_TYPE_ECHO:
            return "Echo";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "TimeExceeded";
        case ICMP_TYPE_PARAM_PROBLEM:
            return "ParameterProblem";
        case ICMP_TYPE_TIMESTAMP:
            return "Timestamp";
        case ICMP_TYPE_TIMESTAMPREPLY:
            return "TimestampReply";
        case ICMP_TYPE_INFO_REQUEST:
            return "InformationRequest";
        case ICMP_TYPE_INFO_REPLY:
            return "InformationReply";
    }
    return "Unknown";
}

// static void icmp_dump(const uint8_t* data, size_t len) {
//     struct icmp_hdr* hdr;
//     struct icmp_echo* echo;
//
//     hdr = (struct icmp_hdr*)data;
//
//     flockfile(stderr);
//     {
//         // 共通フィールド
//         fprintf(stderr, "ICMP |     type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
//         fprintf(stderr, "ICMP |     code: %u\n", hdr->code);
//         fprintf(stderr, "ICMP |      sum: 0x%04x\n", ntoh16(hdr->sum));
//
//         // 固有フィールド
//         switch (hdr->type) {
//             case ICMP_TYPE_ECHOREPLY:
//             case ICMP_TYPE_ECHO:
//                 echo = (struct icmp_echo*)hdr;
//                 fprintf(stderr, "ICMP |       id: %u\n", ntoh16(echo->id));
//                 fprintf(stderr, "ICMP |      seq: %u\n", ntoh16(echo->seq));
//                 break;
//             default:
//                 fprintf(stderr, "ICMP |   values: 0x%08x\n", ntoh32(hdr->values));
//                 break;
//         }
// #ifdef HEXDUMP
//         hexdump(stderr, data, len);
// #endif
//     }
//     funlockfile(stderr);
// }

static void icmp_dump(const uint8_t* data, size_t len, int inout) {
    struct icmp_hdr* hdr;
    struct icmp_echo* echo;

    char arrows[3][5] = {"    ", "I>> ", "O<< "};
    char* arrow;
    if (inout < 0)
        arrow = arrows[2];
    else
        arrow = arrows[inout > 0];

    hdr = (struct icmp_hdr*)data;

    flockfile(stderr);
    {
        // 共通フィールド
        fprintf(stderr, "%sICMP |     type: %u (%s)\n", arrow, hdr->type, icmp_type_ntoa(hdr->type));
        fprintf(stderr, "%sICMP |     code: %u\n", arrow, hdr->code);
        fprintf(stderr, "%sICMP |      sum: 0x%04x\n", arrow, ntoh16(hdr->sum));

        // 固有フィールド
        switch (hdr->type) {
            case ICMP_TYPE_ECHOREPLY:
            case ICMP_TYPE_ECHO:
                echo = (struct icmp_echo*)hdr;
                fprintf(stderr, "%sICMP |       id: %u\n", arrow, ntoh16(echo->id));
                fprintf(stderr, "%sICMP |      seq: %u\n", arrow, ntoh16(echo->seq));
                break;
            default:
                fprintf(stderr, "%sICMP |   values: 0x%08x\n", arrow, ntoh32(hdr->values));
                break;
        }
#ifdef HEXDUMP
        hexdump(stderr, data, len);
#endif
    }
    funlockfile(stderr);
}

void icmp_input(const uint8_t* data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface* iface) {
    struct icmp_hdr* hdr;

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    const int inout = 1;    // input

    hdr = (struct icmp_hdr*)data;

    // Exercise 10-1: ICMP メッセージの検証
    if(len < ICMP_HDR_SIZE){
        errorf("length %u too short (< ICMP_HDR_SIZE = %u)", len, ICMP_HDR_SIZE);
        return;
    }
    uint16_t chk = cksum16((uint16_t*)data, len, 0);
    if (chk) {
        errorf("checksum mismatched (calc: 0x%04x)", chk);
        return;
    }
    // Exercise 10-1

    debugf("%s => %s, len=%zu",
           ip_addr_ntop(src, addr1, sizeof(addr1)),
           ip_addr_ntop(dst, addr2, sizeof(addr2)),
           len);
    icmp_dump(data, len, inout);

    switch(hdr->type){
        case ICMP_TYPE_ECHO:
            // responds with the addressof the received interface
            // Exercise 11-3: ICMP の出力関数を呼び出す
            if(icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values,
                (uint8_t*)(hdr + 1), len - sizeof(*hdr), iface->unicast, src) < 0){
                errorf("icmp_output() failed");
                return;
            }
            // Exercise 11-3
            break;
        case ICMP_TYPE_ECHOREPLY:
            // infof("reply confirmed");
            break;
        default:
            // unsupported type
            break;
    }
}

int icmp_output(
    uint8_t type,
    uint8_t code,
    uint32_t values,
    const uint8_t* data,
    size_t len,
    ip_addr_t src,
    ip_addr_t dst
){
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr* hdr;
    size_t msg_len; // ICMP メッセージの長さ (header + data)
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    const int inout = -1;   // output

    hdr = (struct icmp_hdr*)buf;

    // Exercise 11-1: ICMP メッセージの生成
    // header
    hdr->type = type;
    hdr->code = code;
    hdr->values = values;   // no need to hton*()
    hdr->sum = 0;
    // data
    memcpy(hdr + 1, data, len);
    // length
    msg_len = sizeof(*hdr) + len;
    // checksum
    hdr->sum = cksum16((uint16_t*)buf, msg_len, 0);
    // Exercise 11-1

    debugf("%s => %s, len=%zu",
           ip_addr_ntop(src, addr1, sizeof(addr1)),
           ip_addr_ntop(dst, addr2, sizeof(addr2)),
           msg_len);
    icmp_dump(buf, msg_len, inout);

    // Exercise 11-2: IP の出力関数を呼び出してメッセージを送信
    return ip_output(IP_PROTOCOL_ICMP, buf, msg_len, src, dst);
    // Exercise 11-2
}

int icmp_init(void) {
    // Exercise 9-4: ICMP の入力関数 icmp_input() を IP に登録
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1) {
        errorf("ip_protocol_register() failed");
        return -1;
    }
    // Exercise 9-4

    return 0;
}