#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/loopback.h"

#include "test.h"

#include "ip.h"
#include "icmp.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s){
    (void)s;
    terminate = 1;
}

static int setup(void){
    struct net_device* dev;
    struct ip_iface* iface;

    // シグナルハンドラの設定 (C-c に対してお行儀よく終了するように)
    signal(SIGINT, on_signal);

    // プロトコルスタックの初期化
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    // ループバックデバイスの初期化
    // デバイスドライバがプロトコルスタックへの登録まで済ませる
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failed");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failed");
        return -1;
    }

    // プロトコルスタックの起動
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void cleanup(void){
    net_shutdown();
}

int main(int argc, char* argv[]) {
    ip_addr_t src, dst;
    uint16_t id, seq = 0;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    size_t maxcnt = 1 << 30, lpcnt = 0;
    if (argc == 2) maxcnt = strtol(argv[1], NULL, 10);

    if(setup()== -1){
        errorf("setup() failed");
        return -1;
    }

    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src;
    id = getpid() % UINT16_MAX; // PID から id を採番

    // 1 秒おきにデバイスにパケット (test_data) を書き込む
    while (++lpcnt, !terminate) {
        // if(net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1){
        // if(ip_output(IP_PROTOCOL_ICMP, test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
        if(icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1){
            errorf("icmp_output() failed");
            break;
        }
        if (lpcnt >= maxcnt) break;
        // usleep(10 * 1000);
        usleep(1000 * 1000);
    }
    cleanup();
    return 0;
}