#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "driver/ether_tap.h"
#include "driver/loopback.h"
#include "icmp.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "udp.h"
#include "util.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
    close(0);   // close STDIN
}

static int setup(void) {
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

    // Ethernet デバイスの初期化
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failed");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failed");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failed");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failed");
        return -1;
    }

    // プロトコルスタックの起動
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void cleanup(void) {
    net_shutdown();
}


#define TRY(f) TRY2(f, do {} while(0))

#define TRY2(f, end)               \
    do {                          \
        if ((f) == -1) {          \
            errorf(#f " failed"); \
            end;                  \
            return -1;            \
        }                         \
    } while (0)

int main(int argc, char* argv[]) {
    int soc;
    struct ip_endpoint foreign;
    uint8_t buf[1024];

    TRY(setup());
    TRY(soc = udp_open());
    ip_endpoint_pton("192.0.2.1:10007", &foreign);  // 宛先
    while (!terminate) {
        if (!fgets((char*)buf, sizeof(buf), stdin)) break;  // stdin から 1 行読み込み
        if(udp_sendto(soc, buf, strlen((char*)buf), &foreign)==-1){
            errorf("udp_sendto() failed");
            break;
        }
    }
    udp_close(soc);
    cleanup();
    return 0;
}