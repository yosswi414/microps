#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

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

    // Ethernet デバイスの初期化
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if(!dev){
        errorf("ether_tap_init() failed");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if(!iface){
        errorf("ip_iface_alloc() failed");
        return -1;
    }
    if(ip_iface_register(dev, iface) == -1){
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

    signal(SIGINT, on_signal);
    if(setup() == -1){
        errorf("setup() failed");
        return -1;
    }

    // OS から見えている TAP デバイスの IP アドレスを宛先に
    ip_addr_pton("192.0.2.2", &src);
    ip_addr_pton("192.0.2.1", &dst);
    id = getpid() % UINT16_MAX;

    while (!terminate) {
        infof("### head of loop ###");
        if(icmp_output(ICMP_TYPE_ECHO, 0, hton32(id<<16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1){
            errorf("icmp_output() failed");
            break;
        }
        infof("### tail of loop ###");
        sleep(1);
    }
    cleanup();
}