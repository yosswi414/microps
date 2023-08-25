#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/loopback.h"

#include "test.h"

#include "ip.h"

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
    size_t offset = IP_HDR_SIZE_MIN;

    if(setup()== -1){
        errorf("setup() failed");
        return -1;
    }

    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src;

    // 1 秒おきにデバイスにパケット (test_data) を書き込む
    while(!terminate) {
        // if(net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1){
        if(ip_output(1, test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
            errorf("ip_output() failed");
            break;
        }
        sleep(1);
    }
    cleanup();
    return 0;
}