#define _GNU_SOURCE  // for F_SETSIG
#include "driver/ether_tap.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ether.h"
#include "net.h"
#include "platform.h"
#include "util.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE + 2)

struct ether_tap {
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

#define PRIV(x) ((struct ether_tap*)x->priv)

// Ethernet デバイス (TAP) HW アドレスの取得
static int ether_tap_addr(struct net_device* dev) {
    int soc;
    struct ifreq ifr = {};  // ioctl() で使うリクエスト/レスポンス兼用の構造体

    // 何かソケットをオープンする
    // ioctl() の SIOCGIFHWADDR 要求がソケットとして開かれたディスクリプタでのみ有効であるため
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if(soc==-1){
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    // ハードウェアアドレスを取得したいデバイスの名前を設定
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);
    // ハードウェアアドレスの取得を要求
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1){
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    // 取得したアドレスをデバイス構造体へコピー
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int ether_tap_open(struct net_device* dev) {
    struct ether_tap* tap;
    struct ifreq ifr = {};  // ioctl() で使うリクエスト/レスポンス兼用の構造体

    tap = PRIV(dev);
    // TUN/TAP の制御用デバイスをオープン
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1) {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1);  // TAP デバイスの名前設定
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;                         // フラグ設定 (IFF_TAP: TAP モード、IFF_NO_PI: パケット情報ヘッダを付けない)

    // TAP デバイスの登録要求
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    // シグナル駆動 I/O のための設定
    // set asynchronous I/O signal delivery destination
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // enable asynchronous I/O
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // use other signal instead of SIGIO
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    // HW アドレスが明示的に設定されていない場合
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        // OS 側から見えている TAP デバイスの HW アドレスを取得して使用
        if (ether_tap_addr(dev) == -1) {
            errorf("ether_tap_addr() failed, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }
    return 0;
}

static int ether_tap_close(struct net_device* dev) {
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t ether_tap_write(struct net_device* dev, const uint8_t* frame, size_t flen) {
    return write(PRIV(dev)->fd, frame, flen);
}

int ether_tap_transmit(struct net_device* dev, const uint16_t type, const uint8_t* buf, size_t len, const void* dst) {
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

static ssize_t ether_tap_read(struct net_device* dev, uint8_t* buf, size_t size) {
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);
    if(len <= 0){
        if(len == -1 && errno != EINTR) {
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

static int ether_tap_isr(unsigned int irq, void* id) {
    struct net_device* dev;
    struct pollfd pfd;
    int ret;

    dev = (struct net_device*)id;
    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;
    while(1){
        ret = poll(&pfd, 1, 0); // タイムアウト時間を 0 に設定した poll() で読み込み可能なデータの存在を確認
        if(ret == -1){
            if (errno == EINTR) continue;   // EINTR はシグナルに割り込まれたという回復可能なエラー
            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        }
        if (ret == 0) break;    // ret == 0: タイムアウト (読み込み可能なデータ無し)
        ether_input_helper(dev, ether_tap_read);    // 読み込み可能なら読みに行く
    }
    return 0;
}
static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

// Ethernet デバイス (TAP) の生成
struct net_device* ether_tap_init(const char* name, const char* addr) {
    struct net_device* dev;
    struct ether_tap* tap;

    // デバイス生成
    dev = net_device_alloc();
    if(!dev){
        errorf("net_device_alloc() failed");
        return NULL;
    }

    ether_setup_helper(dev);    // Ethernet デバイスの共通パラメータを設定
    // 引数でハードウェアアドレスの文字列が渡されたらバイト列に変換して設定
    if(addr){
        if(ether_addr_pton(addr, dev->addr) == -1){
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    dev->ops = &ether_tap_ops;  // ドライバの関数部を設定
    // ドライバ内部で使用するプライベートなデータを生成および保持
    tap = memory_alloc(sizeof(*tap));
    if(!tap){
        errorf("memory_alloc() failed");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name) - 1);
    tap->fd = -1;   // 初期値は無効な値
    tap->irq = ETHER_TAP_IRQ;
    dev->priv = tap;

    // デバイスをプロトコルスタックに登録
    if(net_device_register(dev) == -1){
        errorf("net_device_register() failed");
        memory_free(tap);
        return NULL;
    }
    // 割り込みハンドラ登録
    intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}