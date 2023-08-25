#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct net_protocol{
    struct net_protocol* next;
    uint16_t type;
    struct queue_head queue;    // input queue
    void (*handler)(const uint8_t* data, size_t len, struct net_device* dev);
};

struct net_protocol_queue_entry {
    struct net_device* dev;
    size_t len;
    uint8_t data[];
};

// You need to protect the lists with mutex if you add/delete entries after net_run()
static struct net_device* devices;
static struct net_protocol* protocols;

struct net_device* net_device_alloc(void){
    struct net_device* dev;

    /*  デバイス構造体のサイズのメモリを確保
     *  - memory_alloc() で確保したメモリ領域は zerofill されている
     *  - メモリが確保できなければエラーとして NULL を返す
     *  メモリの確保/開放には memory_alloc() / memory_free() を使う
     */
    dev = memory_alloc(sizeof(*dev));
    if(!dev){
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

// You must not call this after net_run()
int net_device_register(struct net_device *dev){
    static unsigned int index = 0;

    // デバイスのインデックス番号を設定
    dev->index = index++;
    // デバイス名を生成 (net0, net1, ...)
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    // デバイスリストの先頭に追加 (push_front)
    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int net_device_open(struct net_device* dev){
    debugf("ndo 1 dev=%s", dev->name);
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("device already open, dev=%s", dev->name);
        return -1;
    }
    debugf("ndo 2");
    if(dev->ops->open){
        debugf("ndo 2-1 %08x", dev->ops->open);
        if (dev->ops->open(dev) == -1) {
            errorf("open() failed, dev=%s", dev->name);
            return -1;
        }
    }
    debugf("ndo 3");
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device* dev){
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("device already closed, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("close() failed, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

// This should not be called after net_run()
int net_device_add_iface(struct net_device* dev, struct net_iface* iface){
    struct net_iface* entry;

    // 重複登録の確認
    for (entry = dev->ifaces; entry; entry = entry->next){
        if(entry->family == iface->family){
            // 重複あり
            // 簡単のためここでは 1 つのデバイスにつき同一 family のインタフェースは
            // 1 つまで登録されるものとする
            errorf("already registered family detected, dev=%s, family=%d", dev->name, entry->family);
            return -1;
        }
    }
    iface->dev = dev;
    // Exercise 7-1: デバイスのインタフェースリストの先頭に iface を挿入
    iface->next = dev->ifaces;
    dev->ifaces = iface;
    // Exercise 7-1
    return 0;
}

struct net_iface* net_device_get_iface(struct net_device* dev, int family){
    // Exercise 7-2: デバイスに紐づくインタフェースを検索
    struct net_iface* iface;
    for (iface = dev->ifaces; iface; iface = iface->next){
        if (iface->family == family) return iface;
    }
    return NULL;
    // Exercise 7-2
}

int net_device_output(
    struct net_device* dev,
    uint16_t type,
    const uint8_t *data,
    size_t len,
    const void *dst
){
    if(!NET_DEVICE_IS_UP(dev)){
        errorf("not open, dev=%s", dev->name);
        return -1;
    }

    if(len > dev->mtu){
        errorf("too large, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if(dev->ops->transmit(dev, type, data, len, dst) == -1){
        errorf("device transmission failed, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

int net_protocol_register(uint16_t type, void (*handler)(const uint8_t* data, size_t len, struct net_device* dev)){
    struct net_protocol* proto;

    // 重複確認
    for (proto = protocols; proto; proto = proto->next){
        if(type == proto->type){
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    // プロトコル構造体のメモリを確保
    proto = memory_alloc(sizeof(*proto));
    if(!proto){
        errorf("memory_alloc() failed");
        return -1;
    }

    proto->type = type;
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);
    return 0;
}

// デバイスが受信したパケットをプロトコルスタックに渡す
int net_input_handler(
    uint16_t            type,
    const uint8_t*      data,
    size_t              len,
    struct net_device*  dev
){
    struct net_protocol* proto;
    struct net_protocol_queue_entry* entry;

    for (proto = protocols; proto; proto=proto->next){
        if(proto->type == type){
            // Exercise 4-1: プロトコルの受信キューにエントリを挿入
            entry = memory_alloc(sizeof(*entry) + len);
            if(!entry){
                errorf("memory_alloc() failed");
                return -1;
            }
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);
            if (!queue_push(&proto->queue, entry)) {
                errorf("queue_push() failed");
                return -1;
            }
            // memory_free(entry);
            // Exercise 4-1
            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
                proto->queue.num, dev->name, type, len);
            debugdump(data, len);
            intr_raise_irq(INTR_IRQ_SOFTIRQ);   // net_softirq_handler()
            return 0;
        }
    }

    // unsupported protocol
    return 0;
}

// ソフトウェア割り込みハンドラ
int net_softirq_handler(void){
    struct net_protocol* proto;
    struct net_protocol_queue_entry* entry;

    // プロトコルを巡回し、それぞれの受信キューからエントリを取り出し、入力関数 (proto->handler()) に渡す
    for (proto = protocols; proto;proto=proto->next){
        while ((entry = queue_pop(&proto->queue))) {
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            proto->handler(entry->data, entry->len, entry->dev);
            memory_free(entry);
        }
    }
    return 0;
}

int net_run(void){
    struct net_device* dev;

    // 割り込み機構の起動
    debugf("starting interrupt system...");
    if (intr_run() == -1) {
        errorf("intr_run() failed");
        return -1;
    }

    debugf("opening all devices...");
    for (dev = devices; dev; dev = dev->next) net_device_open(dev);
    debugf("running...");
    return 0;
}

void net_shutdown(void){
    struct net_device* dev;

    debugf("closing all devices...");
    for (dev = devices; dev; dev = dev->next) net_device_close(dev);

    // 割り込み機構の停止
    debugf("terminating interrupt system...");
    intr_shutdown();

    debugf("shutting down...");
}

int net_init(void){
    if(intr_init() == -1){
        errorf("intr_init() failed");
        return -1;
    }
    if(ip_init() == -1){
        errorf("ip_init() failed");
        return -1;
    }
    infof("initialized");
    return 0;
}
