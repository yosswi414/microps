#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU   UINT16_MAX  // maximum size of IP datagram

#define DUMMY_IRQ   INTR_IRQ_BASE

static int dummy_transmit(
    struct net_device*  dev,
    uint16_t            type,
    const uint8_t*      data,
    size_t              len,
    const void*         dst
){
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    // drop data; do nothing
    intr_raise_irq(DUMMY_IRQ);  // テスト用に割り込みを発生
    return 0;
}

static int dummy_isr(unsigned int irq, void* id){
    // 呼び出されたことが分かればよいのでデバッグ出力のみ
    debugf("irq=%u, dev=%s", irq, ((struct net_device*)id)->name);
    return 0;
}

static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit,
};

struct net_device* dummy_init(void){
    struct net_device* dev;

    dev = net_device_alloc();
    if(!dev){
        errorf("net_device_alloc() failed");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_DUMMY;
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0;  // no header
    dev->alen = 0;  // no address
    dev->ops = &dummy_ops;
    if(net_device_register(dev) == -1){
        errorf("net_device_register() failed");
        return NULL;
    }
    // 割り込みハンドラとして dummy_isr() を登録
    intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
