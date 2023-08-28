#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include "net.h"
#include "ip.h"

#define ARP_RESOLVE_ERROR       -1
#define ARP_RESOLVE_INCOMPLETE   0
#define ARP_RESOLVE_FOUND        1

extern int arp_queue_register(struct ip_iface* iface, const uint8_t* data, size_t len, ip_addr_t dst);

extern int arp_resolve(struct net_iface* iface, ip_addr_t pa, uint8_t* ha);

extern int arp_init(void);

#endif  // ARP_H