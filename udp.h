#ifndef UDP_H
#define UDP_H

#include <rte_mbuf.h>
#include <rte_udp.h>

void process_udp(struct rte_mbuf *m, struct rte_udp_hdr *udp);

#endif /* UDP_H */
