#ifndef TCP_H
#define TCP_H

#include <rte_mbuf.h>
#include <rte_tcp.h>
#include "connection.h"

int process_tcp(struct rte_mbuf *m, struct rte_tcp_hdr *tcp,
                const struct conn_key *key);

/*
 * CCN Name TLV wire encoding から URI パスを生成するヘルパー。
 * tcp.c で定義、ccn.c / ccn_builder.c から参照可能。
 */
void build_uri_from_name_wire(const uint8_t *name_wire, uint16_t name_wire_len,
                               char *uri_out, size_t uri_max);

#endif /* TCP_H */
