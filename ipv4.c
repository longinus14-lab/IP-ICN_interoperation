#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "connection.h"

int
process_ipv4(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(
        m, struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);

    /* バージョン確認 */
    if ((ip->version_ihl >> 4) != 4) {
        printf("  DROP: IPv4 invalid version\n");
        return 0;
    }

    /* IPヘッダ長 */
    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr)) {
        printf("  DROP: IPv4 header too short (%u bytes)\n", ihl);
        return 0;
    }

    /* パケット長がmbufに収まるか確認 */
    uint16_t total_len = rte_be_to_cpu_16(ip->total_length);
    if (total_len < ihl || (uint32_t)RTE_ETHER_HDR_LEN + total_len > m->pkt_len) {
        printf("  DROP: IPv4 invalid total_length\n");
        return 0;
    }

    /* TTL確認（0はドロップ、ルータなので1も転送前にデクリメントして0になるためドロップ） */
    if (ip->time_to_live <= 1) {
        printf("  DROP: IPv4 TTL expired (ttl=%u)\n", ip->time_to_live);
        return 0;
    }

    /* 必要フィールドを変数に格納 */
    uint32_t src_addr  = rte_be_to_cpu_32(ip->src_addr);
    uint32_t dst_addr  = rte_be_to_cpu_32(ip->dst_addr);
    uint8_t  proto     = ip->next_proto_id;
    uint8_t  ttl       = ip->time_to_live;
    uint16_t ip_id     = rte_be_to_cpu_16(ip->packet_id);
    uint16_t fragment  = rte_be_to_cpu_16(ip->fragment_offset);

    printf("  IPv4 src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u ttl=%u id=%u\n",
           (src_addr >> 24) & 0xff, (src_addr >> 16) & 0xff,
           (src_addr >>  8) & 0xff,  src_addr        & 0xff,
           (dst_addr >> 24) & 0xff, (dst_addr >> 16) & 0xff,
           (dst_addr >>  8) & 0xff,  dst_addr        & 0xff,
           proto, ttl, ip_id);

    /* フラグメントパケットは現時点では非対応としてドロップ */
    if (fragment & RTE_IPV4_HDR_MF_FLAG ||
        (fragment & RTE_IPV4_HDR_OFFSET_MASK) != 0) {
        printf("  DROP: IPv4 fragmented packet\n");
        return 0;
    }

    /* TTLデクリメント（チェックサム再計算はハードウェアオフロードがない場合は手動） */
    ip->time_to_live--;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* L4プロトコルによる分岐 */
    void *l4 = (uint8_t *)ip + ihl;

    switch (proto) {
    case IPPROTO_TCP: {
        struct conn_key key = {
            .src_addr = ip->src_addr,
            .dst_addr = ip->dst_addr,
            .src_port = ((struct rte_tcp_hdr *)l4)->src_port,
            .dst_port = ((struct rte_tcp_hdr *)l4)->dst_port,
        };
        return process_tcp(m, (struct rte_tcp_hdr *)l4, &key);
    }
    case IPPROTO_UDP:
        process_udp(m, (struct rte_udp_hdr *)l4);
        break;
    default:
        printf("  DROP: unsupported IPv4 proto=%u\n", proto);
        return 0;
    }

    return 1;
}
