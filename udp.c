#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "udp.h"
#include "ccn.h"

void
process_udp(struct rte_mbuf *m, struct rte_udp_hdr *udp)
{
    uint16_t src_port  = rte_be_to_cpu_16(udp->src_port);
    uint16_t dst_port  = rte_be_to_cpu_16(udp->dst_port);
    uint16_t dgram_len = rte_be_to_cpu_16(udp->dgram_len);

    printf("    UDP src_port=%u dst_port=%u len=%u\n",
           src_port, dst_port, dgram_len);

    /* UDPヘッダ長 (8バイト) 未満はドロップ */
    if (dgram_len < sizeof(struct rte_udp_hdr))
        return;

    uint16_t payload_len = dgram_len - (uint16_t)sizeof(struct rte_udp_hdr);
    const uint8_t *payload = (const uint8_t *)(udp + 1);

    if (dst_port == CCN_UDP_PORT) {
        /*
         * CCN→IP 変換に必要な送信元情報を上位ヘッダから取得する。
         * IPv4ヘッダ: UDP ヘッダの直前
         * Ethernet ヘッダ: IPv4 ヘッダの直前
         */
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((uint8_t *)udp -
                                   sizeof(struct rte_ipv4_hdr));
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)((uint8_t *)ip -
                                     RTE_ETHER_HDR_LEN);

        process_ccn(m, payload, (uint32_t)payload_len,
                    ip->src_addr,          /* 送信元IP (NBO) */
                    udp->src_port,         /* 送信元UDPポート (NBO) */
                    &eth->src_addr);       /* 送信元MAC */
        return;
    }

    /* 今後: その他のUDPポートの処理を実装 */
}
