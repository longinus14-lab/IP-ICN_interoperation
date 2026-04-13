#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "l2.h"
#include "ipv4.h"
#include "ndn.h"

/*
 * 注意: DPDKはNICハードウェアがFCSを検証済みのパケットのみ受け渡すため、
 *       ソフトウェアでのFCS再計算は不要。FCSエラーパケットはNICが破棄する。
 *       ハードウェアがFCSエラー検出をサポートする場合はmbuf->ol_flagsの
 *       RTE_MBUF_F_RX_L4_CKSUM_BAD等で確認できる。
 */
int
process_l2(struct rte_mbuf *m)
{
    /* パケット長の最小チェック（Ethernetヘッダ分） */
    if (m->pkt_len < RTE_ETHER_HDR_LEN) {
        printf("  DROP: packet too short (%u bytes)\n", m->pkt_len);
        return 0;
    }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    /* MACアドレス検証: 送信元がマルチキャストのパケットは不正として破棄 */
    if (rte_is_multicast_ether_addr(&eth->src_addr)) {
        printf("  DROP: multicast source MAC\n");
        return 0;
    }

    /* EtherTypeによる分岐 */
    switch (ether_type) {
    case RTE_ETHER_TYPE_IPV4:
        return process_ipv4(m);

    case RTE_ETHER_TYPE_IPV6:
        printf("  TYPE: IPv6\n");
        /* 今後: IPv6処理関数を呼び出す */
        break;

    case RTE_ETHER_TYPE_ARP:
        printf("  TYPE: ARP\n");
        /* 今後: ARP処理関数を呼び出す */
        break;

    case ETHER_TYPE_NDN:
        printf("  TYPE: NDN (0x8624)\n");
        process_ndn(m);
        break;

    default:
        printf("  DROP: unknown EtherType 0x%04x\n", ether_type);
        return 0;
    }

    return 1;
}
