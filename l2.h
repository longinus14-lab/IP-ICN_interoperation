#ifndef L2_H
#define L2_H

#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

/* NDNのEtherTypeは0x8624 */
#define ETHER_TYPE_NDN  0x8624

/*
 * L2処理: パケットの妥当性チェックとEtherTypeによる分岐
 *
 * 返り値:
 *   1  : フォワード対象（転送する）
 *   0  : ドロップ対象（転送しない）
 */
int process_l2(struct rte_mbuf *m);

/*
 * パケット送信ラッパー: 送信前にパケット情報をログ出力する。
 * 送信できなかったmbufは解放する。
 *
 * port : 送信ポートID
 * bufs : 送信するmbuf配列
 * nb   : 送信するmbuf数
 *
 * 返り値: 実際に送信できたパケット数
 */
static inline uint16_t
tx_burst_log(uint16_t port, struct rte_mbuf **bufs, uint16_t nb)
{
    for (uint16_t i = 0; i < nb; i++) {
        struct rte_ether_hdr *eth =
            rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
        printf("TX [port%u] len=%u  src=%02x:%02x:%02x:%02x:%02x:%02x"
               " -> dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
               port, bufs[i]->pkt_len,
               RTE_ETHER_ADDR_BYTES(&eth->src_addr),
               RTE_ETHER_ADDR_BYTES(&eth->dst_addr));
    }
    uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb);
    for (uint16_t i = nb_tx; i < nb; i++)
        rte_pktmbuf_free(bufs[i]);
    return nb_tx;
}

#endif /* L2_H */
