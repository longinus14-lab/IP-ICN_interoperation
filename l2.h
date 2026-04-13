#ifndef L2_H
#define L2_H

#include <rte_mbuf.h>

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

#endif /* L2_H */
