#ifndef IPV4_H
#define IPV4_H

#include <rte_mbuf.h>

/*
 * IPv4処理: ヘッダフィールドの取得・検証とプロトコルによる分岐
 *
 * 返り値:
 *   1  : フォワード対象
 *   0  : ドロップ対象
 */
int process_ipv4(struct rte_mbuf *m);

#endif /* IPV4_H */
