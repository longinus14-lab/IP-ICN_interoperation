#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <rte_hash.h>
#include <rte_mempool.h>
#include <rte_ether.h>

/* コネクションテーブルの最大エントリ数 */
#define MAX_CONNECTIONS     65536
/* TCBプールのオブジェクト数 (MAX_CONNECTIONSと同数) */
#define TCB_POOL_SIZE       (MAX_CONNECTIONS - 1)

/* ---------- 4タプルキー ---------- */
struct conn_key {
    uint32_t src_addr;  /* 送信元IPアドレス (ネットワークバイトオーダー) */
    uint32_t dst_addr;  /* 宛先IPアドレス   (ネットワークバイトオーダー) */
    uint16_t src_port;  /* 送信元ポート     (ネットワークバイトオーダー) */
    uint16_t dst_port;  /* 宛先ポート       (ネットワークバイトオーダー) */
} __attribute__((packed));

/* ---------- TCPコネクション状態 ---------- */
typedef enum {
    TCP_CLOSED      = 0,
    TCP_SYN_RCVD,       /* SYN受信済み */
    TCP_ESTABLISHED,    /* コネクション確立済み */
    TCP_FIN_WAIT,       /* FIN送信済み */
    TCP_CLOSE_WAIT,     /* 相手からFIN受信済み */
    TCP_TIME_WAIT,      /* 両方向FIN完了・タイムアウト待ち */
} tcp_state_t;

/* CCNx名前の最大ワイヤ長 (gw_pit.hのGW_PIT_NAME_WIRE_MAXと同値) */
#define TCB_CCN_NAME_WIRE_MAX   512

/* ---------- TCP Control Block ---------- */
struct tcb {
    tcp_state_t state;

    /* 送信側シーケンス管理 */
    uint32_t snd_nxt;   /* 次に送信するシーケンス番号 */
    uint32_t snd_una;   /* 未確認の最小シーケンス番号 */
    uint16_t snd_wnd;   /* 送信ウィンドウサイズ */

    /* 受信側シーケンス管理 */
    uint32_t rcv_nxt;   /* 次に期待する受信シーケンス番号 */
    uint16_t rcv_wnd;   /* 受信ウィンドウサイズ */

    /* パケット構築用: 通信相手のMACアドレス (SYN受信時またはSYN送信相手) */
    struct rte_ether_addr peer_mac;

    /*
     * アウトゴイング接続フラグ
     *   0 = incoming (IPホスト → ゲートウェイ)
     *   1 = outgoing (ゲートウェイ → IPホスト, CCN→IP方向)
     */
    uint8_t is_outgoing;

    /* CCN要求元情報 (is_outgoing==1 のときのみ有効) */
    uint8_t  ccn_name_wire[TCB_CCN_NAME_WIRE_MAX]; /* CCN Interest のNameワイヤ */
    uint16_t ccn_name_wire_len;
    uint32_t ccn_src_ip;                           /* CCN Interest 送信元IP (NBO) */
    uint16_t ccn_src_port;                         /* CCN Interest 送信元UDPポート (NBO) */
    struct rte_ether_addr ccn_src_mac;             /* CCN Interest 送信元MAC */
};

/* ---------- グローバルテーブル ---------- */
extern struct rte_hash    *conn_table;
extern struct rte_mempool *tcb_pool;

/* ---------- 関数プロトタイプ ---------- */
int  conn_table_init(void);
struct tcb *conn_lookup(const struct conn_key *key);
struct tcb *conn_insert(const struct conn_key *key);
void conn_delete(const struct conn_key *key);

#endif /* CONNECTION_H */
