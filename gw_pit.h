#ifndef GW_PIT_H
#define GW_PIT_H

#include <stdint.h>
#include "ndn.h"
#include "connection.h"

/*
 * Gateway PIT (gw_pit)
 *
 * 標準NDN PITを本ゲートウェイ向けに改造したテーブル。
 * 「要求コンテンツ名」と「要求元ホストのTCPコネクション」を対応付け、
 * NDNネットワークからDataが返ってきた際にどのIPホストへ
 * 応答すればよいかを解決する。
 *
 * 標準PITとの差異:
 *   標準PIT : コンテンツ名 → 受信Face ID
 *   gw_pit  : コンテンツ名 → 要求元ホストのTCPコネクション (conn_key + tcb*)
 *
 * 主な特徴:
 *   - 完全一致検索
 *   - コンテンツ集約: 同一コンテンツ名への複数リクエストはエントリを共有
 *   - 各要求元はIn-Recordとして記録 (有効期限付き)
 *
 * 実装方針:
 *   - rte_hash  : NameワイヤエンコードのjhashによるO(1)検索
 *   - rte_mempool: エントリのゼロマロック管理
 *   - 有効期限   : rte_rdtsc()ベースのタイムスタンプで管理
 */

#define GW_PIT_MAX_ENTRIES      8192
#define GW_PIT_MAX_IN_RECORDS   8    /* 1エントリあたりの最大要求元コネクション数 */
#define GW_PIT_NAME_WIRE_MAX    512  /* NameTLVのwire encodingの最大バイト数 */

/* ---- In-Record: コンテンツを要求したIPホストのコネクション情報 ---- */
struct gw_pit_in_record {
    struct conn_key  conn_key;    /* 要求元ホストの4タプル (照合・応答先特定用) */
    struct tcb      *tcb;         /* 要求元ホストのTCB (応答パケット生成時に参照) */
    uint64_t         expire_tsc;  /* 有効期限: rte_rdtsc()値 */
};

/* ---- gw_pitエントリ ---- */
struct gw_pit_entry {
    /* コンテンツ名: NameTLVのwire encoding (Type + Length + Value) */
    uint8_t                  name_wire[GW_PIT_NAME_WIRE_MAX];
    uint16_t                 name_wire_len;
    uint32_t                 name_hash;  /* rte_hash削除用 */

    /* In-Recordリスト: コンテンツ集約 */
    uint8_t                  n_in;
    struct gw_pit_in_record  in_records[GW_PIT_MAX_IN_RECORDS];

    /* エントリ全体の最大有効期限 (In-Recordの中の最大値) */
    uint64_t                 max_expire_tsc;
};

/*
 * gw_pitを初期化する。
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int gw_pit_init(void);

/*
 * コンテンツ名のTLV wire encodingでgw_pitを完全一致検索する。
 *
 * 期限切れのエントリは返さない。
 *
 * name_wire     : NameTLVのwire encoding先頭ポインタ
 * name_wire_len : バイト数
 *
 * 返り値: マッチしたエントリへのポインタ、見つからない場合はNULL
 */
struct gw_pit_entry *gw_pit_lookup(const uint8_t *name_wire,
                                   uint16_t name_wire_len);

/*
 * gw_pitにエントリを挿入/更新する。
 *
 * - 同一コンテンツ名のエントリが存在する場合はIn-Recordを追加 (コンテンツ集約)
 * - 存在しない場合は新規エントリを作成
 * - n_in == GW_PIT_MAX_IN_RECORDSに達している場合は失敗
 *
 * (現時点ではスタブ実装: エントリは追加しない)
 *
 * name_wire           : NameTLVのwire encoding
 * name_wire_len       : バイト数
 * key                 : 要求元ホストの4タプル
 * tcb                 : 要求元ホストのTCBポインタ
 * interest_lifetime_ms: 有効期限 (ms)
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int gw_pit_insert(const uint8_t *name_wire, uint16_t name_wire_len,
                  const struct conn_key *key, struct tcb *tcb,
                  uint32_t interest_lifetime_ms);

/*
 * gw_pitから期限切れのエントリを削除する。
 * データパスのバースト処理の合間に定期的に呼び出す想定。
 *
 * 返り値: 削除したエントリ数
 */
int gw_pit_expire(void);

#endif /* GW_PIT_H */
