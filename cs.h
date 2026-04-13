#ifndef CS_H
#define CS_H

#include <stdint.h>

/*
 * NDN Content Store (CS)
 *
 * NDNフォワーディングの3つの主要データ構造のうちの1つ。
 * Dataパケットをキャッシュし、同一Nameに対するInterestを
 * アップストリームに転送せずにローカルで応答する。
 *
 * 実装方針:
 *   - rte_hash  : NameワイヤエンコードのjhashをキーとするO(1)検索
 *   - rte_mempool: CSエントリのゼロマロック管理
 *   - LRUリスト  : 容量超過時の退避ポリシー
 *   - ゼロコピー  : Contentはmbuf内データへのポインタで保持
 */

#define CS_MAX_ENTRIES      4096
#define CS_NAME_WIRE_MAX    512  /* NameTLVのwire encodingの最大バイト数 */

/* ---- Content Store エントリ ---- */
struct cs_entry {
    /* NDN Name: NameTLV全体のwire encoding (Type + Length + Value) */
    uint8_t          name_wire[CS_NAME_WIRE_MAX];
    uint16_t         name_wire_len;
    uint32_t         name_hash; /* cs_evict()でrte_hash削除に使用 */

    /* Data パケットの Content フィールド */
    const uint8_t   *content;          /* NULL = ContentなしのDataパケット */
    uint32_t         content_len;
    uint8_t          content_type;     /* NDN_CONTENT_TYPE_* */

    /* 鮮度管理 */
    uint32_t         freshness_period_ms; /* 0 = 即時stale */
    uint64_t         insert_tsc;          /* 挿入時のrte_rdtsc()値 */

    /* LRU 双方向リンクリスト */
    struct cs_entry *lru_prev; /* より新しいエントリ */
    struct cs_entry *lru_next; /* より古いエントリ */
};

/*
 * Content Storeを初期化する。
 * rte_hash と rte_mempool を作成し、LRUリストを初期化する。
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int cs_init(void);

/*
 * NDN NameのTLV wire encodingでContent Storeを検索する。
 *
 * - FreshnessPeriodが切れているエントリはキャッシュミスとして扱う
 * - ヒット時はLRUリストの先頭(MRU位置)に移動する
 *
 * name_wire     : NameTLVのwire encoding先頭ポインタ
 * name_wire_len : バイト数
 *
 * 返り値: ヒットしたエントリへのポインタ、キャッシュミスの場合はNULL
 */
struct cs_entry *cs_lookup(const uint8_t *name_wire, uint16_t name_wire_len);

/*
 * DataパケットのエントリをContent Storeに挿入する。
 * CS_MAX_ENTRIESに達している場合はLRUエントリを退避してから挿入する。
 *
 * (現時点ではスタブ実装: エントリは追加しない)
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int cs_insert(const uint8_t *name_wire, uint16_t name_wire_len,
              const uint8_t *content, uint32_t content_len,
              uint8_t content_type, uint32_t freshness_period_ms);

/*
 * LRUポリシーに基づいてContent Storeから最も古いエントリを1つ削除する。
 *
 * 返り値: 削除したエントリ数 (0 = 空)
 */
int cs_evict(void);

#endif /* CS_H */
