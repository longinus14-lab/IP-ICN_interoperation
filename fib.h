#ifndef FIB_H
#define FIB_H

#include <stdint.h>
#include "ndn.h"

/*
 * NDN Forwarding Information Base (FIB)
 *
 * NDNフォワーディングの3つの主要データ構造のうちの1つ。
 * Interestパケットのネームプレフィックスをネクストホップ(Face)に対応付ける。
 *
 * 設計方針:
 *   - 最長プレフィックスマッチ (LPM): コンポーネント数を減らしながら
 *     複数回rte_hash検索を行う (O(k), k=コンポーネント数)
 *   - rte_hash : プレフィックスのwire encodingのjhashをキーとする
 *   - rte_mempool: FIBエントリのゼロマロック管理
 *   - 1エントリに複数ネクストホップ (マルチパス転送対応)
 */

#define FIB_MAX_ENTRIES      1024
#define FIB_MAX_NEXTHOPS     8    /* 1エントリあたりの最大ネクストホップ数 */
#define FIB_NAME_WIRE_MAX    512  /* プレフィックスTLVのwire encodingの最大バイト数 */

/* ---- ネクストホップ ---- */
struct fib_nexthop {
    uint32_t face_id; /* 転送先FaceのID */
    uint32_t cost;    /* ルーティングコスト (小さいほど優先) */
};

/* ---- FIBエントリ ---- */
struct fib_entry {
    /* プレフィックス: NameTLVのwire encoding (Type + Length + Value) */
    uint8_t           name_wire[FIB_NAME_WIRE_MAX];
    uint16_t          name_wire_len;
    uint32_t          name_hash;      /* fib_evict()でのrte_hash削除に使用 */

    /* ネクストホップリスト */
    uint8_t           n_nexthops;
    struct fib_nexthop nexthops[FIB_MAX_NEXTHOPS];
};

/*
 * FIBを初期化する。
 * rte_hash と rte_mempool を作成する。
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int fib_init(void);

/*
 * NDN NameをFIBで最長プレフィックスマッチ検索する。
 *
 * コンポーネント数を最大から1ずつ減らしながらrte_hashを検索し、
 * 最初にマッチしたエントリを返す。
 *
 * name : 解析済みNDN Name
 *
 * 返り値: マッチしたFIBエントリへのポインタ、見つからない場合はNULL
 */
struct fib_entry *fib_lookup(const struct ndn_name *name);

/*
 * FIBにプレフィックスエントリを挿入する。
 * 同一プレフィックスが存在する場合はネクストホップを追加する。
 *
 * (現時点ではスタブ実装: エントリは追加しない)
 *
 * prefix_wire     : プレフィックスNameTLVのwire encoding
 * prefix_wire_len : バイト数
 * face_id         : 転送先FaceのID
 * cost            : ルーティングコスト
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int fib_insert(const uint8_t *prefix_wire, uint16_t prefix_wire_len,
               uint32_t face_id, uint32_t cost);

#endif /* FIB_H */
