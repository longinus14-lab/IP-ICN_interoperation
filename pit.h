#ifndef PIT_H
#define PIT_H

#include <stdint.h>
#include "ndn.h"

/*
 * NDN Pending Interest Table (PIT)
 *
 * NDNフォワーディングの3つの主要データ構造のうちの1つ。
 * 転送済みInterestを記録し、対応するDataが到着した際に
 * どのFaceへ返送するかを管理する。
 *
 * 主な特徴:
 *   - 完全一致検索 (CSと同様、FIBのLPMとは異なる)
 *   - Interest集約: 同一Nameの複数InterestはPITエントリを共有
 *   - 各受信FaceはIn-Recordとして記録 (InterestLifetime付き)
 *   - Nonce記録: ループ検出に使用
 *
 * 実装方針:
 *   - rte_hash  : NameワイヤエンコードのjhashによるO(1)検索
 *   - rte_mempool: PITエントリのゼロマロック管理
 *   - 有効期限   : rte_rdtsc()ベースのタイムスタンプで管理
 */

#define PIT_MAX_ENTRIES      8192
#define PIT_MAX_IN_RECORDS   8    /* 1エントリあたりの最大受信Face数 */
#define PIT_NAME_WIRE_MAX    512  /* NameTLVのwire encodingの最大バイト数 */

/* ---- In-Record: Interestを受信したFaceの情報 ---- */
struct pit_in_record {
    uint32_t face_id;     /* 受信Face ID */
    uint32_t nonce;       /* Interestに含まれるNonce (ループ検出用) */
    uint64_t expire_tsc;  /* 有効期限: rte_rdtsc()値 */
};

/* ---- PITエントリ ---- */
struct pit_entry {
    /* Interest Name: NameTLVのwire encoding (Type + Length + Value) */
    uint8_t              name_wire[PIT_NAME_WIRE_MAX];
    uint16_t             name_wire_len;
    uint32_t             name_hash; /* rte_hash削除用 */

    /* In-Recordリスト: Interest集約 */
    uint8_t              n_in;
    struct pit_in_record in_records[PIT_MAX_IN_RECORDS];

    /* エントリ全体の最大有効期限 (In-Recordの中の最大値) */
    uint64_t             max_expire_tsc;
};

/*
 * PITを初期化する。
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int pit_init(void);

/*
 * NDN NameのTLV wire encodingでPITを完全一致検索する。
 *
 * 期限切れのエントリは返さない。
 *
 * name_wire     : NameTLVのwire encoding先頭ポインタ
 * name_wire_len : バイト数
 *
 * 返り値: マッチしたエントリへのポインタ、見つからない場合はNULL
 */
struct pit_entry *pit_lookup(const uint8_t *name_wire,
                             uint16_t name_wire_len);

/*
 * PITにInterestエントリを挿入/更新する。
 *
 * - 同一Nameのエントリが存在する場合はIn-Recordを追加 (Interest集約)
 * - 存在しない場合は新規エントリを作成
 * - n_in == PIT_MAX_IN_RECORDSに達している場合は失敗
 *
 * (現時点ではスタブ実装: エントリは追加しない)
 *
 * name_wire           : NameTLVのwire encoding
 * name_wire_len       : バイト数
 * face_id             : 受信FaceのID
 * nonce               : InterestのNonce値
 * interest_lifetime_ms: InterestLifetimeフィールドの値 (ms)
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int pit_insert(const uint8_t *name_wire, uint16_t name_wire_len,
               uint32_t face_id, uint32_t nonce,
               uint32_t interest_lifetime_ms);

/*
 * PITから期限切れのエントリを削除する。
 * データパスのバースト処理の合間に定期的に呼び出す想定。
 *
 * 返り値: 削除したエントリ数
 */
int pit_expire(void);

#endif /* PIT_H */
