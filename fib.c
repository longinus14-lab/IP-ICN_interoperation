#include <stdio.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mempool.h>
#include "fib.h"

static struct rte_hash    *fib_hash;
static struct rte_mempool *fib_pool;

/* ---- VAR-NUMBER エンコード (TLV wire encoding 生成用) ---- */
static inline uint32_t
encode_var_number(uint64_t n, uint8_t *buf)
{
    if (n < 0xFD) {
        buf[0] = (uint8_t)n;
        return 1;
    } else if (n <= 0xFFFF) {
        buf[0] = 0xFD;
        buf[1] = (uint8_t)(n >> 8);
        buf[2] = (uint8_t)n;
        return 3;
    } else if (n <= 0xFFFFFFFF) {
        buf[0] = 0xFE;
        buf[1] = (uint8_t)(n >> 24);
        buf[2] = (uint8_t)(n >> 16);
        buf[3] = (uint8_t)(n >>  8);
        buf[4] = (uint8_t)n;
        return 5;
    } else {
        buf[0] = 0xFF;
        buf[1] = (uint8_t)(n >> 56);
        buf[2] = (uint8_t)(n >> 48);
        buf[3] = (uint8_t)(n >> 40);
        buf[4] = (uint8_t)(n >> 32);
        buf[5] = (uint8_t)(n >> 24);
        buf[6] = (uint8_t)(n >> 16);
        buf[7] = (uint8_t)(n >>  8);
        buf[8] = (uint8_t)n;
        return 9;
    }
}

/*
 * ---- プレフィックスのwire encoding を生成 ----
 *
 * struct ndn_name の先頭 n_comps 個のコンポーネントから
 * NameTLV wire encoding を buf に書き込む。
 *
 * 返り値: 書き込んだバイト数, バッファ不足の場合は -1
 */
static int
build_prefix_wire(const struct ndn_name *name, uint8_t n_comps,
                  uint8_t *buf, size_t buf_size)
{
    uint8_t tmp[9];
    uint32_t n;

    /* ---- 第1パス: コンポーネント部分の合計バイト数を計算 ---- */
    uint64_t value_len = 0;
    for (uint8_t i = 0; i < n_comps; i++) {
        const struct ndn_name_component *c = &name->components[i];
        /* type フィールドのエンコードサイズ */
        if      (c->type < 0xFD)      value_len += 1;
        else if (c->type <= 0xFFFF)   value_len += 3;
        else                           value_len += 5;
        /* length フィールドのエンコードサイズ */
        if      (c->length < 0xFD)    value_len += 1;
        else if (c->length <= 0xFFFF) value_len += 3;
        else                           value_len += 5;
        /* value バイト数 */
        value_len += c->length;
    }

    /* ---- 第2パス: wire encoding を buf に書き込む ---- */
    uint8_t *p   = buf;
    uint8_t *end = buf + buf_size;

    /* Name type = 0x07 */
    if (p >= end)
        return -1;
    *p++ = NDN_TLV_NAME;

    /* Name length */
    n = encode_var_number(value_len, tmp);
    if (p + n > end)
        return -1;
    memcpy(p, tmp, n);
    p += n;

    /* コンポーネントを順に書き込む */
    for (uint8_t i = 0; i < n_comps; i++) {
        const struct ndn_name_component *c = &name->components[i];

        /* type */
        n = encode_var_number(c->type, tmp);
        if (p + n > end)
            return -1;
        memcpy(p, tmp, n);
        p += n;

        /* length */
        n = encode_var_number(c->length, tmp);
        if (p + n > end)
            return -1;
        memcpy(p, tmp, n);
        p += n;

        /* value */
        if (p + c->length > end)
            return -1;
        memcpy(p, c->value, c->length);
        p += c->length;
    }

    return (int)(p - buf);
}

/* ---- 初期化 ---- */

int
fib_init(void)
{
    /*
     * ハッシュテーブル:
     *   key = uint32_t (プレフィックスwire encodingのrte_jhash値)
     *
     * LPM検索ではコンポーネント数を変えて複数回ルックアップを行うため、
     * 異なるプレフィックス長のエントリが同一テーブルに共存する。
     */
    struct rte_hash_parameters params = {
        .name               = "fib_hash",
        .entries            = FIB_MAX_ENTRIES * 2,
        .key_len            = sizeof(uint32_t),
        .hash_func          = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id          = rte_socket_id(),
        .extra_flag         = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };
    fib_hash = rte_hash_create(&params);
    if (fib_hash == NULL) {
        printf("FIB: failed to create hash table\n");
        return -1;
    }

    /* エントリプール */
    fib_pool = rte_mempool_create("fib_pool",
                                  FIB_MAX_ENTRIES,
                                  sizeof(struct fib_entry),
                                  0 /* キャッシュなし: FIBはデータパス外で更新 */,
                                  0, NULL, NULL, NULL, NULL,
                                  rte_socket_id(), 0);
    if (fib_pool == NULL) {
        printf("FIB: failed to create entry pool\n");
        return -1;
    }

    printf("FIB: initialized (max_entries=%u, max_nexthops=%u)\n",
           FIB_MAX_ENTRIES, FIB_MAX_NEXTHOPS);
    return 0;
}

/* ---- 最長プレフィックスマッチ検索 ---- */

struct fib_entry *
fib_lookup(const struct ndn_name *name)
{
    uint8_t prefix_wire[FIB_NAME_WIRE_MAX];

    /*
     * コンポーネント数を最大から0まで順に試し、最初にマッチしたものを返す。
     * - n_comps == 0 のケース: "/" (デフォルトルート) に相当
     * - 計算量: O(k) ハッシュルックアップ (k = コンポーネント数)
     */
    for (int8_t k = (int8_t)name->n_components; k >= 0; k--) {
        int len = build_prefix_wire(name, (uint8_t)k,
                                    prefix_wire, sizeof(prefix_wire));
        if (len < 0)
            continue;

        uint32_t hash = rte_jhash(prefix_wire, (uint32_t)len, 0);
        struct fib_entry *entry;

        if (rte_hash_lookup_data(fib_hash, &hash, (void **)&entry) < 0)
            continue;

        /* フルプレフィックス比較でハッシュ衝突を解決 */
        if (entry->name_wire_len == (uint16_t)len &&
            memcmp(entry->name_wire, prefix_wire, (size_t)len) == 0)
            return entry;
    }

    return NULL;
}

/* ---- 挿入 (スタブ) ---- */

int
fib_insert(const uint8_t *prefix_wire, uint16_t prefix_wire_len,
           uint32_t face_id, uint32_t cost)
{
    /* 今後実装: エントリの挿入処理 */
    (void)prefix_wire;
    (void)prefix_wire_len;
    (void)face_id;
    (void)cost;
    return 0;
}
