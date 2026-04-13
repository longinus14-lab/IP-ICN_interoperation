#include <stdio.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include "pit.h"

static struct rte_hash    *pit_hash;
static struct rte_mempool *pit_pool;

/*
 * 期限切れエントリ走査用リスト。
 * エントリはmax_expire_tscの昇順で管理し、
 * pit_expire()が先頭から期限切れを削除できるようにする。
 *
 * expire_head.next : 最も早く期限切れになるエントリ
 * expire_head.prev : 最も遅く期限切れになるエントリ
 *
 * PITエントリにリンクフィールドを持たせるため、
 * pit_entry構造体の末尾に配置する (pit.h側は公開しない)。
 */
struct pit_entry_internal {
    struct pit_entry         pub;   /* 公開フィールド (pit.h) */
    struct pit_entry_internal *exp_prev;
    struct pit_entry_internal *exp_next;
};

static struct pit_entry_internal exp_head; /* センチネル */
static uint32_t pit_count;

/* ---- 期限切れリスト操作 ---- */

static inline void
exp_remove(struct pit_entry_internal *e)
{
    e->exp_prev->exp_next = e->exp_next;
    e->exp_next->exp_prev = e->exp_prev;
}

/*
 * max_expire_tscの昇順を維持しながら挿入する。
 * PITエントリ数は通常少ないため線形挿入で十分。
 * 大規模化する場合はタイムホイールに置き換える。
 */
static inline void
exp_insert_sorted(struct pit_entry_internal *e)
{
    struct pit_entry_internal *cur = exp_head.exp_next;
    while (cur != &exp_head &&
           cur->pub.max_expire_tsc <= e->pub.max_expire_tsc)
        cur = cur->exp_next;

    e->exp_next = cur;
    e->exp_prev = cur->exp_prev;
    cur->exp_prev->exp_next = e;
    cur->exp_prev = e;
}

/* ---- 初期化 ---- */

int
pit_init(void)
{
    /*
     * ハッシュテーブル:
     *   key     = uint32_t (NameワイヤエンコードのjhashValue)
     *   entries = PIT_MAX_ENTRIES * 2 (負荷率 ~0.5)
     *
     * InterestのNDNネームは高いエントロピーを持つため、
     * 32bitハッシュ衝突による偽ヒットは実用上無視できる。
     * 衝突時はcs_lookup()同様のフルネーム比較で解決する。
     */
    struct rte_hash_parameters params = {
        .name               = "pit_hash",
        .entries            = PIT_MAX_ENTRIES * 2,
        .key_len            = sizeof(uint32_t),
        .hash_func          = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id          = rte_socket_id(),
        .extra_flag         = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };
    pit_hash = rte_hash_create(&params);
    if (pit_hash == NULL) {
        printf("PIT: failed to create hash table\n");
        return -1;
    }

    /*
     * エントリプール:
     *   内部管理用のpit_entry_internalサイズで確保する。
     *   公開APIはpub (= struct pit_entry)へのポインタを返す。
     */
    pit_pool = rte_mempool_create("pit_pool",
                                  PIT_MAX_ENTRIES,
                                  sizeof(struct pit_entry_internal),
                                  0 /* キャッシュなし */,
                                  0, NULL, NULL, NULL, NULL,
                                  rte_socket_id(), 0);
    if (pit_pool == NULL) {
        printf("PIT: failed to create entry pool\n");
        return -1;
    }

    /* 期限切れリストのセンチネルを循環リストとして初期化 */
    exp_head.exp_next = &exp_head;
    exp_head.exp_prev = &exp_head;
    pit_count = 0;

    printf("PIT: initialized (max_entries=%u, max_in_records=%u)\n",
           PIT_MAX_ENTRIES, PIT_MAX_IN_RECORDS);
    return 0;
}

/* ---- 検索 ---- */

struct pit_entry *
pit_lookup(const uint8_t *name_wire, uint16_t name_wire_len)
{
    uint32_t hash = rte_jhash(name_wire, name_wire_len, 0);
    struct pit_entry_internal *entry;

    if (rte_hash_lookup_data(pit_hash, &hash, (void **)&entry) < 0)
        return NULL;

    /* ハッシュ衝突解決: フルNameのwire encodingをバイト比較 */
    if (entry->pub.name_wire_len != name_wire_len ||
        memcmp(entry->pub.name_wire, name_wire, name_wire_len) != 0)
        return NULL;

    /* 期限切れ確認: 全In-Recordが期限切れなら無効 */
    uint64_t now = rte_rdtsc();
    if (entry->pub.max_expire_tsc < now)
        return NULL;

    return &entry->pub;
}

/* ---- 挿入 (スタブ) ---- */

int
pit_insert(const uint8_t *name_wire, uint16_t name_wire_len,
           uint32_t face_id, uint32_t nonce,
           uint32_t interest_lifetime_ms)
{
    /* 今後実装: エントリの挿入・Interest集約処理 */
    (void)name_wire;
    (void)name_wire_len;
    (void)face_id;
    (void)nonce;
    (void)interest_lifetime_ms;
    return 0;
}

/* ---- 期限切れエントリの削除 ---- */

int
pit_expire(void)
{
    uint64_t now = rte_rdtsc();
    int removed = 0;

    /*
     * 期限切れリストは昇順に並んでいるため、
     * 先頭から期限切れでなくなったら即座に終了できる。
     */
    while (exp_head.exp_next != &exp_head) {
        struct pit_entry_internal *e = exp_head.exp_next;
        if (e->pub.max_expire_tsc >= now)
            break;

        rte_hash_del_key(pit_hash, &e->pub.name_hash);
        exp_remove(e);
        rte_mempool_put(pit_pool, e);
        pit_count--;
        removed++;
    }

    return removed;
}
