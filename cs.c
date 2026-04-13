#include <stdio.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include "cs.h"

static struct rte_hash   *cs_hash;
static struct rte_mempool *cs_pool;

/*
 * LRU双方向リストのセンチネルノード。
 *   lru_head.lru_next : MRU (最近使用されたエントリ)
 *   lru_head.lru_prev : LRU (最も古いエントリ)
 */
static struct cs_entry lru_head;
static uint32_t cs_count;

/* ---- LRUリスト操作 (inline: 高速化) ---- */

static inline void
lru_remove(struct cs_entry *e)
{
    e->lru_prev->lru_next = e->lru_next;
    e->lru_next->lru_prev = e->lru_prev;
}

static inline void
lru_push_front(struct cs_entry *e)
{
    e->lru_next = lru_head.lru_next;
    e->lru_prev = &lru_head;
    lru_head.lru_next->lru_prev = e;
    lru_head.lru_next = e;
}

/* ---- 初期化 ---- */

int
cs_init(void)
{
    /*
     * ハッシュテーブル:
     *   key     = uint32_t (name_wireのrte_jhash値)
     *   entries = CS_MAX_ENTRIES * 2 (負荷率 ~0.5 でリハッシュ回避)
     *
     * 注意: 異なるNameが同一のhash値を持つ場合(衝突)、
     *       cs_lookup()内のフルネーム比較でキャッシュミス扱いになる。
     *       CSはキャッシュであり正確性に影響しないため許容する。
     */
    struct rte_hash_parameters params = {
        .name               = "cs_hash",
        .entries            = CS_MAX_ENTRIES * 2,
        .key_len            = sizeof(uint32_t),
        .hash_func          = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id          = rte_socket_id(),
        .extra_flag         = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };
    cs_hash = rte_hash_create(&params);
    if (cs_hash == NULL) {
        printf("CS: failed to create hash table\n");
        return -1;
    }

    /* エントリプール */
    cs_pool = rte_mempool_create("cs_pool",
                                 CS_MAX_ENTRIES,
                                 sizeof(struct cs_entry),
                                 64 /* per-lcore cache */,
                                 0, NULL, NULL, NULL, NULL,
                                 rte_socket_id(), 0);
    if (cs_pool == NULL) {
        printf("CS: failed to create entry pool\n");
        return -1;
    }

    /* LRUセンチネルを循環リストとして初期化 */
    lru_head.lru_next = &lru_head;
    lru_head.lru_prev = &lru_head;
    cs_count = 0;

    printf("CS: initialized (max_entries=%u, name_max=%u bytes)\n",
           CS_MAX_ENTRIES, CS_NAME_WIRE_MAX);
    return 0;
}

/* ---- 検索 ---- */

struct cs_entry *
cs_lookup(const uint8_t *name_wire, uint16_t name_wire_len)
{
    uint32_t hash = rte_jhash(name_wire, name_wire_len, 0);
    struct cs_entry *entry;

    if (rte_hash_lookup_data(cs_hash, &hash, (void **)&entry) < 0)
        return NULL;

    /* ハッシュ衝突解決: フルNameのwire encodingをバイト比較 */
    if (entry->name_wire_len != name_wire_len ||
        memcmp(entry->name_wire, name_wire, name_wire_len) != 0)
        return NULL;

    /* Freshnessチェック: FreshnessPeriodが設定されている場合のみ */
    if (entry->freshness_period_ms > 0) {
        uint64_t elapsed_ms = (rte_rdtsc() - entry->insert_tsc)
                              * 1000ULL / rte_get_timer_hz();
        if (elapsed_ms > entry->freshness_period_ms) {
            printf("  CS: stale entry name_len=%u elapsed=%lums\n",
                   name_wire_len, elapsed_ms);
            return NULL;
        }
    }

    /* LRUリストをMRU位置に更新 */
    lru_remove(entry);
    lru_push_front(entry);

    return entry;
}

/* ---- 挿入 (スタブ) ---- */

int
cs_insert(const uint8_t *name_wire, uint16_t name_wire_len,
          const uint8_t *content, uint32_t content_len,
          uint8_t content_type, uint32_t freshness_period_ms)
{
    /* 今後実装: エントリの挿入処理 */
    (void)name_wire;
    (void)name_wire_len;
    (void)content;
    (void)content_len;
    (void)content_type;
    (void)freshness_period_ms;
    return 0;
}

/* ---- LRU退避 ---- */

int
cs_evict(void)
{
    if (cs_count == 0)
        return 0;

    /* LRUリストの末尾 = 最も古いエントリ */
    struct cs_entry *lru = lru_head.lru_prev;
    if (lru == &lru_head)
        return 0;

    rte_hash_del_key(cs_hash, &lru->name_hash);
    lru_remove(lru);
    rte_mempool_put(cs_pool, lru);
    cs_count--;

    return 1;
}
