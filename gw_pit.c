#include <stdio.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include "gw_pit.h"

static struct rte_hash    *gw_pit_hash;
static struct rte_mempool *gw_pit_pool;

/*
 * 期限切れエントリ走査用リスト。
 * エントリはmax_expire_tscの昇順で管理し、
 * gw_pit_expire()が先頭から期限切れを削除できるようにする。
 *
 * リンクフィールドは公開APIに露出させないため内部型で管理する。
 */
struct gw_pit_entry_internal {
    struct gw_pit_entry          pub;      /* 公開フィールド (gw_pit.h) */
    struct gw_pit_entry_internal *exp_prev;
    struct gw_pit_entry_internal *exp_next;
};

static struct gw_pit_entry_internal exp_head; /* センチネル */
static uint32_t gw_pit_count;

/* ---- 期限切れリスト操作 ---- */

static inline void
exp_remove(struct gw_pit_entry_internal *e)
{
    e->exp_prev->exp_next = e->exp_next;
    e->exp_next->exp_prev = e->exp_prev;
}

/*
 * max_expire_tscの昇順を維持しながら挿入する。
 * エントリ数が少ない想定のため線形挿入。
 * 大規模化する場合はタイムホイールに置き換える。
 */
static inline void
exp_insert_sorted(struct gw_pit_entry_internal *e)
{
    struct gw_pit_entry_internal *cur = exp_head.exp_next;
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
gw_pit_init(void)
{
    struct rte_hash_parameters params = {
        .name               = "gw_pit_hash",
        .entries            = GW_PIT_MAX_ENTRIES * 2,
        .key_len            = sizeof(uint32_t),
        .hash_func          = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id          = rte_socket_id(),
        .extra_flag         = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };
    gw_pit_hash = rte_hash_create(&params);
    if (gw_pit_hash == NULL) {
        printf("GW_PIT: failed to create hash table\n");
        return -1;
    }

    gw_pit_pool = rte_mempool_create("gw_pit_pool",
                                     GW_PIT_MAX_ENTRIES,
                                     sizeof(struct gw_pit_entry_internal),
                                     0,
                                     0, NULL, NULL, NULL, NULL,
                                     rte_socket_id(), 0);
    if (gw_pit_pool == NULL) {
        printf("GW_PIT: failed to create entry pool\n");
        return -1;
    }

    exp_head.exp_next = &exp_head;
    exp_head.exp_prev = &exp_head;
    gw_pit_count = 0;

    printf("GW_PIT: initialized (max_entries=%u, max_in_records=%u)\n",
           GW_PIT_MAX_ENTRIES, GW_PIT_MAX_IN_RECORDS);
    return 0;
}

/* ---- 検索 ---- */

struct gw_pit_entry *
gw_pit_lookup(const uint8_t *name_wire, uint16_t name_wire_len)
{
    uint32_t hash = rte_jhash(name_wire, name_wire_len, 0);
    struct gw_pit_entry_internal *entry;

    if (rte_hash_lookup_data(gw_pit_hash, &hash, (void **)&entry) < 0)
        return NULL;

    /* ハッシュ衝突解決: フルNameのwire encodingをバイト比較 */
    if (entry->pub.name_wire_len != name_wire_len ||
        memcmp(entry->pub.name_wire, name_wire, name_wire_len) != 0)
        return NULL;

    /* 全In-Recordが期限切れなら無効 */
    if (entry->pub.max_expire_tsc < rte_rdtsc())
        return NULL;

    return &entry->pub;
}

/* ---- 挿入 ---- */

int
gw_pit_insert(const uint8_t *name_wire, uint16_t name_wire_len,
              const struct conn_key *key, struct tcb *tcb,
              uint32_t interest_lifetime_ms)
{
    if (name_wire_len > GW_PIT_NAME_WIRE_MAX)
        return -1;

    uint32_t hash = rte_jhash(name_wire, name_wire_len, 0);
    uint64_t expire_tsc = rte_rdtsc() +
                          (uint64_t)interest_lifetime_ms * rte_get_tsc_hz() / 1000;

    struct gw_pit_entry_internal *entry = NULL;

    if (rte_hash_lookup_data(gw_pit_hash, &hash, (void **)&entry) >= 0) {
        /* ハッシュ衝突チェック: 別名が同じhashを持つ場合は挿入不可 */
        if (entry->pub.name_wire_len != name_wire_len ||
            memcmp(entry->pub.name_wire, name_wire, name_wire_len) != 0)
            return -1;

        if (entry->pub.n_in >= GW_PIT_MAX_IN_RECORDS)
            return -1;

        /* コンテンツ集約: 既存エントリにIn-Recordを追加 */
        struct gw_pit_in_record *rec = &entry->pub.in_records[entry->pub.n_in++];
        rec->conn_key   = *key;
        rec->tcb        = tcb;
        rec->expire_tsc = expire_tsc;

        /* 有効期限が延びた場合は期限切れリストを再挿入 */
        if (expire_tsc > entry->pub.max_expire_tsc) {
            entry->pub.max_expire_tsc = expire_tsc;
            exp_remove(entry);
            exp_insert_sorted(entry);
        }

        return 0;
    }

    /* 新規エントリを作成 */
    if (gw_pit_count >= GW_PIT_MAX_ENTRIES)
        return -1;

    if (rte_mempool_get(gw_pit_pool, (void **)&entry) != 0)
        return -1;

    memset(entry, 0, sizeof(*entry));
    memcpy(entry->pub.name_wire, name_wire, name_wire_len);
    entry->pub.name_wire_len          = name_wire_len;
    entry->pub.name_hash              = hash;
    entry->pub.n_in                   = 1;
    entry->pub.in_records[0].conn_key = *key;
    entry->pub.in_records[0].tcb      = tcb;
    entry->pub.in_records[0].expire_tsc = expire_tsc;
    entry->pub.max_expire_tsc         = expire_tsc;

    if (rte_hash_add_key_data(gw_pit_hash, &hash, entry) < 0) {
        rte_mempool_put(gw_pit_pool, entry);
        return -1;
    }

    exp_insert_sorted(entry);
    gw_pit_count++;

    return 0;
}

/* ---- 期限切れエントリの削除 ---- */

int
gw_pit_expire(void)
{
    uint64_t now = rte_rdtsc();
    int removed = 0;

    while (exp_head.exp_next != &exp_head) {
        struct gw_pit_entry_internal *e = exp_head.exp_next;
        if (e->pub.max_expire_tsc >= now)
            break;

        rte_hash_del_key(gw_pit_hash, &e->pub.name_hash);
        exp_remove(e);
        rte_mempool_put(gw_pit_pool, e);
        gw_pit_count--;
        removed++;
    }

    return removed;
}
