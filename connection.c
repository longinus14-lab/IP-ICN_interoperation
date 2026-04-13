#include <stdio.h>
#include <string.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mempool.h>
#include <rte_errno.h>

#include "connection.h"

struct rte_hash    *conn_table = NULL;
struct rte_mempool *tcb_pool   = NULL;

int
conn_table_init(void)
{
    /* ハッシュテーブル作成 */
    struct rte_hash_parameters params = {
        .name               = "conn_table",
        .entries            = MAX_CONNECTIONS,
        .key_len            = sizeof(struct conn_key),
        .hash_func          = rte_jhash,        /* 高速なJenkinsハッシュ */
        .hash_func_init_val = 0,
        .socket_id          = rte_socket_id(),
        /* シングルスレッドのためロックフリー動作 */
        .extra_flag         = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };

    conn_table = rte_hash_create(&params);
    if (conn_table == NULL) {
        fprintf(stderr, "Failed to create conn_table: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }

    /* TCBオブジェクトプール作成 (hugepageから確保) */
    tcb_pool = rte_mempool_create(
        "tcb_pool",
        TCB_POOL_SIZE,
        sizeof(struct tcb),
        0,          /* キャッシュなし (シングルスレッド) */
        0,
        NULL, NULL, NULL, NULL,
        rte_socket_id(),
        0);
    if (tcb_pool == NULL) {
        fprintf(stderr, "Failed to create tcb_pool: %s\n",
                rte_strerror(rte_errno));
        rte_hash_free(conn_table);
        conn_table = NULL;
        return -1;
    }

    printf("Connection table initialized: max=%u entries\n", MAX_CONNECTIONS);
    return 0;
}

/*
 * 4タプルでTCBを検索する
 * 返り値: 見つかった場合はTCBポインタ、なければNULL
 */
struct tcb *
conn_lookup(const struct conn_key *key)
{
    struct tcb *tcb = NULL;
    int ret = rte_hash_lookup_data(conn_table, key, (void **)&tcb);
    return (ret >= 0) ? tcb : NULL;
}

/*
 * 新規コネクションを登録し、TCBを返す
 * 返り値: 確保したTCBポインタ、失敗時はNULL
 */
struct tcb *
conn_insert(const struct conn_key *key)
{
    struct tcb *tcb = NULL;

    if (rte_mempool_get(tcb_pool, (void **)&tcb) != 0) {
        fprintf(stderr, "conn_insert: TCB pool exhausted\n");
        return NULL;
    }

    memset(tcb, 0, sizeof(*tcb));
    tcb->state = TCP_CLOSED;

    if (rte_hash_add_key_data(conn_table, key, tcb) < 0) {
        fprintf(stderr, "conn_insert: hash table full\n");
        rte_mempool_put(tcb_pool, tcb);
        return NULL;
    }

    return tcb;
}

/*
 * コネクションをテーブルから削除しTCBをプールに返却する
 */
void
conn_delete(const struct conn_key *key)
{
    struct tcb *tcb = NULL;
    int pos = rte_hash_lookup_data(conn_table, key, (void **)&tcb);
    if (pos < 0)
        return;

    rte_hash_del_key(conn_table, key);
    if (tcb != NULL)
        rte_mempool_put(tcb_pool, tcb);
}
