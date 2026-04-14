#include <stdio.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_random.h>
#include <rte_ethdev.h>
#include "l2.h"
#include "tcp.h"
#include "connection.h"
#include "http.h"
#include "gw_config.h"
#include "gw_pit.h"
#include "ccn_builder.h"

/*
 * ハーフオープンコネクション一時テーブル
 *
 * インカミング接続の SYN 受信時に conn_table へは追加せず、
 * ここに一時保存する。3-way ハンドシェイク完了 (ACK 受信) 時に
 * conn_table へ移行して TCP_ESTABLISHED にセットする。
 */
#define PENDING_MAX 64

struct pending_entry {
    int                   in_use;
    struct conn_key       key;
    uint32_t              iss;      /* GW が SYN-ACK で送った ISS */
    uint32_t              rcv_nxt;  /* ホストの ISN + 1 */
    struct rte_ether_addr peer_mac;
};

static struct pending_entry pending_table[PENDING_MAX];

static struct pending_entry *
pending_lookup(const struct conn_key *key)
{
    for (int i = 0; i < PENDING_MAX; i++) {
        if (pending_table[i].in_use &&
            memcmp(&pending_table[i].key, key, sizeof(*key)) == 0)
            return &pending_table[i];
    }
    return NULL;
}

static struct pending_entry *
pending_alloc(const struct conn_key *key)
{
    /* 再送SYN: 既存エントリを再利用 */
    struct pending_entry *e = pending_lookup(key);
    if (e != NULL)
        return e;

    for (int i = 0; i < PENDING_MAX; i++) {
        if (!pending_table[i].in_use) {
            pending_table[i].in_use = 1;
            pending_table[i].key    = *key;
            return &pending_table[i];
        }
    }
    return NULL;
}

static void
pending_delete(const struct conn_key *key)
{
    for (int i = 0; i < PENDING_MAX; i++) {
        if (pending_table[i].in_use &&
            memcmp(&pending_table[i].key, key, sizeof(*key)) == 0) {
            pending_table[i].in_use = 0;
            return;
        }
    }
}

int
process_tcp(struct rte_mbuf *m, struct rte_tcp_hdr *tcp,
            const struct conn_key *key)
{
    uint16_t src_port  = rte_be_to_cpu_16(tcp->src_port);
    uint16_t dst_port  = rte_be_to_cpu_16(tcp->dst_port);
    uint32_t sent_seq  = rte_be_to_cpu_32(tcp->sent_seq);
    uint32_t recv_ack  = rte_be_to_cpu_32(tcp->recv_ack);
    uint8_t  data_off  = (tcp->data_off >> 4) * 4; /* ヘッダ長(bytes) */
    uint8_t  tcp_flags = tcp->tcp_flags;

    printf("    TCP src_port=%u dst_port=%u seq=%u ack=%u hdr_len=%u"
           " flags=%s%s%s%s%s%s\n",
           src_port, dst_port, sent_seq, recv_ack, data_off,
           (tcp_flags & RTE_TCP_SYN_FLAG) ? "SYN " : "",
           (tcp_flags & RTE_TCP_ACK_FLAG) ? "ACK " : "",
           (tcp_flags & RTE_TCP_FIN_FLAG) ? "FIN " : "",
           (tcp_flags & RTE_TCP_RST_FLAG) ? "RST " : "",
           (tcp_flags & RTE_TCP_PSH_FLAG) ? "PSH " : "",
           (tcp_flags & RTE_TCP_URG_FLAG) ? "URG " : "");

    int is_syn = (tcp_flags & RTE_TCP_SYN_FLAG) != 0;
    int is_ack = (tcp_flags & RTE_TCP_ACK_FLAG) != 0;
    int is_fin = (tcp_flags & RTE_TCP_FIN_FLAG) != 0;
    int is_rst = (tcp_flags & RTE_TCP_RST_FLAG) != 0;

    struct tcb *tcb = conn_lookup(key);

    if (is_rst) {
        /* RST: コネクション強制終了 */
        if (tcb != NULL) {
            printf("    TCP: RST received, deleting connection\n");
            conn_delete(key);
        }
        return 0;
    }

    if (is_syn && !is_ack) {
        /*
         * SYNのみ: インカミング接続の確立要求 (3-wayハンドシェイク 第1段)
         * conn_table にはまだ追加せず pending_table に一時保存する。
         */

        /* 既存のconn_tableエントリがあれば削除 (RST後の再接続など) */
        if (tcb != NULL)
            conn_delete(key);

        struct pending_entry *pe = pending_alloc(key);
        if (pe == NULL) {
            printf("    TCP: pending table full, dropping SYN\n");
            rte_pktmbuf_free(m);
            return -1;
        }

        pe->rcv_nxt = sent_seq + 1;

        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        rte_ether_addr_copy(&eth->src_addr, &pe->peer_mac);

        /* ISS (Initial Send Sequence) をランダムに生成 */
        uint32_t iss = (uint32_t)rte_rand();
        pe->iss = iss;

        /* SYNパケットをin-placeでSYN-ACKに書き換える */

        /* Ethernetヘッダ: 送信元/宛先MACを入れ替え */
        struct rte_ether_addr tmp_mac;
        rte_ether_addr_copy(&eth->dst_addr, &tmp_mac);
        rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
        rte_ether_addr_copy(&tmp_mac, &eth->src_addr);

        /* IPv4ヘッダ: 送信元/宛先IPを入れ替え、チェックサム再計算 */
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        uint32_t tmp_ip  = ip->src_addr;
        ip->src_addr     = ip->dst_addr;
        ip->dst_addr     = tmp_ip;
        ip->time_to_live = 64;

        /* TCPヘッダ: ポートを入れ替え、SYN+ACK・seq/ackをセット */
        uint16_t tmp_port = tcp->src_port;
        tcp->src_port     = tcp->dst_port;
        tcp->dst_port     = tmp_port;
        tcp->sent_seq     = rte_cpu_to_be_32(iss);
        tcp->recv_ack     = rte_cpu_to_be_32(pe->rcv_nxt);
        tcp->tcp_flags    = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
        tcp->data_off     = ((sizeof(struct rte_tcp_hdr) + 4) / 4) << 4; /* 24バイト (MSS option込み) */
        tcp->rx_win       = rte_cpu_to_be_16(65535);
        tcp->tcp_urp      = 0;
        tcp->cksum        = 0;

        /* TCPオプション: MSS (kind=2, length=4, value=9460) */
        uint8_t *opt = (uint8_t *)(tcp + 1);
        opt[0] = 0x02;
        opt[1] = 0x04;
        opt[2] = (9460 >> 8) & 0xff;
        opt[3] =  9460        & 0xff;

        /* IPv4 total_length を MSS option (4バイト) 分だけ更新してチェックサム再計算 */
        ip->total_length = rte_cpu_to_be_16(
            sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 4);
        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);

        /* TCPチェックサム再計算 */
        m->l2_len  = RTE_ETHER_HDR_LEN;
        m->l3_len  = sizeof(struct rte_ipv4_hdr);
        tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

        /* mbufのpkt_len を MSS option (4バイト) 込みのサイズに設定 */
        m->pkt_len = m->data_len = RTE_ETHER_HDR_LEN +
                                   sizeof(struct rte_ipv4_hdr) +
                                   sizeof(struct rte_tcp_hdr) + 4;

        tx_burst_log(ETH1_PORT_ID, &m, 1);

        printf("    TCP: SYN-ACK sent (iss=%u ack=%u) src_port=%u dst_port=%u\n",
               iss, pe->rcv_nxt, dst_port, src_port);
        return -1;

    } else if (is_syn && is_ack) {
        /* SYN+ACK: コネクション確立応答 (3-wayハンドシェイク 第2段) */
        if (tcb != NULL) {
            tcb->state   = TCP_ESTABLISHED;
            tcb->rcv_nxt = sent_seq + 1;
            tcb->snd_una = recv_ack;

            if (tcb->is_outgoing) {
                /*
                 * アウトゴイング接続 (CCN→IP) の SYN-ACK 受信:
                 * ACK を送信し、続けて HTTP GET を送信する。
                 */
                struct rte_mbuf *ack_m = build_tcp_ack(key, tcb);
                if (ack_m != NULL)
                    tx_burst_log(ETH1_PORT_ID, &ack_m, 1);

                /* CCN名前 → URI変換 */
                char uri[256];
                struct ccn_name tmp_name;
                memset(&tmp_name, 0, sizeof(tmp_name));
                /* wire から直接パスを生成するために ccn_uri_path_from_name_wire を使う */
                /* ccn_name 構造体は持っていないが name_wire から名前文字列を構築する */
                /* パスを name_wire_len の bytes から直接抽出 */
                build_uri_from_name_wire(tcb->ccn_name_wire,
                                         tcb->ccn_name_wire_len,
                                         uri, sizeof(uri));

                struct rte_mbuf *get_m = build_http_get(key, tcb, uri);
                if (get_m != NULL)
                    tx_burst_log(ETH1_PORT_ID, &get_m, 1);

                printf("    TCP: outgoing SYN-ACK → ACK+HTTP GET sent uri=%s\n", uri);
            } else {
                printf("    TCP: connection established (SYN+ACK) src_port=%u dst_port=%u\n",
                       src_port, dst_port);
            }
        }
        return 0;

    } else if (is_fin) {
        /* FIN: コネクション終了要求 → FIN+ACK を送信して即クローズ */
        if (tcb != NULL) {
            tcb->rcv_nxt = sent_seq + 1;  /* FIN は1シーケンス番号を消費 */

            struct rte_mbuf *fin_ack_m = build_tcp_fin_ack(key, tcb);
            if (fin_ack_m != NULL)
                tx_burst_log(ETH1_PORT_ID, &fin_ack_m, 1);

            conn_delete(key);
            printf("    TCP: FIN received, FIN-ACK sent, connection closed\n");
        }
        return 0;

    } else {
        /* データ転送 or 3-wayハンドシェイク完了ACK */
        if (tcb == NULL) {
            /*
             * conn_table にエントリがない場合、pending_table を確認する。
             * GW の SYN-ACK に対するホストの ACK (第3段) であれば
             * conn_table に登録して TCP_ESTABLISHED へ遷移する。
             */
            struct pending_entry *pe = pending_lookup(key);
            if (pe != NULL && is_ack && recv_ack == pe->iss + 1) {
                tcb = conn_insert(key);
                if (tcb == NULL) {
                    printf("    TCP: failed to allocate TCB on ACK\n");
                    return 0;
                }
                tcb->state       = TCP_ESTABLISHED;
                tcb->rcv_nxt     = pe->rcv_nxt;
                tcb->snd_nxt     = pe->iss + 1;
                tcb->snd_una     = pe->iss + 1;
                tcb->rcv_wnd     = rte_be_to_cpu_16(tcp->rx_win);
                tcb->is_outgoing = 0;
                rte_ether_addr_copy(&pe->peer_mac, &tcb->peer_mac);
                pending_delete(key);
                printf("    TCP: ESTABLISHED (3-way complete) src_port=%u dst_port=%u\n",
                       src_port, dst_port);
            } else {
                printf("    TCP: DROP no established connection src_port=%u dst_port=%u\n",
                       src_port, dst_port);
                return 0;
            }
        }

        if (tcb->state != TCP_ESTABLISHED) {
            printf("    TCP: DROP not ESTABLISHED src_port=%u dst_port=%u\n",
                   src_port, dst_port);
            return 0;
        }

        tcb->snd_una = recv_ack;

        /* TCPペイロード先頭と長さを計算
         *
         * m->pkt_len ではなく IP total_length を基に計算する。
         * Ethernet は最小フレーム 60 バイトを保証するためパディングを付加する
         * ことがあり、m->pkt_len にはそのパディングが含まれる。
         * IP total_length はパディングを含まない実際の長さを示すため、
         * これを使って正確なペイロード長を求める。
         */
        const struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(
            m, const struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);
        uint16_t ip_total_len = rte_be_to_cpu_16(ip_hdr->total_length);
        uint16_t ip_hdr_len   = (uint16_t)((ip_hdr->version_ihl & 0x0f) * 4);
        int32_t  payload_len_i = (int32_t)ip_total_len - ip_hdr_len - data_off;
        uint16_t payload_len   = (payload_len_i > 0) ? (uint16_t)payload_len_i : 0;

        const char *payload = (const char *)tcp + data_off;

        if (payload_len == 0)
            return 0;

        /* rcv_nxt をペイロード分進める */
        tcb->rcv_nxt = sent_seq + payload_len;

        /* データ受信に対する ACK を送信する */
        struct rte_mbuf *ack_m = build_tcp_ack(key, tcb);
        if (ack_m != NULL)
            tx_burst_log(ETH1_PORT_ID, &ack_m, 1);

        /* 宛先ポートによるアプリケーション層分岐 */
        if (dst_port == GW_HTTP_PORT) {
            if (tcb->is_outgoing) {
                /*
                 * アウトゴイング接続 (CCN→IP) の HTTP レスポンス受信:
                 * CCN Content Object を構築して CCN 要求元に送信する。
                 */
                printf("    TCP: HTTP response received (outgoing), building CCN Content Object\n");

                struct rte_mbuf *co_m = build_ccn_content_object(
                    tcb->ccn_name_wire,
                    tcb->ccn_name_wire_len,
                    (const uint8_t *)payload,
                    payload_len,
                    &tcb->ccn_src_mac,
                    tcb->ccn_src_ip,
                    tcb->ccn_src_port);

                if (co_m != NULL)
                    tx_burst_log(ETH2_PORT_ID, &co_m, 1);

                return 0;
            } else {
                /*
                 * インカミング接続 (IP→GW) の HTTP GET 受信:
                 * HTTP リクエストを解析し CCN Interest を生成・送信する。
                 */
                struct http_request req;
                if (parse_http_request(payload, payload_len, &req) == 0) {
                    printf("    TCP: HTTP GET %s → CCN Interest\n", req.uri);

                    /* URI → CCN Name wire encoding */
                    uint8_t name_wire[TCB_CCN_NAME_WIRE_MAX];
                    uint16_t name_wire_len = 0;

                    if (ccn_name_from_uri_path(req.uri, name_wire, &name_wire_len) == 0) {
                        /* CCN Interest を構築して ETH2 (CCN側) へ送信 */
                        struct rte_mbuf *im = build_ccn_interest(name_wire, name_wire_len);
                        if (im != NULL)
                            tx_burst_log(ETH2_PORT_ID, &im, 1);

                        /* gw_pit に登録 (CCN Content Object 到着時に応答先を解決) */
                        gw_pit_insert(name_wire, name_wire_len, key, tcb,
                                      GW_CCN_INTEREST_LIFETIME_MS);
                    } else {
                        printf("    TCP: CCN name encoding failed for uri=%s\n", req.uri);
                    }
                } else {
                    printf("    TCP: HTTP parse failed (incomplete or invalid)\n");
                }
                return 0;
            }
        } else {
            printf("    TCP: data transfer dst_port=%u src_port=%u\n",
                   dst_port, src_port);
            /* 今後: その他のポートの処理を実装 */
        }
        return 1;
    }
}

/*
 * CCN Name TLV wire encoding から URI パスを生成する。
 *
 * ccn_name_from_uri_path の逆変換。
 * name_wire は T_NAME TLV 全体 (T(2)+L(2)+V(segments...))。
 */
void
build_uri_from_name_wire(const uint8_t *name_wire, uint16_t name_wire_len,
                          char *uri_out, size_t uri_max)
{
    if (name_wire_len < 4 || uri_max == 0) {
        uri_out[0] = '\0';
        return;
    }

    /* T_NAME TLV の value 部分へスキップ (先頭4バイトはT_NAME T+L) */
    uint16_t name_value_len = (uint16_t)((name_wire[2] << 8) | name_wire[3]);
    const uint8_t *p   = name_wire + 4;
    const uint8_t *end = p + name_value_len;

    size_t pos = 0;

    while (p < end && p + 4 <= end) {
        /* T_NAMESEGMENT TLV: T(2) + L(2) + V */
        /* uint16_t seg_type = (p[0] << 8) | p[1]; (使用しない) */
        uint16_t seg_len  = (uint16_t)((p[2] << 8) | p[3]);
        const uint8_t *seg_val = p + 4;

        if (p + 4 + seg_len > end)
            break;

        if (pos + 1 + seg_len + 1 > uri_max)
            break;

        uri_out[pos++] = '/';
        memcpy(uri_out + pos, seg_val, seg_len);
        pos += seg_len;

        p += 4 + seg_len;
    }

    if (pos == 0 && uri_max > 0)
        uri_out[pos++] = '/';

    uri_out[pos] = '\0';
}
