#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_random.h>
#include "ccn_builder.h"
#include "ccn.h"
#include "gw_config.h"
#include "connection.h"

/* ================================================================
 * 内部ヘルパー: CCNx TLV 構築
 * ================================================================ */

/*
 * 2バイト Type + 2バイト Length (CCNx固定形式) を buf に書き込む。
 * 書き込んだバイト数 (=4) を返す。
 */
static inline uint16_t
write_tlv_header(uint8_t *buf, uint16_t type, uint16_t length)
{
    buf[0] = (uint8_t)(type >> 8);
    buf[1] = (uint8_t)(type & 0xff);
    buf[2] = (uint8_t)(length >> 8);
    buf[3] = (uint8_t)(length & 0xff);
    return 4;
}

/* ================================================================
 * 名前変換ユーティリティ
 * ================================================================ */

int
ccn_name_from_uri_path(const char *uri,
                        uint8_t *name_wire_out,
                        uint16_t *len_out)
{
    if (uri == NULL || name_wire_out == NULL || len_out == NULL)
        return -1;

    /*
     * 2パス:
     *   Pass 1: 必要バイト数を計算
     *   Pass 2: セグメントを書き込む
     */
    const char *p = uri;

    /* 先頭の '/' をスキップ */
    if (*p == '/')
        p++;

    /* Pass 1: 合計セグメントサイズを計算 */
    uint16_t segments_total = 0;
    const char *seg_start = p;
    while (*p != '\0') {
        if (*p == '/') {
            uint16_t seg_len = (uint16_t)(p - seg_start);
            if (seg_len > 0)
                segments_total += (uint16_t)(4 + seg_len);  /* T_NAMESEGMENT TLV */
            seg_start = p + 1;
        }
        p++;
    }
    /* 最後のセグメント */
    {
        uint16_t seg_len = (uint16_t)(p - seg_start);
        if (seg_len > 0)
            segments_total += (uint16_t)(4 + seg_len);
    }

    /* T_NAME TLV 全体のサイズ: 4 (ヘッダ) + segments_total */
    uint16_t total = (uint16_t)(4 + segments_total);
    if (total > TCB_CCN_NAME_WIRE_MAX)
        return -1;

    /* Pass 2: 書き込み */
    uint8_t *out = name_wire_out;
    out += write_tlv_header(out, CCN_T_NAME, segments_total);

    p = uri;
    if (*p == '/')
        p++;

    seg_start = p;
    while (*p != '\0') {
        if (*p == '/') {
            uint16_t seg_len = (uint16_t)(p - seg_start);
            if (seg_len > 0) {
                out += write_tlv_header(out, CCN_T_NAMESEGMENT, seg_len);
                memcpy(out, seg_start, seg_len);
                out += seg_len;
            }
            seg_start = p + 1;
        }
        p++;
    }
    {
        uint16_t seg_len = (uint16_t)(p - seg_start);
        if (seg_len > 0) {
            out += write_tlv_header(out, CCN_T_NAMESEGMENT, seg_len);
            memcpy(out, seg_start, seg_len);
            out += seg_len;
        }
    }

    *len_out = total;
    return 0;
}

int
ccn_uri_path_from_name(const struct ccn_name *name,
                        char *uri_out, size_t uri_max)
{
    if (name == NULL || uri_out == NULL || uri_max == 0)
        return -1;

    size_t pos = 0;

    if (name->n_segments == 0) {
        if (pos + 2 > uri_max) return -1;
        uri_out[pos++] = '/';
        uri_out[pos]   = '\0';
        return 0;
    }

    for (uint8_t i = 0; i < name->n_segments; i++) {
        const struct ccn_name_segment *s = &name->segments[i];
        /* '/' + segment bytes */
        if (pos + 1 + s->length + 1 > uri_max) return -1;
        uri_out[pos++] = '/';
        memcpy(uri_out + pos, s->value, s->length);
        pos += s->length;
    }
    uri_out[pos] = '\0';
    return 0;
}

/* ================================================================
 * 共通: Ether/IP/UDP ヘッダ構築
 * ================================================================ */

/*
 * mbuf に Ethernet + IPv4 + UDP ヘッダを書き込む。
 * udp_payload_len: UDPペイロード (UDPヘッダ以降) のバイト数
 *
 * 返り値: UDPペイロード先頭ポインタ
 */
static uint8_t *
build_eth_ip_udp(struct rte_mbuf *m,
                 const struct rte_ether_addr *src_mac,
                 const struct rte_ether_addr *dst_mac,
                 uint32_t src_ip_be,
                 uint32_t dst_ip_be,
                 uint16_t src_port_hbo,
                 uint16_t dst_port_hbo,
                 uint16_t udp_payload_len)
{
    uint16_t udp_total   = (uint16_t)(sizeof(struct rte_udp_hdr) + udp_payload_len);
    uint16_t ip_total    = (uint16_t)(sizeof(struct rte_ipv4_hdr) + udp_total);
    uint16_t pkt_total   = (uint16_t)(RTE_ETHER_HDR_LEN + ip_total);

    m->pkt_len = m->data_len = pkt_total;
    m->l2_len  = RTE_ETHER_HDR_LEN;
    m->l3_len  = sizeof(struct rte_ipv4_hdr);

    /* Ethernet */
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_ether_addr_copy(src_mac, &eth->src_addr);
    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IPv4 */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl     = 0x45;  /* version=4, IHL=5 (20 bytes) */
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(ip_total);
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = GW_DEFAULT_TTL;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = src_ip_be;
    ip->dst_addr        = dst_ip_be;
    ip->hdr_checksum    = 0;
    ip->hdr_checksum    = rte_ipv4_cksum(ip);

    /* UDP */
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    udp->src_port  = rte_cpu_to_be_16(src_port_hbo);
    udp->dst_port  = rte_cpu_to_be_16(dst_port_hbo);
    udp->dgram_len = rte_cpu_to_be_16(udp_total);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return (uint8_t *)(udp + 1);
}

/*
 * mbuf に Ethernet + IPv4 + TCP ヘッダを書き込む（データなし版）。
 * tcp_flags: RTE_TCP_SYN_FLAG など
 * tcp_payload_len: TCPペイロードのバイト数
 *
 * 返り値: TCPペイロード先頭ポインタ
 */
static uint8_t *
build_eth_ip_tcp(struct rte_mbuf *m,
                 const struct rte_ether_addr *src_mac,
                 const struct rte_ether_addr *dst_mac,
                 uint32_t src_ip_be,
                 uint32_t dst_ip_be,
                 uint16_t src_port_nbo,
                 uint16_t dst_port_nbo,
                 uint32_t seq_hbo,
                 uint32_t ack_hbo,
                 uint8_t  tcp_flags,
                 uint16_t tcp_payload_len)
{
    uint16_t tcp_hdr_len = sizeof(struct rte_tcp_hdr);
    uint16_t ip_total    = (uint16_t)(sizeof(struct rte_ipv4_hdr) +
                                       tcp_hdr_len + tcp_payload_len);
    uint16_t pkt_total   = (uint16_t)(RTE_ETHER_HDR_LEN + ip_total);

    m->pkt_len = m->data_len = pkt_total;
    m->l2_len  = RTE_ETHER_HDR_LEN;
    m->l3_len  = sizeof(struct rte_ipv4_hdr);

    /* Ethernet */
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_ether_addr_copy(src_mac, &eth->src_addr);
    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IPv4 */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(ip_total);
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = GW_DEFAULT_TTL;
    ip->next_proto_id   = IPPROTO_TCP;
    ip->src_addr        = src_ip_be;
    ip->dst_addr        = dst_ip_be;
    ip->hdr_checksum    = 0;
    ip->hdr_checksum    = rte_ipv4_cksum(ip);

    /* TCP */
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port  = src_port_nbo;
    tcp->dst_port  = dst_port_nbo;
    tcp->sent_seq  = rte_cpu_to_be_32(seq_hbo);
    tcp->recv_ack  = rte_cpu_to_be_32(ack_hbo);
    tcp->data_off  = (uint8_t)((tcp_hdr_len / 4) << 4);
    tcp->tcp_flags = tcp_flags;
    tcp->rx_win    = rte_cpu_to_be_16(65535);
    tcp->tcp_urp   = 0;
    tcp->cksum     = 0;
    tcp->cksum     = rte_ipv4_udptcp_cksum(ip, tcp);

    return (uint8_t *)(tcp + 1);
}

/* ================================================================
 * CCN パケット構築
 * ================================================================ */

struct rte_mbuf *
build_ccn_interest(const uint8_t *name_wire, uint16_t name_wire_len)
{
    /*
     * CCNx Interest パケットレイアウト (全て連続):
     *   ccn_fixed_hdr (8B)
     *   T_INTEREST TLV header (4B)
     *   name_wire (name_wire_len B)
     */
    uint16_t msg_value_len = name_wire_len;   /* Message本体 = Name TLVのみ */
    uint16_t ccn_total     = (uint16_t)(CCN_FIXED_HEADER_LEN + 4 + msg_value_len);
    uint16_t udp_payload   = ccn_total;

    uint16_t pkt_total = (uint16_t)(RTE_ETHER_HDR_LEN +
                                     sizeof(struct rte_ipv4_hdr) +
                                     sizeof(struct rte_udp_hdr) +
                                     udp_payload);

    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    if (rte_pktmbuf_tailroom(m) < pkt_total) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    static const struct rte_ether_addr ccn_host_mac = GW_CCN_HOST_MAC_INIT;
    uint8_t *ccn_start = build_eth_ip_udp(
        m,
        &gw_eth2_mac,
        &ccn_host_mac,
        rte_cpu_to_be_32(GW_ETH2_IP_BE),
        rte_cpu_to_be_32(GW_CCN_HOST_IP_BE),
        GW_CCN_UDP_SRC_PORT,
        CCN_UDP_PORT,
        udp_payload);

    /* CCN 固定ヘッダ */
    struct ccn_fixed_hdr *fh = (struct ccn_fixed_hdr *)ccn_start;
    fh->version   = CCN_VERSION;
    fh->pkt_type  = CCN_PT_INTEREST;
    {
        uint16_t pl = rte_cpu_to_be_16(ccn_total);
        memcpy(&fh->pkt_len, &pl, 2);
    }
    fh->hop_limit = GW_CCN_HOP_LIMIT;
    fh->reserved1 = 0;
    fh->reserved2 = 0;
    fh->hdr_len   = CCN_FIXED_HEADER_LEN;

    /* T_INTEREST TLV */
    uint8_t *p = ccn_start + CCN_FIXED_HEADER_LEN;
    p += write_tlv_header(p, CCN_T_INTEREST, msg_value_len);

    /* Name TLV (name_wire はすでに T_NAME TLV 全体) */
    memcpy(p, name_wire, name_wire_len);

    return m;
}

struct rte_mbuf *
build_ccn_content_object(const uint8_t *name_wire, uint16_t name_wire_len,
                          const uint8_t *payload, uint32_t payload_len,
                          const struct rte_ether_addr *dst_mac,
                          uint32_t dst_ip_be,
                          uint16_t dst_port_be)
{
    /*
     * CCNx Content Object レイアウト:
     *   ccn_fixed_hdr (8B)
     *   T_CONTENT_OBJECT TLV header (4B)
     *   name_wire (name_wire_len B)
     *   T_PAYLOAD TLV header (4B)
     *   payload (payload_len B)
     */
    if (payload_len > 65000)  /* UDP/CCNサイズ上限チェック */
        return NULL;

    uint16_t msg_value_len = (uint16_t)(name_wire_len + 4 + payload_len);
    uint16_t ccn_total     = (uint16_t)(CCN_FIXED_HEADER_LEN + 4 + msg_value_len);

    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    uint16_t pkt_total = (uint16_t)(RTE_ETHER_HDR_LEN +
                                     sizeof(struct rte_ipv4_hdr) +
                                     sizeof(struct rte_udp_hdr) +
                                     ccn_total);
    if (rte_pktmbuf_tailroom(m) < pkt_total) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    uint8_t *ccn_start = build_eth_ip_udp(
        m,
        &gw_eth2_mac,
        dst_mac,
        rte_cpu_to_be_32(GW_ETH2_IP_BE),
        dst_ip_be,
        CCN_UDP_PORT,
        rte_be_to_cpu_16(dst_port_be),
        (uint16_t)ccn_total);

    /* CCN 固定ヘッダ */
    struct ccn_fixed_hdr *fh = (struct ccn_fixed_hdr *)ccn_start;
    fh->version   = CCN_VERSION;
    fh->pkt_type  = CCN_PT_CONTENT;
    {
        uint16_t pl = rte_cpu_to_be_16(ccn_total);
        memcpy(&fh->pkt_len, &pl, 2);
    }
    fh->hop_limit = 0;
    fh->reserved1 = 0;
    fh->reserved2 = 0;
    fh->hdr_len   = CCN_FIXED_HEADER_LEN;

    /* T_CONTENT_OBJECT TLV */
    uint8_t *p = ccn_start + CCN_FIXED_HEADER_LEN;
    p += write_tlv_header(p, CCN_T_CONTENT_OBJECT, msg_value_len);

    /* Name TLV */
    memcpy(p, name_wire, name_wire_len);
    p += name_wire_len;

    /* T_PAYLOAD TLV */
    p += write_tlv_header(p, CCN_T_PAYLOAD, (uint16_t)payload_len);
    memcpy(p, payload, payload_len);

    return m;
}

/* ================================================================
 * HTTP パケット構築
 * ================================================================ */

struct rte_mbuf *
build_http_get(const struct conn_key *key, struct tcb *tcb, const char *uri)
{
    /* HTTP GET リクエスト文字列を生成 */
    char req_buf[1024];
    int req_len = snprintf(req_buf, sizeof(req_buf),
        "GET %s HTTP/1.1\r\n"
        "Host: %u.%u.%u.%u\r\n"
        "Connection: close\r\n"
        "\r\n",
        uri,
        (rte_be_to_cpu_32(key->dst_addr) >> 24) & 0xff,
        (rte_be_to_cpu_32(key->dst_addr) >> 16) & 0xff,
        (rte_be_to_cpu_32(key->dst_addr) >>  8) & 0xff,
         rte_be_to_cpu_32(key->dst_addr)        & 0xff);

    if (req_len <= 0 || (size_t)req_len >= sizeof(req_buf))
        return NULL;

    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    uint16_t pkt_total = (uint16_t)(RTE_ETHER_HDR_LEN +
                                     sizeof(struct rte_ipv4_hdr) +
                                     sizeof(struct rte_tcp_hdr) +
                                     req_len);
    if (rte_pktmbuf_tailroom(m) < pkt_total) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    static const struct rte_ether_addr ip_host_mac = GW_IP_HOST_MAC_INIT;
    uint8_t *payload = build_eth_ip_tcp(
        m,
        &gw_eth1_mac,
        &ip_host_mac,
        key->src_addr,  /* src = GW eth1 IP (= outgoing接続のsrc) */
        key->dst_addr,  /* dst = IPホストIP */
        key->src_port,  /* src port (NBO) */
        key->dst_port,  /* dst port (NBO) = 80 */
        tcb->snd_nxt,
        tcb->rcv_nxt,
        RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
        (uint16_t)req_len);

    memcpy(payload, req_buf, req_len);
    tcb->snd_nxt += req_len;

    return m;
}

struct rte_mbuf *
build_http_response(const struct conn_key *key, struct tcb *tcb,
                    const uint8_t *payload, uint32_t payload_len)
{
    /*
     * HTTP/1.1 200 OK レスポンスヘッダを生成する。
     * ヘッダとボディを連続したバッファに書き込む。
     */
    char hdr_buf[256];
    int hdr_len = snprintf(hdr_buf, sizeof(hdr_buf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %u\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: close\r\n"
        "\r\n",
        payload_len);

    if (hdr_len <= 0 || (size_t)hdr_len >= sizeof(hdr_buf))
        return NULL;

    uint32_t total_payload = (uint32_t)hdr_len + payload_len;
    if (total_payload > 65000)
        return NULL;

    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    uint16_t pkt_total = (uint16_t)(RTE_ETHER_HDR_LEN +
                                     sizeof(struct rte_ipv4_hdr) +
                                     sizeof(struct rte_tcp_hdr) +
                                     total_payload);
    if (rte_pktmbuf_tailroom(m) < pkt_total) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    /*
     * incoming接続 (IP→GW) では:
     *   conn_key.src = IPホスト (クライアント)
     *   conn_key.dst = ゲートウェイ (サーバ)
     * 応答時は src/dst を入れ替えて送信する。
     */
    uint8_t *data = build_eth_ip_tcp(
        m,
        &gw_eth1_mac,
        &tcb->peer_mac,    /* IPホストのMAC */
        key->dst_addr,     /* src IP = GW (= 元の dst) */
        key->src_addr,     /* dst IP = IPホスト (= 元の src) */
        key->dst_port,     /* src port = 80 (NBO, = 元の dst_port) */
        key->src_port,     /* dst port = IPホストのエフェメラルポート (NBO) */
        tcb->snd_nxt,
        tcb->rcv_nxt,
        RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG,
        (uint16_t)total_payload);

    memcpy(data, hdr_buf, hdr_len);
    memcpy(data + hdr_len, payload, payload_len);
    tcb->snd_nxt += total_payload;

    return m;
}

/* ================================================================
 * TCP 制御パケット構築
 * ================================================================ */

struct rte_mbuf *
build_tcp_syn(const struct conn_key *key, struct tcb *tcb)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    static const struct rte_ether_addr ip_host_mac = GW_IP_HOST_MAC_INIT;
    build_eth_ip_tcp(
        m,
        &gw_eth1_mac,
        &ip_host_mac,
        key->src_addr,   /* src = GW eth1 IP */
        key->dst_addr,   /* dst = IPホストIP */
        key->src_port,   /* src port (NBO) */
        key->dst_port,   /* dst port = 80 (NBO) */
        tcb->snd_nxt,    /* seq = ISS */
        0,               /* ack = 0 (SYN には ACK なし) */
        RTE_TCP_SYN_FLAG,
        0);              /* SYN ペイロードなし */

    /* SYN を送信したので snd_nxt を 1 進める */
    tcb->snd_nxt++;
    tcb->state = TCP_SYN_RCVD;  /* SYN_SENT に相当 (既存enumを流用) */

    return m;
}

struct rte_mbuf *
build_tcp_ack(const struct conn_key *key, struct tcb *tcb)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    static const struct rte_ether_addr ip_host_mac = GW_IP_HOST_MAC_INIT;

    if (tcb->is_outgoing) {
        /* アウトゴイング接続: key.src=GW, key.dst=IPホスト */
        build_eth_ip_tcp(
            m,
            &gw_eth1_mac,
            &ip_host_mac,
            key->src_addr,
            key->dst_addr,
            key->src_port,
            key->dst_port,
            tcb->snd_nxt,
            tcb->rcv_nxt,
            RTE_TCP_ACK_FLAG,
            0);
    } else {
        /* インカミング接続: key.src=IPホスト, key.dst=GW → 反転して送信 */
        build_eth_ip_tcp(
            m,
            &gw_eth1_mac,
            &tcb->peer_mac,
            key->dst_addr,   /* src IP = GW */
            key->src_addr,   /* dst IP = IPホスト */
            key->dst_port,   /* src port = GW側ポート */
            key->src_port,   /* dst port = IPホストのポート */
            tcb->snd_nxt,
            tcb->rcv_nxt,
            RTE_TCP_ACK_FLAG,
            0);
    }

    return m;
}

struct rte_mbuf *
build_tcp_fin_ack(const struct conn_key *key, struct tcb *tcb)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL)
        return NULL;

    static const struct rte_ether_addr ip_host_mac = GW_IP_HOST_MAC_INIT;

    if (tcb->is_outgoing) {
        /*
         * アウトゴイング接続: key.src=GW, key.dst=IPホスト
         * GW → IPホスト方向でそのまま送信
         */
        build_eth_ip_tcp(
            m,
            &gw_eth1_mac,
            &ip_host_mac,
            key->src_addr,
            key->dst_addr,
            key->src_port,
            key->dst_port,
            tcb->snd_nxt,
            tcb->rcv_nxt,
            RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG,
            0);
    } else {
        /*
         * インカミング接続: key.src=IPホスト, key.dst=GW
         * 応答時は src/dst を反転して IPホストへ送信
         */
        build_eth_ip_tcp(
            m,
            &gw_eth1_mac,
            &tcb->peer_mac,
            key->dst_addr,   /* src IP = GW (= 元の dst) */
            key->src_addr,   /* dst IP = IPホスト (= 元の src) */
            key->dst_port,   /* src port = GW側ポート (= 元の dst_port) */
            key->src_port,   /* dst port = IPホストのポート (= 元の src_port) */
            tcb->snd_nxt,
            tcb->rcv_nxt,
            RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG,
            0);
    }

    tcb->snd_nxt++;  /* FIN は1シーケンス番号を消費する */

    return m;
}

/* ================================================================
 * エフェメラルポート管理
 * ================================================================ */

uint16_t
ephemeral_port_alloc(void)
{
    /*
     * 49152〜65534 の範囲でラウンドロビン割り当て。
     * シングルスレッド動作を前提とした単純なカウンタ。
     */
    static uint16_t next_port = 49152;
    uint16_t port = next_port;
    next_port = (next_port >= 65534) ? 49152 : (uint16_t)(next_port + 1);
    return port;
}
