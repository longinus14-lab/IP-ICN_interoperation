#include <stdio.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_random.h>
#include "ccn.h"
#include "gw_pit.h"
#include "cs.h"
#include "gw_config.h"
#include "connection.h"
#include "ccn_builder.h"

/* ------------------------------------------------------------------ */
/* 内部ヘルパー                                                         */
/* ------------------------------------------------------------------ */

/*
 * CCNx固定4バイト TLV (T=2bytes, L=2bytes) をデコードする。
 *
 * バイトシフトで手動読み出しすることで、アライメントに依存しない。
 */
static inline int
parse_tlv_fixed(const uint8_t *p, const uint8_t *end,
                uint16_t *tlv_type, uint16_t *tlv_len,
                const uint8_t **tlv_val, uint32_t *consumed)
{
    if (p + 4 > end)
        return -1;

    *tlv_type = (uint16_t)((p[0] << 8) | p[1]);
    *tlv_len  = (uint16_t)((p[2] << 8) | p[3]);

    if (p + 4 + *tlv_len > end)
        return -1;

    *tlv_val  = p + 4;
    *consumed = 4u + *tlv_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Name パース                                                          */
/* ------------------------------------------------------------------ */

static int
parse_ccn_name(const uint8_t *wire_start, const uint8_t *value,
               uint16_t length, struct ccn_name *name)
{
    /* zero-copy: gw_pit / cs のキーとして T_NAME TLV全体を使う */
    name->wire     = wire_start;
    name->wire_len = (uint16_t)(4 + length);  /* T(2) + L(2) + V(length) */
    name->n_segments = 0;

    const uint8_t *p   = value;
    const uint8_t *end = value + length;

    while (p < end) {
        uint16_t seg_type, seg_len;
        const uint8_t *seg_val;
        uint32_t consumed;

        if (parse_tlv_fixed(p, end, &seg_type, &seg_len, &seg_val, &consumed) < 0)
            return -1;

        if (name->n_segments < CCN_NAME_MAX_SEGMENTS) {
            struct ccn_name_segment *s = &name->segments[name->n_segments];
            s->type   = seg_type;
            s->length = seg_len;
            s->value  = seg_val;
            name->n_segments++;
        }
        p += consumed;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Interest パース                                                      */
/* ------------------------------------------------------------------ */

static int
parse_interest_body(const uint8_t *value, uint16_t length,
                    struct ccn_interest *interest,
                    uint8_t hop_limit, uint16_t lifetime_ms)
{
    memset(interest, 0, sizeof(*interest));
    interest->hop_limit   = hop_limit;
    interest->lifetime_ms = lifetime_ms;

    const uint8_t *p   = value;
    const uint8_t *end = value + length;

    while (p < end) {
        uint16_t t, l;
        const uint8_t *v;
        uint32_t consumed;

        if (parse_tlv_fixed(p, end, &t, &l, &v, &consumed) < 0)
            return -1;

        switch (t) {
        case CCN_T_NAME:
            if (parse_ccn_name(p, v, l, &interest->name) < 0)
                return -1;
            break;
        case CCN_T_KEYIDRESTR:
            interest->keyid_restr     = v;
            interest->keyid_restr_len = l;
            break;
        case CCN_T_OBJHASHRESTR:
            interest->hash_restr      = v;
            interest->hash_restr_len  = l;
            break;
        default:
            /* RFC8609: 不明なTLVは無視する */
            break;
        }
        p += consumed;
    }

    /* T_NAME は Interest に必須 */
    if (interest->name.wire == NULL)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Content Object パース                                                */
/* ------------------------------------------------------------------ */

static int
parse_content_body(const uint8_t *value, uint16_t length,
                   struct ccn_content *content)
{
    memset(content, 0, sizeof(*content));
    content->payload_type = CCN_PAYLDTYPE_DATA;  /* RFC8569デフォルト */

    const uint8_t *p   = value;
    const uint8_t *end = value + length;

    while (p < end) {
        uint16_t t, l;
        const uint8_t *v;
        uint32_t consumed;

        if (parse_tlv_fixed(p, end, &t, &l, &v, &consumed) < 0)
            return -1;

        switch (t) {
        case CCN_T_NAME:
            if (parse_ccn_name(p, v, l, &content->name) < 0)
                return -1;
            break;
        case CCN_T_PAYLDTYPE:
            if (l == 1)
                content->payload_type = v[0];
            break;
        case CCN_T_EXPIRY:
            /* RFC8609: 8バイト unsigned int, epoch ms */
            if (l == 8) {
                content->expiry_time =
                    ((uint64_t)v[0] << 56) | ((uint64_t)v[1] << 48) |
                    ((uint64_t)v[2] << 40) | ((uint64_t)v[3] << 32) |
                    ((uint64_t)v[4] << 24) | ((uint64_t)v[5] << 16) |
                    ((uint64_t)v[6] <<  8) |  (uint64_t)v[7];
            }
            break;
        case CCN_T_PAYLOAD:
            content->payload     = v;
            content->payload_len = l;
            break;
        default:
            break;
        }
        p += consumed;
    }

    /* T_NAME は Content Object に必須 */
    if (content->name.wire == NULL)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* トップレベルパーサ                                                   */
/* ------------------------------------------------------------------ */

int
ccn_parse_packet(const uint8_t *buf, uint32_t len, struct ccn_packet *pkt)
{
    if (len < CCN_FIXED_HEADER_LEN)
        return -1;

    const struct ccn_fixed_hdr *fh = (const struct ccn_fixed_hdr *)buf;

    if (fh->version != CCN_VERSION)
        return -1;

    uint16_t pkt_len;
    {
        const uint8_t *raw = (const uint8_t *)&fh->pkt_len;
        pkt_len = (uint16_t)((raw[0] << 8) | raw[1]);
    }

    if (pkt_len > len || pkt_len < CCN_FIXED_HEADER_LEN)
        return -1;

    uint8_t hdr_len = fh->hdr_len;
    if (hdr_len < CCN_FIXED_HEADER_LEN || hdr_len > pkt_len)
        return -1;

    /* ---- Optional Headers をスキャン ---- */
    uint16_t lifetime_ms = CCN_DEFAULT_INTLIFE_MS;

    const uint8_t *opt_p   = buf + CCN_FIXED_HEADER_LEN;
    const uint8_t *opt_end = buf + hdr_len;

    while (opt_p < opt_end) {
        uint16_t t, l;
        const uint8_t *v;
        uint32_t consumed;

        if (parse_tlv_fixed(opt_p, opt_end, &t, &l, &v, &consumed) < 0)
            break;

        if (t == CCN_T_INTLIFE && l == 2)
            lifetime_ms = (uint16_t)((v[0] << 8) | v[1]);

        opt_p += consumed;
    }

    /* ---- Message TLV をパース ---- */
    const uint8_t *msg_p   = buf + hdr_len;
    const uint8_t *msg_end = buf + pkt_len;

    if (msg_p >= msg_end)
        return -1;

    uint16_t msg_type, msg_len;
    const uint8_t *msg_val;
    uint32_t consumed;

    if (parse_tlv_fixed(msg_p, msg_end, &msg_type, &msg_len, &msg_val, &consumed) < 0)
        return -1;

    /* PacketType と Message TLV タイプの整合性を確認 */
    switch (fh->pkt_type) {
    case CCN_PT_INTEREST:
        if (msg_type != CCN_T_INTEREST)
            return -1;
        pkt->type = CCN_PKT_INTEREST;
        return parse_interest_body(msg_val, msg_len,
                                   &pkt->interest, fh->hop_limit, lifetime_ms);

    case CCN_PT_CONTENT:
        if (msg_type != CCN_T_CONTENT_OBJECT)
            return -1;
        pkt->type = CCN_PKT_CONTENT;
        return parse_content_body(msg_val, msg_len, &pkt->content);

    case CCN_PT_RETURN:
        pkt->type = CCN_PKT_RETURN;
        return 0;

    default:
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* デバッグ用 Name 表示                                                 */
/* ------------------------------------------------------------------ */

static void
print_ccn_name(const struct ccn_name *name)
{
    if (name->n_segments == 0) {
        printf("ccnx:/");
        return;
    }
    printf("ccnx:/");
    for (uint8_t i = 0; i < name->n_segments; i++) {
        const struct ccn_name_segment *s = &name->segments[i];
        for (uint16_t j = 0; j < s->length; j++) {
            uint8_t ch = s->value[j];
            if (ch >= 0x21 && ch <= 0x7e && ch != '%')
                printf("%c", ch);
            else
                printf("%%%02x", ch);
        }
        if (i + 1 < name->n_segments)
            printf("/");
    }
}

/* ------------------------------------------------------------------ */
/* process_ccn: udp.c から呼ばれるエントリポイント                      */
/* ------------------------------------------------------------------ */

int
process_ccn(struct rte_mbuf *m, const uint8_t *buf, uint32_t len,
            uint32_t ip_src_be, uint16_t udp_src_be,
            const struct rte_ether_addr *eth_src)
{
    (void)m;

    struct ccn_packet pkt;
    if (ccn_parse_packet(buf, len, &pkt) < 0) {
        printf("    CCN: parse error\n");
        return -1;
    }

    if (pkt.type == CCN_PKT_INTEREST) {
        struct ccn_interest *i = &pkt.interest;
        printf("    CCN Interest name=");
        print_ccn_name(&i->name);
        printf(" hop_limit=%u lifetime=%ums\n",
               i->hop_limit, i->lifetime_ms);

        /* CS検索: キャッシュヒットなら将来的に直接応答可能 */
        struct cs_entry *cs = cs_lookup(i->name.wire, i->name.wire_len);
        if (cs != NULL) {
            printf("    CCN: CS hit (name_wire_len=%u)\n", i->name.wire_len);
            /* 今後: CS からコンテンツを取得して CCN Content Object を送信 */
        }

        /*
         * CCN→IP 変換:
         * 1. name_wire をコピーしてアウトゴイング TCB に保存
         * 2. IP ホストへ TCP SYN を送信
         */
        if (i->name.wire_len > TCB_CCN_NAME_WIRE_MAX) {
            printf("    CCN: name too long (%u), dropping\n", i->name.wire_len);
            return -1;
        }

        /* アウトゴイング接続の4タプルキーを生成 */
        struct conn_key out_key = {
            .src_addr = rte_cpu_to_be_32(GW_ETH1_IP_BE),
            .dst_addr = rte_cpu_to_be_32(GW_IP_HOST_IP_BE),
            .src_port = rte_cpu_to_be_16(ephemeral_port_alloc()),
            .dst_port = rte_cpu_to_be_16(GW_IP_HOST_PORT),
        };

        struct tcb *tcb = conn_insert(&out_key);
        if (tcb == NULL) {
            printf("    CCN: failed to allocate TCB for outgoing connection\n");
            return -1;
        }

        /* TCB 初期化 */
        uint32_t iss = (uint32_t)rte_rand();
        tcb->state             = TCP_SYN_RCVD;  /* SYN_SENT に相当 */
        tcb->snd_nxt           = iss;
        tcb->snd_una           = iss;
        tcb->rcv_nxt           = 0;
        tcb->is_outgoing       = 1;

        /* CCN 要求元情報を保存 */
        memcpy(tcb->ccn_name_wire, i->name.wire, i->name.wire_len);
        tcb->ccn_name_wire_len = i->name.wire_len;
        tcb->ccn_src_ip        = ip_src_be;
        tcb->ccn_src_port      = udp_src_be;
        rte_ether_addr_copy(eth_src, &tcb->ccn_src_mac);

        /* TCP SYN を IP ホストへ送信 */
        struct rte_mbuf *syn_m = build_tcp_syn(&out_key, tcb);
        if (syn_m != NULL)
            rte_eth_tx_burst(ETH1_PORT_ID, 0, &syn_m, 1);

        printf("    CCN: TCP SYN sent to IP host for uri\n");

    } else if (pkt.type == CCN_PKT_CONTENT) {
        struct ccn_content *c = &pkt.content;
        printf("    CCN Content Object name=");
        print_ccn_name(&c->name);
        printf(" payload_len=%u\n", c->payload_len);

        /*
         * IP→CCN 変換の応答: gw_pit で要求元 IP ホストを特定し HTTP 200 を返す
         */
        struct gw_pit_entry *gw = gw_pit_lookup(c->name.wire, c->name.wire_len);
        if (gw != NULL && gw->n_in > 0) {
            printf("    CCN: gw_pit hit, %u pending IP host(s)\n", gw->n_in);
            for (uint8_t idx = 0; idx < gw->n_in; idx++) {
                struct rte_mbuf *resp_m = build_http_response(
                    &gw->in_records[idx].conn_key,
                     gw->in_records[idx].tcb,
                     c->payload,
                     (uint32_t)c->payload_len);
                if (resp_m != NULL)
                    rte_eth_tx_burst(ETH1_PORT_ID, 0, &resp_m, 1);
            }
        }

        /* CS挿入: Content Object をキャッシュ (現在スタブ) */
        if (c->payload != NULL) {
            cs_insert(c->name.wire, c->name.wire_len,
                      c->payload, c->payload_len,
                      c->payload_type, 0);
        }

    } else {
        /* CCN_PKT_RETURN: Interest Return → ドロップ */
        printf("    CCN: Interest Return received (dropped)\n");
    }

    return 0;
}
