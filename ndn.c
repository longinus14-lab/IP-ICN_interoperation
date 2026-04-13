#include <stdio.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "ndn.h"

/* 内部用TLV要素 (ndn.hのndn_tlv型とは別に定義) */
struct ndn_tlv_raw {
    uint64_t        type;
    uint64_t        length;
    const uint8_t  *value;
};

/* ---- Variable-length number decoding ----
 * NDN TLV仕様のVAR-NUMBER形式:
 *   0x00-0xFC : 1バイト (値そのまま)
 *   0xFD      : 続く2バイトがビッグエンディアンで値
 *   0xFE      : 続く4バイトがビッグエンディアンで値
 *   0xFF      : 続く8バイトがビッグエンディアンで値
 */
static inline int
decode_var_number(const uint8_t *p, const uint8_t *end,
                  uint64_t *out, uint32_t *consumed)
{
    if (p >= end)
        return -1;

    uint8_t first = *p;
    if (first < 0xFD) {
        *out      = first;
        *consumed = 1;
    } else if (first == 0xFD) {
        if (p + 3 > end)
            return -1;
        *out      = ((uint64_t)p[1] << 8) | p[2];
        *consumed = 3;
    } else if (first == 0xFE) {
        if (p + 5 > end)
            return -1;
        *out      = ((uint64_t)p[1] << 24) | ((uint64_t)p[2] << 16) |
                    ((uint64_t)p[3] <<  8) |  (uint64_t)p[4];
        *consumed = 5;
    } else { /* 0xFF */
        if (p + 9 > end)
            return -1;
        *out      = ((uint64_t)p[1] << 56) | ((uint64_t)p[2] << 48) |
                    ((uint64_t)p[3] << 40) | ((uint64_t)p[4] << 32) |
                    ((uint64_t)p[5] << 24) | ((uint64_t)p[6] << 16) |
                    ((uint64_t)p[7] <<  8) |  (uint64_t)p[8];
        *consumed = 9;
    }
    return 0;
}

/* ---- 単一TLV要素の解析 ----
 * type, length, value(元バッファへのポインタ)を取得する。
 * *consumed にはT+L+Vのバイト数が格納される。
 */
static inline int
parse_tlv(const uint8_t *buf, const uint8_t *end,
          struct ndn_tlv_raw *tlv, uint32_t *consumed)
{
    const uint8_t *p = buf;
    uint32_t n;

    if (decode_var_number(p, end, &tlv->type, &n) < 0)
        return -1;
    p += n;

    if (decode_var_number(p, end, &tlv->length, &n) < 0)
        return -1;
    p += n;

    if (p + tlv->length > end)
        return -1;

    tlv->value = p;
    *consumed  = (uint32_t)(p + tlv->length - buf);
    return 0;
}

/* ---- 非負整数値のデコード (1/2/4/8バイト固定長ビッグエンディアン) ---- */
static inline uint64_t
decode_nonneg_int(const uint8_t *v, uint64_t len)
{
    switch (len) {
    case 1: return v[0];
    case 2: return ((uint64_t)v[0] <<  8) |  (uint64_t)v[1];
    case 4: return ((uint64_t)v[0] << 24) | ((uint64_t)v[1] << 16) |
                   ((uint64_t)v[2] <<  8) |  (uint64_t)v[3];
    case 8: return ((uint64_t)v[0] << 56) | ((uint64_t)v[1] << 48) |
                   ((uint64_t)v[2] << 40) | ((uint64_t)v[3] << 32) |
                   ((uint64_t)v[4] << 24) | ((uint64_t)v[5] << 16) |
                   ((uint64_t)v[6] <<  8) |  (uint64_t)v[7];
    default: return 0;
    }
}

/* ---- NameTLVの解析 ---- */
static int
parse_name(const uint8_t *value, uint64_t length, struct ndn_name *name)
{
    const uint8_t *p   = value;
    const uint8_t *end = value + length;

    name->n_components = 0;

    while (p < end) {
        struct ndn_tlv_raw comp;
        uint32_t consumed;

        if (parse_tlv(p, end, &comp, &consumed) < 0)
            return -1;

        /* Nameコンポーネントのtypeは[1, 65535]の範囲でなければならない */
        if (comp.type == 0 || comp.type > 0xFFFF)
            return -1;

        if (name->n_components < NDN_NAME_MAX_COMPONENTS) {
            struct ndn_name_component *c =
                &name->components[name->n_components];
            c->type   = comp.type;
            c->length = (uint32_t)comp.length;
            c->value  = comp.value;
            name->n_components++;
        }
        /* NDN_NAME_MAX_COMPONENTSを超えた場合はスキップ */

        p += consumed;
    }
    return 0;
}

/* ---- InterestパケットのTLVフィールド解析 ---- */
static int
parse_interest_fields(const uint8_t *value, uint64_t length,
                      struct ndn_interest *interest)
{
    const uint8_t *p   = value;
    const uint8_t *end = value + length;

    memset(interest, 0, sizeof(*interest));
    interest->interest_lifetime_ms = NDN_DEFAULT_INTEREST_LIFETIME_MS;

    while (p < end) {
        struct ndn_tlv_raw tlv;
        uint32_t consumed;

        if (parse_tlv(p, end, &tlv, &consumed) < 0)
            return -1;

        switch (tlv.type) {
        case NDN_TLV_NAME:
            if (parse_name(tlv.value, tlv.length, &interest->name) < 0)
                return -1;
            break;
        case NDN_TLV_CAN_BE_PREFIX:
            interest->can_be_prefix = 1;
            break;
        case NDN_TLV_MUST_BE_FRESH:
            interest->must_be_fresh = 1;
            break;
        case NDN_TLV_NONCE:
            if (tlv.length == 4)
                interest->nonce = ((uint32_t)tlv.value[0] << 24) |
                                  ((uint32_t)tlv.value[1] << 16) |
                                  ((uint32_t)tlv.value[2] <<  8) |
                                   (uint32_t)tlv.value[3];
            break;
        case NDN_TLV_INTEREST_LIFETIME:
            interest->interest_lifetime_ms =
                (uint32_t)decode_nonneg_int(tlv.value, tlv.length);
            break;
        case NDN_TLV_HOP_LIMIT:
            if (tlv.length == 1) {
                interest->has_hop_limit = 1;
                interest->hop_limit     = tlv.value[0];
            }
            break;
        case NDN_TLV_APPLICATION_PARAMETERS:
            interest->app_params     = tlv.value;
            interest->app_params_len = (uint32_t)tlv.length;
            break;
        case NDN_TLV_FORWARDING_HINT:
            /* 今後: ForwardingHint処理を実装 */
            break;
        default:
            /* Critical type (type<=31 または LSB=1) は解析失敗 */
            if (tlv.type <= 31 || (tlv.type & 1))
                return -1;
            /* Non-critical typeは無視して続行 */
            break;
        }

        p += consumed;
    }
    return 0;
}

/* ---- DataパケットのTLVフィールド解析 ---- */
static int
parse_data_fields(const uint8_t *value, uint64_t length,
                  struct ndn_data *data)
{
    const uint8_t *p   = value;
    const uint8_t *end = value + length;

    memset(data, 0, sizeof(*data));

    while (p < end) {
        struct ndn_tlv_raw tlv;
        uint32_t consumed;

        if (parse_tlv(p, end, &tlv, &consumed) < 0)
            return -1;

        switch (tlv.type) {
        case NDN_TLV_NAME:
            if (parse_name(tlv.value, tlv.length, &data->name) < 0)
                return -1;
            break;
        case NDN_TLV_META_INFO: {
            /* MetaInfoのサブTLVを解析 */
            const uint8_t *mp   = tlv.value;
            const uint8_t *mend = tlv.value + tlv.length;
            while (mp < mend) {
                struct ndn_tlv_raw mt;
                uint32_t mc;
                if (parse_tlv(mp, mend, &mt, &mc) < 0)
                    break;
                if (mt.type == NDN_TLV_CONTENT_TYPE)
                    data->content_type =
                        (uint8_t)decode_nonneg_int(mt.value, mt.length);
                else if (mt.type == NDN_TLV_FRESHNESS_PERIOD)
                    data->freshness_period_ms =
                        (uint32_t)decode_nonneg_int(mt.value, mt.length);
                mp += mc;
            }
            break;
        }
        case NDN_TLV_CONTENT:
            data->content     = tlv.value;
            data->content_len = (uint32_t)tlv.length;
            break;
        case NDN_TLV_SIGNATURE_INFO:
        case NDN_TLV_SIGNATURE_VALUE:
            /* 署名フィールドは現時点ではスキップ */
            break;
        default:
            if (tlv.type <= 31 || (tlv.type & 1))
                return -1;
            break;
        }

        p += consumed;
    }
    return 0;
}

/* ---- NDN Nameをデバッグ用にURIとして表示 ---- */
static void
print_name(const struct ndn_name *name)
{
    if (name->n_components == 0) {
        printf("/");
        return;
    }

    for (uint8_t i = 0; i < name->n_components; i++) {
        const struct ndn_name_component *c = &name->components[i];
        printf("/");

        if (c->type == NDN_TLV_GENERIC_NAME_COMPONENT) {
            /* 印字可能なASCIIはそのまま、それ以外はパーセントエンコード */
            for (uint32_t j = 0; j < c->length; j++) {
                uint8_t ch = c->value[j];
                if (ch >= 0x21 && ch <= 0x7E && ch != '%')
                    printf("%c", ch);
                else
                    printf("%%%02X", ch);
            }
        } else if (c->type == NDN_TLV_IMPLICIT_SHA256_DIGEST) {
            printf("sha256digest=");
            for (uint32_t j = 0; j < c->length; j++)
                printf("%02x", c->value[j]);
        } else if (c->type == NDN_TLV_PARAMETERS_SHA256_DIGEST) {
            printf("params-sha256=");
            for (uint32_t j = 0; j < c->length; j++)
                printf("%02x", c->value[j]);
        } else {
            printf("%lu=", c->type);
            for (uint32_t j = 0; j < c->length; j++)
                printf("%02x", c->value[j]);
        }
    }
}

/* ---- トップレベルNDNパケット解析 ---- */
int
ndn_parse_packet(const uint8_t *buf, uint32_t len, struct ndn_packet *pkt)
{
    struct ndn_tlv_raw outer;
    uint32_t consumed;

    if (parse_tlv(buf, buf + len, &outer, &consumed) < 0) {
        printf("  NDN: TLV parse error\n");
        return -1;
    }

    switch (outer.type) {
    case NDN_TLV_INTEREST:
        pkt->type = NDN_PKT_INTEREST;
        return parse_interest_fields(outer.value, outer.length,
                                     &pkt->interest);
    case NDN_TLV_DATA:
        pkt->type = NDN_PKT_DATA;
        return parse_data_fields(outer.value, outer.length,
                                 &pkt->data);
    default:
        printf("  NDN: unknown packet type %lu\n", outer.type);
        return -1;
    }
}

/* ---- mbufエントリポイント ---- */
int
process_ndn(struct rte_mbuf *m)
{
    /* NDNペイロードはEthernetヘッダの直後 */
    const uint8_t *payload = rte_pktmbuf_mtod_offset(
        m, const uint8_t *, RTE_ETHER_HDR_LEN);
    uint32_t len = m->pkt_len - RTE_ETHER_HDR_LEN;

    struct ndn_packet pkt;
    if (ndn_parse_packet(payload, len, &pkt) < 0)
        return -1;

    if (pkt.type == NDN_PKT_INTEREST) {
        struct ndn_interest *i = &pkt.interest;
        printf("  NDN Interest name=");
        print_name(&i->name);
        printf(" nonce=%u lifetime=%ums", i->nonce, i->interest_lifetime_ms);
        if (i->has_hop_limit)
            printf(" hop_limit=%u", i->hop_limit);
        if (i->can_be_prefix)
            printf(" CanBePrefix");
        if (i->must_be_fresh)
            printf(" MustBeFresh");
        printf("\n");
    } else {
        struct ndn_data *d = &pkt.data;
        printf("  NDN Data name=");
        print_name(&d->name);
        printf(" content_type=%u freshness=%ums content_len=%u\n",
               d->content_type, d->freshness_period_ms, d->content_len);
    }

    return 0;
}
