#ifndef NDN_H
#define NDN_H

#include <stdint.h>
#include <rte_mbuf.h>

/* ---- TLV type numbers (NDN packet spec) ---- */
#define NDN_TLV_IMPLICIT_SHA256_DIGEST      1
#define NDN_TLV_PARAMETERS_SHA256_DIGEST    2
#define NDN_TLV_INTEREST                    5
#define NDN_TLV_DATA                        6
#define NDN_TLV_NAME                        7
#define NDN_TLV_GENERIC_NAME_COMPONENT      8
#define NDN_TLV_NONCE                       10
#define NDN_TLV_INTEREST_LIFETIME           12
#define NDN_TLV_MUST_BE_FRESH               18
#define NDN_TLV_META_INFO                   20
#define NDN_TLV_CONTENT                     21
#define NDN_TLV_SIGNATURE_INFO              22
#define NDN_TLV_SIGNATURE_VALUE             23
#define NDN_TLV_CONTENT_TYPE                24
#define NDN_TLV_FRESHNESS_PERIOD            25
#define NDN_TLV_FINAL_BLOCK_ID              26
#define NDN_TLV_FORWARDING_HINT             30
#define NDN_TLV_CAN_BE_PREFIX               33
#define NDN_TLV_HOP_LIMIT                   34
#define NDN_TLV_APPLICATION_PARAMETERS      36

/* Content types */
#define NDN_CONTENT_TYPE_BLOB   0
#define NDN_CONTENT_TYPE_LINK   1
#define NDN_CONTENT_TYPE_KEY    2
#define NDN_CONTENT_TYPE_NACK   3

#define NDN_NAME_MAX_COMPONENTS             32
#define NDN_DEFAULT_INTEREST_LIFETIME_MS    4000

/* ---- Name component ---- */
struct ndn_name_component {
    uint64_t        type;
    uint32_t        length;
    const uint8_t  *value;  /* Points into original buffer (zero-copy) */
};

/* ---- Parsed NDN Name ---- */
struct ndn_name {
    uint8_t                   n_components;
    struct ndn_name_component components[NDN_NAME_MAX_COMPONENTS];
};

/* ---- Parsed Interest packet ---- */
struct ndn_interest {
    struct ndn_name  name;
    uint8_t          can_be_prefix;
    uint8_t          must_be_fresh;
    uint8_t          has_hop_limit;
    uint8_t          hop_limit;
    uint32_t         nonce;
    uint32_t         interest_lifetime_ms;
    const uint8_t   *app_params;
    uint32_t         app_params_len;
};

/* ---- Parsed Data packet ---- */
struct ndn_data {
    struct ndn_name  name;
    uint8_t          content_type;
    uint32_t         freshness_period_ms;
    const uint8_t   *content;
    uint32_t         content_len;
};

/* ---- NDN packet (tagged union) ---- */
typedef enum {
    NDN_PKT_INTEREST = NDN_TLV_INTEREST,
    NDN_PKT_DATA     = NDN_TLV_DATA,
} ndn_pkt_type_t;

struct ndn_packet {
    ndn_pkt_type_t type;
    union {
        struct ndn_interest interest;
        struct ndn_data     data;
    };
};

/*
 * Parse an NDN packet from raw bytes.
 *
 * buf  : pointer to the start of the NDN TLV (after Ethernet header)
 * len  : available bytes
 * pkt  : output
 *
 * 返り値: 0 = 成功, -1 = 解析失敗
 */
int ndn_parse_packet(const uint8_t *buf, uint32_t len,
                     struct ndn_packet *pkt);

/*
 * mbufからNDNパケットを処理する。
 * Ethernetヘッダ直後のNDNペイロードを解析する。
 *
 * 返り値: 0 = 成功, -1 = 解析失敗
 */
int process_ndn(struct rte_mbuf *m);

#endif /* NDN_H */
