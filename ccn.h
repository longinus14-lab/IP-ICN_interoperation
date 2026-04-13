#ifndef CCN_H
#define CCN_H

#include <stdint.h>
#include <rte_mbuf.h>

/*
 * CCNx パケット処理 (RFC8569 / RFC8609)
 *
 * CCNxパケットはEther/IP/UDP(9695)/CCNxのスタックで伝送される。
 * TLVフォーマットは固定2バイトType + 2バイトLength (ネットワークバイトオーダー)。
 * NDNの可変長TLVとは異なる。
 */

/* ---- バージョン・パケットタイプ (RFC8609 Section 3.1) ---- */
#define CCN_VERSION             0x01
#define CCN_PT_INTEREST         0x00  /* Interest パケット */
#define CCN_PT_CONTENT          0x01  /* Content Object パケット */
#define CCN_PT_RETURN           0x02  /* Interest Return パケット */

/* CCNxの標準UDPポート */
#define CCN_UDP_PORT            9695

/* 固定ヘッダ長 */
#define CCN_FIXED_HEADER_LEN    8

/* ---- Message TLV タイプ (RFC8609 Section 3.3) ---- */
#define CCN_T_INTEREST          0x0001
#define CCN_T_CONTENT_OBJECT    0x0002

/* ---- Message本体のTLVタイプ ---- */
#define CCN_T_NAME              0x0000  /* Name TLV */
#define CCN_T_PAYLOAD           0x0001  /* Content Object のペイロード */
#define CCN_T_KEYIDRESTR        0x0002  /* Interest の KeyIdRestriction */
#define CCN_T_OBJHASHRESTR      0x0003  /* Interest の ObjHashRestriction */
#define CCN_T_PAYLDTYPE         0x0005  /* Content Object のペイロードタイプ */
#define CCN_T_EXPIRY            0x0006  /* Content Object の有効期限 (ms since epoch) */

/* ---- Name セグメントのTLVタイプ (RFC8609 Section 3.3.3) ---- */
#define CCN_T_NAMESEGMENT       0x0001  /* 汎用Nameセグメント */
#define CCN_T_IPID              0x0002  /* Interest Payload ID */

/* ---- Optional Header のTLVタイプ (RFC8609 Section 3.2) ---- */
#define CCN_T_INTLIFE           0x0001  /* Interest Lifetime (2バイト, ms) */
#define CCN_T_CACHETIME         0x0002  /* Recommended Cache Time */

/* ---- PayloadType 値 (RFC8609 Section 3.3.2.2) ---- */
#define CCN_PAYLDTYPE_DATA      0x00
#define CCN_PAYLDTYPE_KEY       0x01
#define CCN_PAYLDTYPE_LINK      0x02
#define CCN_PAYLDTYPE_MANIFEST  0x03

/* ---- 各種上限値 ---- */
#define CCN_NAME_MAX_SEGMENTS   32
#define CCN_DEFAULT_INTLIFE_MS  4000  /* Interest Lifetimeのデフォルト値 (ms) */

/*
 * CCNx 固定ヘッダ (8バイト, RFC8609 Section 3.1)
 *
 * wire上のバイト列に直接キャストするため __attribute__((packed)) を使用。
 * pkt_len / 複数バイトフィールドはネットワークバイトオーダー。
 */
struct __attribute__((packed)) ccn_fixed_hdr {
    uint8_t  version;    /* 常に CCN_VERSION (0x01) */
    uint8_t  pkt_type;   /* CCN_PT_INTEREST / CCN_PT_CONTENT / CCN_PT_RETURN */
    uint16_t pkt_len;    /* パケット全体長 (固定ヘッダ + Optional Headers + Message) */
    uint8_t  hop_limit;  /* ホップ数制限 (Interest のみ使用) */
    uint8_t  reserved1;
    uint8_t  reserved2;
    uint8_t  hdr_len;    /* パケット先頭からMessage TLVまでのバイトオフセット (最小8) */
};

/* ---- Nameセグメント (mbuf内への zero-copy ポインタ) ---- */
struct ccn_name_segment {
    uint16_t        type;    /* CCN_T_NAMESEGMENT 等 */
    uint16_t        length;
    const uint8_t  *value;   /* mbuf内データへの直接ポインタ (zero-copy) */
};

/* ---- パース済みCCNx Name ---- */
struct ccn_name {
    uint8_t                 n_segments;
    struct ccn_name_segment segments[CCN_NAME_MAX_SEGMENTS];

    /*
     * T_NAME TLV 全体のwire位置 (gw_pit / cs のキーとして使用)
     * wire[0..wire_len-1] = {0x00,0x00, Lhi,Llo, seg...}
     */
    const uint8_t          *wire;      /* mbuf内T_NAME type先頭ポインタ */
    uint16_t                wire_len;  /* T_NAME TLV全体のバイト数 (= 4 + value_len) */
};

/* ---- パース済みCCNx Interest ---- */
struct ccn_interest {
    struct ccn_name  name;
    uint8_t          hop_limit;        /* 固定ヘッダから取得 */
    uint16_t         lifetime_ms;      /* T_INTLIFE Optional Header から取得 */
    const uint8_t   *keyid_restr;      /* T_KEYIDRESTR valueポインタ (NULLなら不在) */
    uint16_t         keyid_restr_len;
    const uint8_t   *hash_restr;       /* T_OBJHASHRESTR valueポインタ (NULLなら不在) */
    uint16_t         hash_restr_len;
};

/* ---- パース済みCCNx Content Object ---- */
struct ccn_content {
    struct ccn_name  name;
    uint8_t          payload_type;     /* CCN_PAYLDTYPE_* (デフォルト: DATA) */
    uint64_t         expiry_time;      /* T_EXPIRY: epoch ms, 0=不在 */
    const uint8_t   *payload;          /* T_PAYLOAD valueポインタ (NULLなら不在) */
    uint16_t         payload_len;
};

/* ---- CCNxパケット (タグ付きユニオン) ---- */
typedef enum {
    CCN_PKT_INTEREST = CCN_PT_INTEREST,  /* 0x00 */
    CCN_PKT_CONTENT  = CCN_PT_CONTENT,   /* 0x01 */
    CCN_PKT_RETURN   = CCN_PT_RETURN,    /* 0x02 */
} ccn_pkt_type_t;

struct ccn_packet {
    ccn_pkt_type_t type;
    union {
        struct ccn_interest interest;
        struct ccn_content  content;
    };
};

/*
 * CCNxパケットをパースする。
 *
 * buf : UDPペイロード先頭 (CCNx固定ヘッダのbyte 0)
 * len : 利用可能バイト数 (udp->dgram_len - sizeof(rte_udp_hdr))
 * pkt : パース結果の出力先
 *
 * 返り値: 0 = 成功, -1 = パースエラー
 */
int ccn_parse_packet(const uint8_t *buf, uint32_t len, struct ccn_packet *pkt);

/*
 * udp.c から呼び出されるCCNx処理エントリポイント。
 * dst_port == CCN_UDP_PORT のとき呼ばれる。
 *
 * m          : mbuf (zero-copy検証用)
 * buf        : CCNx固定ヘッダ先頭ポインタ
 * len        : CCNxペイロード長
 * ip_src_be  : 送信元IPアドレス (network byte order)
 * udp_src_be : 送信元UDPポート (network byte order)
 * eth_src    : 送信元MACアドレス
 *
 * 返り値: 0 = 成功, -1 = 失敗
 */
int process_ccn(struct rte_mbuf *m, const uint8_t *buf, uint32_t len,
                uint32_t ip_src_be, uint16_t udp_src_be,
                const struct rte_ether_addr *eth_src);

#endif /* CCN_H */
