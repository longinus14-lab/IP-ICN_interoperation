#ifndef GW_CONFIG_H
#define GW_CONFIG_H

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

/*
 * ゲートウェイ設定定数
 *
 * ネットワーク構成:
 *   IPホスト (10.0.0.1) <-- eth1 (10.0.0.254) --> ゲートウェイ <-- eth2 (192.168.0.254) --> CCNホスト (192.168.0.1)
 */

/* ---- DPDKポートID ---- */
#define ETH1_PORT_ID    0   /* IP側インターフェース (eth1) */
#define ETH2_PORT_ID    1   /* CCN側インターフェース (eth2) */

/* ---- CCN側 (eth2) 設定 ---- */
/* CCNホストのIPアドレス (network byte order) */
#define GW_CCN_HOST_IP_BE   RTE_IPV4(192, 168, 0, 1)

/* CCNホストのMACアドレス */
#define GW_CCN_HOST_MAC_INIT  { .addr_bytes = { 0xaa, 0xc1, 0xab, 0xe8, 0xa5, 0x48 } }

/* ゲートウェイ eth2 のIPアドレス (network byte order) */
#define GW_ETH2_IP_BE       RTE_IPV4(192, 168, 0, 254)

/* ---- IP側 (eth1) 設定 ---- */
/* IPホストのIPアドレス (network byte order) */
#define GW_IP_HOST_IP_BE    RTE_IPV4(10, 0, 0, 1)

/* IPホストのMACアドレス */
#define GW_IP_HOST_MAC_INIT  { .addr_bytes = { 0xaa, 0xc1, 0xab, 0x87, 0xda, 0x1a } }

/* ゲートウェイ eth1 のIPアドレス (network byte order) */
#define GW_ETH1_IP_BE       RTE_IPV4(10, 0, 0, 254)

/* ---- ポート設定 ---- */
#define GW_IP_HOST_PORT      80     /* IPホストへのHTTPポート */
#define GW_CCN_UDP_SRC_PORT  12345  /* CCN Interest送信時のUDPソースポート */

/* ---- TTL設定 ---- */
#define GW_DEFAULT_TTL       64
#define GW_CCN_HOP_LIMIT     32

/* ---- CCN Interest デフォルトLifetime (ms) ---- */
#define GW_CCN_INTEREST_LIFETIME_MS  4000

/*
 * ゲートウェイ自身のMACアドレス (main.cでrte_eth_macaddr_getして格納)
 * tcp.c, ccn_builder.c から extern で参照する
 */
extern struct rte_ether_addr gw_eth1_mac;
extern struct rte_ether_addr gw_eth2_mac;

/*
 * DPDKメモリプール (main.cで確保)
 * 新規パケット構築時にccn_builder.cから参照する
 */
extern struct rte_mempool *mbuf_pool;

#endif /* GW_CONFIG_H */
