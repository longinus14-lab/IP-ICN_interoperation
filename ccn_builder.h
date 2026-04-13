#ifndef CCN_BUILDER_H
#define CCN_BUILDER_H

#include <stdint.h>
#include <stddef.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "ccn.h"
#include "connection.h"

/*
 * CCN/HTTP パケット構築関数群
 *
 * IP↔CCN 変換ゲートウェイの双方向変換ロジックを実装する。
 * 全関数はゼロコピー設計で、新規mbufを確保して完全なパケットを返す。
 */

/* ================================================================
 * 名前変換ユーティリティ
 * ================================================================ */

/*
 * HTTP URIパスをCCN Name TLV wire encodingに変換する。
 *
 * "/"区切りで各コンポーネントを T_NAMESEGMENT TLV に変換し、
 * 全体を T_NAME TLV で包む。
 * 例: "/a/b/c" → T_NAME { T_NAMESEGMENT("a"), T_NAMESEGMENT("b"), T_NAMESEGMENT("c") }
 *
 * uri           : NUL終端URIパス文字列 (例: "/path/to/data")
 * name_wire_out : 出力バッファ (TCB_CCN_NAME_WIRE_MAX バイト以上)
 * len_out       : 出力: 書き込んだバイト数
 *
 * 返り値: 0 = 成功, -1 = 失敗 (URI不正またはバッファ不足)
 */
int ccn_name_from_uri_path(const char *uri,
                            uint8_t *name_wire_out,
                            uint16_t *len_out);

/*
 * CCN Name TLV wire encodingをHTTP URIパス文字列に変換する。
 *
 * 例: T_NAME { T_NAMESEGMENT("a"), T_NAMESEGMENT("b") } → "/a/b"
 *
 * name     : パース済みCCN名前構造体
 * uri_out  : 出力バッファ
 * uri_max  : 出力バッファサイズ
 *
 * 返り値: 0 = 成功, -1 = バッファ不足
 */
int ccn_uri_path_from_name(const struct ccn_name *name,
                            char *uri_out, size_t uri_max);

/* ================================================================
 * CCN パケット構築
 * ================================================================ */

/*
 * CCN Interestパケットを新規mbufに構築して返す。
 *
 * Ether/IP/UDP/CCN 全ヘッダを含む完全なパケットを生成する。
 * 宛先: gw_config.h の GW_CCN_HOST_MAC / GW_CCN_HOST_IP_BE / CCN_UDP_PORT
 *
 * name_wire     : T_NAME TLV wire encoding (ccn_name_from_uri_pathで生成)
 * name_wire_len : バイト数
 *
 * 返り値: 成功時mbuf*, 失敗時NULL (プールが空など)
 */
struct rte_mbuf *build_ccn_interest(const uint8_t *name_wire,
                                     uint16_t name_wire_len);

/*
 * CCN Content Objectパケットを新規mbufに構築して返す。
 *
 * Ether/IP/UDP/CCN 全ヘッダを含む完全なパケットを生成する。
 * 送信先は引数で指定する (IP→CCNではCCNホスト、CCN→IPではCCN Interest送信元)。
 *
 * name_wire     : T_NAME TLV wire encoding
 * name_wire_len : バイト数
 * payload       : ペイロードデータ
 * payload_len   : バイト数
 * dst_mac       : 送信先MACアドレス
 * dst_ip_be     : 送信先IPアドレス (network byte order)
 * dst_port_be   : 送信先UDPポート (network byte order)
 *
 * 返り値: 成功時mbuf*, 失敗時NULL
 */
struct rte_mbuf *build_ccn_content_object(const uint8_t *name_wire,
                                           uint16_t name_wire_len,
                                           const uint8_t *payload,
                                           uint32_t payload_len,
                                           const struct rte_ether_addr *dst_mac,
                                           uint32_t dst_ip_be,
                                           uint16_t dst_port_be);

/* ================================================================
 * HTTP パケット構築
 * ================================================================ */

/*
 * HTTP GET リクエストを格納したTCPパケットを新規mbufに構築して返す。
 *
 * ゲートウェイが IPホストへアウトゴイング接続で HTTP GET を送信する際に使用。
 * (CCN→IP方向で TCP SYN-ACK 受信後に呼ばれる)
 *
 * key  : outgoing接続の4タプルキー (src=GW, dst=IPホスト)
 * tcb  : outgoing接続のTCB
 * uri  : リクエストするURIパス (例: "/a/b/c")
 *
 * 返り値: 成功時mbuf*, 失敗時NULL
 */
struct rte_mbuf *build_http_get(const struct conn_key *key,
                                 struct tcb *tcb,
                                 const char *uri);

/*
 * HTTP/1.1 200 OK レスポンスを格納したTCPパケットを新規mbufに構築して返す。
 *
 * ゲートウェイが IPホストへ CCN Content Object のペイロードを返す際に使用。
 * (IP→CCN方向で CCN Content Object 受信後に gw_pit 経由で呼ばれる)
 *
 * key         : incoming接続の4タプルキー
 * tcb         : incoming接続のTCB (peer_mac, seq/ackを使用)
 * payload     : レスポンスボディ
 * payload_len : バイト数
 *
 * 返り値: 成功時mbuf*, 失敗時NULL
 */
struct rte_mbuf *build_http_response(const struct conn_key *key,
                                      struct tcb *tcb,
                                      const uint8_t *payload,
                                      uint32_t payload_len);

/* ================================================================
 * TCP 制御パケット構築
 * ================================================================ */

/*
 * TCP SYN パケットを新規mbufに構築して返す。
 *
 * ゲートウェイが IPホストへアウトゴイング接続を開始する際に使用。
 * (CCN→IP方向で CCN Interest 受信後に呼ばれる)
 *
 * key : outgoing接続の4タプルキー (src=GW, dst=IPホスト)
 * tcb : outgoing接続のTCB (snd_nxt=ISS がセット済みであること)
 *
 * 返り値: 成功時mbuf*, 失敗時NULL
 */
struct rte_mbuf *build_tcp_syn(const struct conn_key *key,
                                struct tcb *tcb);

/*
 * TCP ACK パケットを新規mbufに構築して返す。
 *
 * outgoing接続で SYN-ACK 受信後の ACK 送信に使用。
 *
 * key : outgoing接続の4タプルキー
 * tcb : outgoing接続のTCB
 *
 * 返り値: 成功時mbuf*, 失敗時NULL
 */
struct rte_mbuf *build_tcp_ack(const struct conn_key *key,
                                struct tcb *tcb);

/*
 * TCP FIN+ACK パケットを新規mbufに構築して返す。
 *
 * 相手から FIN を受信したときのパッシブクローズ応答に使用。
 * tcb->is_outgoing に応じて src/dst の方向を自動判定する:
 *   is_outgoing=0 (incoming): key.src=IPホスト → GW側からIPホストへ返信
 *   is_outgoing=1 (outgoing): key.src=GW, key.dst=IPホスト → IPホストへ送信
 * 呼び出し側は送信後 conn_delete() で TCB を解放すること。
 *
 * key : 接続の4タプルキー
 * tcb : 接続のTCB (rcv_nxt は FIN 受信後に更新済みであること)
 *
 * 返り値: 成功時mbuf*, 失敗時NULL
 */
struct rte_mbuf *build_tcp_fin_ack(const struct conn_key *key,
                                    struct tcb *tcb);

/*
 * エフェメラルポート番号を生成する。
 * アウトゴイングTCP接続のソースポートとして使用。
 *
 * 返り値: 49152〜65534 の範囲のポート番号 (ホストバイトオーダー)
 */
uint16_t ephemeral_port_alloc(void);

#endif /* CCN_BUILDER_H */
