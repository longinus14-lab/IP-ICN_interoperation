#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

#define HTTP_METHOD_MAX   16
#define HTTP_URI_MAX      512
#define HTTP_HOST_MAX     256
#define HTTP_CTYPE_MAX    128

/* 解析済みHTTP/1.1リクエストを格納する構造体 */
struct http_request {
    char     method[HTTP_METHOD_MAX];   /* GET, POST, etc. */
    char     uri[HTTP_URI_MAX];         /* リクエストURI */
    char     host[HTTP_HOST_MAX];       /* Hostヘッダ */
    char     content_type[HTTP_CTYPE_MAX]; /* Content-Typeヘッダ */
    uint32_t content_length;            /* Content-Lengthヘッダ (なければ0) */
    uint16_t header_len;                /* ヘッダ全体の長さ (body先頭オフセット) */
};

/*
 * HTTPリクエストを解析する
 *
 * payload     : TCPペイロードの先頭ポインタ
 * payload_len : ペイロード長
 * req         : 解析結果の格納先
 *
 * 返り値:
 *   0  : 解析成功
 *  -1  : 不正なフォーマット
 */
int parse_http_request(const char *payload, uint16_t payload_len,
                       struct http_request *req);

#endif /* HTTP_H */
