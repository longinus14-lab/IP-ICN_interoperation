#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "http.h"

/* ペイロード内で部分文字列を探し、見つかった位置を返す (なければNULL) */
static const char *
find_crlf(const char *p, const char *end)
{
    while (p + 1 < end) {
        if (p[0] == '\r' && p[1] == '\n')
            return p;
        p++;
    }
    return NULL;
}

/* src から最大 dst_max-1 文字を dst にコピーしNUL終端する */
static void
safe_copy(char *dst, const char *src, size_t len, size_t dst_max)
{
    if (len >= dst_max)
        len = dst_max - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

int
parse_http_request(const char *payload, uint16_t payload_len,
                   struct http_request *req)
{
    const char *p   = payload;
    const char *end = payload + payload_len;

    memset(req, 0, sizeof(*req));

    /* ---- リクエストライン: "METHOD URI HTTP/1.x\r\n" ---- */

    /* METHOD */
    const char *sp1 = memchr(p, ' ', (size_t)(end - p));
    if (sp1 == NULL || sp1 == p)
        return -1;
    safe_copy(req->method, p, (size_t)(sp1 - p), sizeof(req->method));

    /* URI */
    p = sp1 + 1;
    const char *sp2 = memchr(p, ' ', (size_t)(end - p));
    if (sp2 == NULL || sp2 == p)
        return -1;
    safe_copy(req->uri, p, (size_t)(sp2 - p), sizeof(req->uri));

    /* HTTP バージョン確認 */
    p = sp2 + 1;
    const char *eol = find_crlf(p, end);
    if (eol == NULL)
        return -1;
    if (eol - p < 8 || memcmp(p, "HTTP/1.", 7) != 0)
        return -1;

    /* ---- ヘッダ行を1行ずつ解析 ---- */
    p = eol + 2; /* \r\n をスキップ */

    while (p < end) {
        eol = find_crlf(p, end);
        if (eol == NULL)
            break;

        /* 空行 (\r\n のみ) = ヘッダ終端 */
        if (eol == p) {
            req->header_len = (uint16_t)(p + 2 - payload);
            break;
        }

        /* "Name: Value" を分割 */
        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (colon == NULL) {
            p = eol + 2;
            continue;
        }

        size_t name_len  = (size_t)(colon - p);
        const char *val  = colon + 1;
        /* 値の先頭のスペースをスキップ */
        while (val < eol && *val == ' ')
            val++;
        size_t val_len = (size_t)(eol - val);

        /* 主要ヘッダを抽出 (大文字小文字を区別しない比較) */
        if (name_len == 4 && strncasecmp(p, "Host", 4) == 0) {
            safe_copy(req->host, val, val_len, sizeof(req->host));

        } else if (name_len == 12 && strncasecmp(p, "Content-Type", 12) == 0) {
            safe_copy(req->content_type, val, val_len, sizeof(req->content_type));

        } else if (name_len == 14 && strncasecmp(p, "Content-Length", 14) == 0) {
            char tmp[16];
            safe_copy(tmp, val, val_len, sizeof(tmp));
            req->content_length = (uint32_t)strtoul(tmp, NULL, 10);
        }

        p = eol + 2;
    }

    printf("      HTTP method=\"%s\" uri=\"%s\" host=\"%s\" "
           "content-type=\"%s\" content-length=%u\n",
           req->method, req->uri, req->host,
           req->content_type, req->content_length);

    return 0;
}
