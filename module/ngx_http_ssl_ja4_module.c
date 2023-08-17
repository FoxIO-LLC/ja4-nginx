#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>

typedef struct ngx_ssl_ja4_s {
    int             version;

    size_t          ciphers_sz;
    unsigned short *ciphers;

    size_t          extensions_sz;
    unsigned short *extensions;

    size_t          curves_sz;
    unsigned short  *curves;

    size_t          point_formats_sz;
    unsigned char  *point_formats;

} ngx_ssl_ja4_t;


int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

/* http_json_log config preparation */
static ngx_http_module_t ngx_http_ssl_ja4_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ssl_ja4_init,                 /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


/* http_json_log delivery */
ngx_module_t ngx_http_ssl_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_ja4_module_ctx,          /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_ssl_ja4_hash(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_t                  ja4;
    ngx_str_t                      fp = ngx_null_string;

    ngx_md5_t                      ctx;
    u_char                         hash[17] = {0};

    if (r->connection == NULL) {
        return NGX_OK;
    }

    v->data = ngx_pcalloc(r->pool, 32);

    if (v->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED) {
        return NGX_ERROR;
    }

    ngx_ssl_ja4_fp(r->pool, &ja4, &fp);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, fp.data, fp.len);
    ngx_md5_final(hash, &ctx);
    ngx_hex_dump(v->data, hash, 16);

    v->len = 32;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

#if (NGX_DEBUG)
    {
        u_char                         hash_hex[33] = {0};
        ngx_memcpy(hash_hex, v->data, 32);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       r->connection->pool->log, 0, "ssl_ja4: http: hash: [%s]\n", hash_hex);
    }
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_t                  ja4;
    ngx_str_t                      fp = ngx_null_string;

    if (r->connection == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED) {
        return NGX_ERROR;
    }

    ngx_ssl_ja4_fp(r->pool, &ja4, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_http_variable_t  ngx_http_ssl_ja4_variables_list[] = {

    {   ngx_string("http_ssl_ja4_hash"),
        NULL,
        ngx_http_ssl_ja4_hash,
        0, 0, 0
    },
    {   ngx_string("http_ssl_ja4"),
        NULL,
        ngx_http_ssl_ja4,
        0, 0, 0
    },

};


static ngx_int_t
ngx_http_ssl_ja4_init(ngx_conf_t *cf)
{

    ngx_http_variable_t          *v;
    size_t                        l = 0;
    size_t                        vars_len;

    vars_len = (sizeof(ngx_http_ssl_ja4_variables_list) /
            sizeof(ngx_http_ssl_ja4_variables_list[0]));

    /* Register variables */
    for (l = 0; l < vars_len ; ++l) {
        v = ngx_http_add_variable(cf,
                &ngx_http_ssl_ja4_variables_list[l].name,
                ngx_http_ssl_ja4_variables_list[l].flags);
        if (v == NULL) {
            continue;
        }
        *v = ngx_http_ssl_ja4_variables_list[l];
    }

    return NGX_OK;
}

static const unsigned short GREASE[] = {
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa,
};


static int
ngx_ssl_ja4_is_ext_greased(int id)
{
    size_t i;
    for (i = 0; i < (sizeof(GREASE) / sizeof(GREASE[0])); ++i) {
        if (id == GREASE[i]) {
            return 1;
        }
    }
    return 0;
}


static const int nid_list[] = {
    NID_sect163k1,        /* sect163k1 (1) */
    NID_sect163r1,        /* sect163r1 (2) */
    NID_sect163r2,        /* sect163r2 (3) */
    NID_sect193r1,        /* sect193r1 (4) */
    NID_sect193r2,        /* sect193r2 (5) */
    NID_sect233k1,        /* sect233k1 (6) */
    NID_sect233r1,        /* sect233r1 (7) */
    NID_sect239k1,        /* sect239k1 (8) */
    NID_sect283k1,        /* sect283k1 (9) */
    NID_sect283r1,        /* sect283r1 (10) */
    NID_sect409k1,        /* sect409k1 (11) */
    NID_sect409r1,        /* sect409r1 (12) */
    NID_sect571k1,        /* sect571k1 (13) */
    NID_sect571r1,        /* sect571r1 (14) */
    NID_secp160k1,        /* secp160k1 (15) */
    NID_secp160r1,        /* secp160r1 (16) */
    NID_secp160r2,        /* secp160r2 (17) */
    NID_secp192k1,        /* secp192k1 (18) */
    NID_X9_62_prime192v1, /* secp192r1 (19) */
    NID_secp224k1,        /* secp224k1 (20) */
    NID_secp224r1,        /* secp224r1 (21) */
    NID_secp256k1,        /* secp256k1 (22) */
    NID_X9_62_prime256v1, /* secp256r1 (23) */
    NID_secp384r1,        /* secp384r1 (24) */
    NID_secp521r1,        /* secp521r1 (25) */
    NID_brainpoolP256r1,  /* brainpoolP256r1 (26) */
    NID_brainpoolP384r1,  /* brainpoolP384r1 (27) */
    NID_brainpoolP512r1,  /* brainpool512r1 (28) */
    NID_X25519,           /* X25519 (29) */
    NID_X448,             /* X448 (30) */
};


static unsigned short
ngx_ssl_ja4_nid_to_cid(int nid)
{
    unsigned char i;
    unsigned char sz = (sizeof(nid_list) / sizeof(nid_list[0]));

    for (i = 0; i < sz; i++) {
        if (nid == nid_list[i]) {
            return i+1;
        }
    }

    if (nid == NID_ffdhe2048) {
        return 0x100;
    }
    if (nid == NID_ffdhe3072) {
        return 0x101;
    }
    if (nid == NID_ffdhe4096) {
        return 0x102;
    }
    if (nid == NID_ffdhe6144) {
        return 0x103;
    }
    if (nid == NID_ffdhe8192) {
        return 0x104;
    }

    return nid;
}

static size_t
ngx_ssj_ja4_num_digits(int n)
{
    int c = 0;
    if (n < 9) {
        return 1;
    }
    for (; n; n /= 10) {
        ++c;
    }
    return c;
}

// static void
// ngx_sort_ext(unsigned short *ext, int size)
// {
//     for (int i = 0; i < size - 1; i++)
//     {
//         for (int j = 0; j < size - i - 1; j++)
//         {
//             if (ext[j] > ext[j + 1])
//             {
//                 int tmp = ext[j];
//                 ext[j] = ext[j + 1];
//                 ext[j + 1] = tmp;
//             }
//         }
//     }
// }

#if (NGX_DEBUG)
static void
ngx_ssl_ja4_detail_print(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    size_t i;
    /* Version */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: Version:  %d\n", ja4->version);

    /* Ciphers */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: ciphers: length: %d\n",
                   ja4->ciphers_sz);

    for (i = 0; i < ja4->ciphers_sz; ++i) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    cipher: 0x%04uxD -> %d",
                       ja4->ciphers[i],
                       ja4->ciphers[i]
        );
    }

    /* Extensions */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extensions: length: %d\n",
                   ja4->extensions_sz);

    for (i = 0; i < ja4->extensions_sz; ++i) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    extension: 0x%04uxD -> %d",
                       ja4->extensions[i],
                       ja4->extensions[i]
        );
    }

    /* Eliptic Curves */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: curves: length: %d\n",
                   ja4->curves_sz);

    for (i = 0; i < ja4->curves_sz; ++i) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    curves: 0x%04uxD -> %d",
                       ja4->curves[i],
                       ja4->curves[i]
        );
    }

    /* EC Format Points */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: formats: length: %d\n",
                   ja4->point_formats_sz);
    for (i = 0; i < ja4->point_formats_sz; ++i) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    format: %d",
                       ja4->point_formats[i]
        );
    }
}
#endif


void
ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    size_t                    i;
    size_t                    len = 0, cur = 0;

    if (pool == NULL || ja4 == NULL || out == NULL) {
        return;
    }

    len += ngx_ssj_ja4_num_digits(ja4->version);            /* Version */
    ++len;                                                  /* ',' separator */

    if (ja4->ciphers_sz) {
        for (i = 0; i < ja4->ciphers_sz; ++i) {
            len += ngx_ssj_ja4_num_digits(ja4->ciphers[i]); /* cipher [i] */
        }
        len += (ja4->ciphers_sz - 1);                       /* '-' separators */
    }
    ++len;                                                  /* ',' separator */

    if (ja4->extensions_sz) {
        for (i = 0; i < ja4->extensions_sz; ++i) {
            len += ngx_ssj_ja4_num_digits(ja4->extensions[i]); /* ext [i] */
        }
        len += (ja4->extensions_sz - 1);                   /* '-' separators */
    }
    ++len;                                                  /* ',' separator */

    if (ja4->curves_sz) {
        for (i = 0; i < ja4->curves_sz; ++i) {
            len += ngx_ssj_ja4_num_digits(ja4->curves[i]); /* curves [i] */
        }
        len += (ja4->curves_sz - 1);                       /* '-' separators */
    }
    ++len;                                                  /* ',' separator */

    if (ja4->point_formats_sz) {
        for (i = 0; i < ja4->point_formats_sz; ++i) {
            len += ngx_ssj_ja4_num_digits(ja4->point_formats[i]); /* fmt [i] */
        }
        len += (ja4->point_formats_sz - 1);                 /* '-' separators */
    }

    out->data = ngx_pnalloc(pool, len);
    out->len = len;

    len = ngx_ssj_ja4_num_digits(ja4->version) + 1;
    ngx_snprintf(out->data + cur, len, "%d,", ja4->version);
    cur += len;

    if (ja4->ciphers_sz) {
        for (i = 0; i < ja4->ciphers_sz; ++i) {
            if (i > 0) {
                ngx_snprintf(out->data + (cur++), 1, "-");
            }
            len = ngx_ssj_ja4_num_digits(ja4->ciphers[i]);
            ngx_snprintf(out->data + cur, len, "%d", ja4->ciphers[i]);
            cur += len;
        }
    }
    ngx_snprintf(out->data + (cur++), 1, ",");

    if (ja4->extensions_sz) {
        for (i = 0; i < ja4->extensions_sz; i++) {
            if (i > 0) {
                ngx_snprintf(out->data + (cur++), 1, "-");
            }
            len = ngx_ssj_ja4_num_digits(ja4->extensions[i]);
            ngx_snprintf(out->data + cur, len, "%d", ja4->extensions[i]);
            cur += len;
        }
    }
    ngx_snprintf(out->data + (cur++), 1, ",");

    if (ja4->curves_sz) {
        for (i = 0; i < ja4->curves_sz; i++) {
            if (i > 0) {
                ngx_snprintf(out->data + (cur++), 1, "-");
            }
            len = ngx_ssj_ja4_num_digits(ja4->curves[i]);
            ngx_snprintf(out->data + cur, len, "%d", ja4->curves[i]);
            cur += len;
        }
    }
    ngx_snprintf(out->data + (cur++), 1, ",");

    if (ja4->point_formats_sz) {
        for (i = 0; i < ja4->point_formats_sz; i++) {
            if (i > 0) {
                ngx_snprintf(out->data + (cur++), 1, "-");
            }
            len = ngx_ssj_ja4_num_digits(ja4->point_formats[i]);
            ngx_snprintf(out->data + cur, len, "%d", ja4->point_formats[i]);
            cur += len;
        }
    }

    out->len = cur;
#if (NGX_DEBUG)
    ngx_ssl_ja4_detail_print(pool, ja4);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: fp: [%V]\n", out);
#endif

}


/*
   /usr/bin/openssl s_client -connect 127.0.0.1:12345 \
           -cipher "AES128-SHA" -curves secp521r1
*/
int
ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4) {

    SSL                           *ssl;
    size_t                         i;
    size_t                         len = 0;
    unsigned short                 us = 0;

    if (! c->ssl) {
        return NGX_DECLINED;
    }

    if (! c->ssl->handshaked) {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if ( ! ssl) {
        return NGX_DECLINED;
    }

    /* SSLVersion*/
    ja4->version = SSL_version(ssl);

    /* Cipher suites */
    ja4->ciphers = NULL;
    ja4->ciphers_sz = 0;

    if (c->ssl->ciphers && c->ssl->ciphers_sz) {
        len = c->ssl->ciphers_sz * sizeof(unsigned short);
        ja4->ciphers = ngx_pnalloc(pool, len);
        if (ja4->ciphers == NULL) {
            return NGX_DECLINED;
        }
        /* Filter out GREASE extensions */
        for (i = 0; i < c->ssl->ciphers_sz; ++i) {
            us = ntohs(c->ssl->ciphers[i]);
            if (! ngx_ssl_ja4_is_ext_greased(us)) {
                ja4->ciphers[ja4->ciphers_sz++] = us;
            }
        }
    }

    /* Extensions */
    ja4->extensions = NULL;
    ja4->extensions_sz = 0;
    if (c->ssl->extensions_sz && c->ssl->extensions) {
        len = c->ssl->extensions_sz * sizeof(int);
        ja4->extensions = ngx_pnalloc(pool, len);
        if (ja4->extensions == NULL) {
            return NGX_DECLINED;
        }
        for (i = 0; i < c->ssl->extensions_sz; ++i) {
            if (! ngx_ssl_ja4_is_ext_greased(c->ssl->extensions[i])) {
                ja4->extensions[ja4->extensions_sz++] = c->ssl->extensions[i];
            }
        }
// #ifdef ja4_SORT_EXT
//         ngx_sort_ext(ja4->extensions, ja4->extensions_sz);
// #endif
    }

    /* Elliptic curve points */
    ja4->curves = c->ssl->curves;
    ja4->curves_sz = 0;
    if (c->ssl->curves && c->ssl->curves_sz) {
        len = c->ssl->curves_sz * sizeof(int);
        ja4->curves = ngx_pnalloc(pool, len);
        if (ja4->curves == NULL) {
            return NGX_DECLINED;
        }
        for (i = 0; i < c->ssl->curves_sz; i++) {
            us = ntohs(c->ssl->curves[i]);
            if (! ngx_ssl_ja4_is_ext_greased(us)) {
                ja4->curves[ja4->curves_sz++] = ngx_ssl_ja4_nid_to_cid(c->ssl->curves[i]);
            }
        }
    }

    /* Elliptic curve point formats */
    ja4->point_formats_sz = c->ssl->point_formats_sz;
    ja4->point_formats = c->ssl->point_formats;

    return NGX_OK;
}
