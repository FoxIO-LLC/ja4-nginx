#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>
#include <openssl/sha.h>

typedef struct ngx_ssl_ja4_s
{
    const char *version; // TLS version

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz;       // Count of ciphers
    unsigned short *ciphers; // List of ciphers

    size_t extensions_sz;       // Count of extensions
    unsigned short *extensions; // List of extensions

    size_t alpn_sz;    // Size of the first ALPN value (assuming it's a string)
    char *alpn_values; // First ALPN extension value

    char cipher_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char cipher_hash_truncated[13]; // 12 bytes * 2 characters/byte + 1 for '\0'

    char extension_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char extension_hash_truncated[13]; // 6 bytes * 2 characters/byte + 1 for '\0'
} ngx_ssl_ja4_t;

int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

/* http_json_log config preparation */
static ngx_http_module_t ngx_http_ssl_ja4_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_http_ssl_ja4_init, /* postconfiguration */
    NULL,                  /* create main configuration */
    NULL,                  /* init main configuration */
    NULL,                  /* create server configuration */
    NULL,                  /* merge server configuration */
    NULL,                  /* create location configuration */
    NULL                   /* merge location configuration */
};

/* http_json_log delivery */
ngx_module_t ngx_http_ssl_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_ja4_module_ctx, /* module context */
    NULL,                         /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_ssl_ja4(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED)
    {
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
/**
 * This is a list of Nginx variables that will be registered with Nginx.
 * The `ngx_http_add_variable` function will be used to register each
 * variable in the `ngx_http_ssl_ja4_init` function.
 */
static ngx_http_variable_t ngx_http_ssl_ja4_variables_list[] = {

    {ngx_string("http_ssl_ja4"),
     NULL,
     ngx_http_ssl_ja4,
     0, 0, 0},

};

/**
 * ngx_http_ssl_ja4_init - Initialize Nginx variables for JA4.
 *
 * This function initializes Nginx variables so that they can be accessed
 * and used in the Nginx configuration files. It iterates over a predefined
 * list of variables (`ngx_http_ssl_ja4_variables_list`) and registers each
 * variable using the `ngx_http_add_variable` function.
 *
 * @param cf A pointer to the Nginx configuration structure.
 * @return NGX_OK on successful initialization.
 */
static ngx_int_t
ngx_http_ssl_ja4_init(ngx_conf_t *cf)
{

    ngx_http_variable_t *v;
    size_t l = 0;
    size_t vars_len;

    vars_len = (sizeof(ngx_http_ssl_ja4_variables_list) /
                sizeof(ngx_http_ssl_ja4_variables_list[0]));

    /* Register variables */
    for (l = 0; l < vars_len; ++l)
    {
        v = ngx_http_add_variable(cf,
                                  &ngx_http_ssl_ja4_variables_list[l].name,
                                  ngx_http_ssl_ja4_variables_list[l].flags);
        if (v == NULL)
        {
            continue;
        }
        *v = ngx_http_ssl_ja4_variables_list[l];
    }

    return NGX_OK;
}

/**
 * Grease values to be ignored.
*/
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
    for (i = 0; i < (sizeof(GREASE) / sizeof(GREASE[0])); ++i)
    {
        if (id == GREASE[i])
        {
            return 1;
        }
    }
    return 0;
}

#if (NGX_DEBUG)
static void
ngx_ssl_ja4_detail_print(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    size_t i;

    /* Transport Protocol (QUIC or TCP) */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: Transport Protocol: %c",
                   ja4->transport);

    /* SNI presence or absence */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: SNI: %c",
                   ja4->has_sni);

    /* Version */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: Version:  %d\n", ja4->version);

    /* Ciphers */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: ciphers: length: %d\n",
                   ja4->ciphers_sz);

    for (i = 0; i < ja4->ciphers_sz; ++i)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    cipher: 0x%04uxD -> %d",
                       ja4->ciphers[i],
                       ja4->ciphers[i]);
    }

    // cipher hash
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: cipher hash: %s\n",
                   ja4->cipher_hash);

    // cipher hash truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: cipher hash truncated: %s\n",
                   ja4->cipher_hash_truncated);

    // extension hash
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash: %s\n",
                   ja4->extension_hash);

    // extension hash truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash truncated: %s\n",
                   ja4->extension_hash_truncated);

    /* Extensions */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extensions: length: %d\n",
                   ja4->extensions_sz);

    for (i = 0; i < ja4->extensions_sz; ++i)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    extension: 0x%04uxD -> %d",
                       ja4->extensions[i],
                       ja4->extensions[i]);
    }

    /* ALPN Values */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: ALPN Values Length: %d",
                   ja4->alpn_sz);
    for (i = 0; i < ja4->alpn_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                       "ssl_ja4: |    ALPN Value: %c",
                       ja4->alpn_values[i]);
    }
}
#endif

void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // Calculate memory requirements for output
    size_t len = 1     // for q/t
                 + 2   // TLS version
                 + 1   // d/i for SNI
                 + 2   // count of ciphers
                 + 2   // count of extensions
                 + 2   // first and last characters of ALPN
                 + 1   // underscore
                 + 12  // truncated sha256 of ciphers in hex
                 + 1   // underscore
                 + 12; // truncated sha256 of extensions in hex

    out->data = ngx_pnalloc(pool, len);
    out->len = len;

    size_t cur = 0;

    // q for QUIC or t for TCP
    // out->data[cur++] = (ja4->is_quic) ? 'q' : 't';  // Assuming is_quic is a boolean.
    // TODO: placeholder
    out->data[cur++] = 't';

    // 2 character TLS version
    memcpy(out->data + cur, ja4->version, 2);
    cur += 2;

    // SNI = d, no SNI = i
    // out->data[cur++] = (ja4->has_sni) ? 'd' : 'i'; // Assuming has_sni is a boolean.
    // TODO: placeholder
    out->data[cur++] = 'i';
    // TODO: size or count?
    // 2 character count of ciphers
    ngx_snprintf(out->data + cur, 3, "%02zu", ja4->ciphers_sz);
    cur += 2;
    // TODO: size or count?
    // 2 character count of extensions
    ngx_snprintf(out->data + cur, 3, "%02zu", ja4->extensions_sz);
    cur += 2;

    // first and last characters of first ALPN extension value
    // Assuming ALPN values are stored in a char array.
    // if (ja4->alpn_sz > 0) {
    //     out->data[cur++] = ja4->alpn_values[0]; // first char
    //     out->data[cur++] = ja4->alpn_values[ja4->alpn_sz - 1]; // last char
    // }
    // Placeholder for ALPN in ngx_ssl_ja4_fp function
    // TODO: placeholder
    // We assume the ALPN values might be characters. So, for the sake of placeholder, let's use dummy characters.
    char first_alpn_char = 'a'; // dummy value for the first character
    char last_alpn_char = 'z';  // dummy value for the last character

    out->data[cur++] = first_alpn_char;
    out->data[cur++] = last_alpn_char;

    // add underscore
    out->data[cur++] = '_';

    // add cipher hash, 24 character with null terminator
    ngx_snprintf(out->data + cur, 13, "%s", ja4->cipher_hash_truncated);
    cur += 12; // Adjust the current pointer by 24 chars for the cipher hash

    // add underscore
    out->data[cur++] = '_';

    // add extension hash, 24 character with null terminator
    ngx_snprintf(out->data + cur, 13, "%s", ja4->extension_hash_truncated);
    cur += 12; // Adjust the current pointer by 24 chars for the extension

    out->len = cur;

#if (NGX_DEBUG)
    ngx_ssl_ja4_detail_print(pool, ja4);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp: [%V]\n", out);
#endif
}

static int compare_ciphers(const void *a, const void *b)
{
    unsigned short cipher_a = *(unsigned short *)a;
    unsigned short cipher_b = *(unsigned short *)b;

    if (cipher_a < cipher_b)
        return -1;
    if (cipher_a > cipher_b)
        return 1;
    return 0;
}

int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{

    SSL *ssl;
    size_t i;
    size_t len = 0;
    unsigned short us = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }

    // TODO: Need to detect QUIC
    // 1. Determine the transport protocol:
    // (This is a placeholder and might need to be replaced depending on how you determine the protocol in your environment.)
    ja4->transport = 't'; // Assuming default is TCP. You'll need to add a check for QUIC.

    // TODO: verify this
    // 2. Determine if SNI is present or not:
    const char *sni_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    ja4->has_sni = (sni_name != NULL) ? 'd' : 'i';

    // TODO: verify this
    // 3. Fetch the ALPN value:
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    if (alpn && alpnlen > 0)
    {
        ja4->alpn_sz = alpnlen;
        ja4->alpn_values = ngx_pnalloc(pool, alpnlen);
        if (!ja4->alpn_values)
        {
            return NGX_DECLINED;
        }
        ngx_memcpy(ja4->alpn_values, alpn, alpnlen);
    }
    else
    {
        ja4->alpn_sz = 0;
        ja4->alpn_values = NULL;
    }

    /* SSLVersion*/
    int version = SSL_version(c->ssl->connection);

    switch (version)
    {
    case SSL3_VERSION:
        ja4->version = "03";
        break;
    case TLS1_VERSION:
        ja4->version = "10";
        break;
    case TLS1_1_VERSION:
        ja4->version = "11";
        break;
    case TLS1_2_VERSION:
        ja4->version = "12";
        break;
    case TLS1_3_VERSION:
        ja4->version = "13";
        break;
    default:
        ja4->version = "XX"; // Represents an unknown version
        break;
    }

    /* Cipher suites */
    ja4->ciphers = NULL;
    ja4->ciphers_sz = 0;
    /*
    Allocate memory for and populate a list of ciphers from 'c->ssl->ciphers',
    excluding any GREASE values. The resulting ciphers are stored in host byte
    order in 'ja4->ciphers'. If memory allocation fails, the function returns NGX_DECLINED.
    */
    if (c->ssl->ciphers && c->ssl->ciphers_sz)
    {
        // total length required to store all ciphers
        len = c->ssl->ciphers_sz * sizeof(unsigned short);

        // allocate memory
        ja4->ciphers = ngx_pnalloc(pool, len);

        // check if memory allocation was successful
        if (ja4->ciphers == NULL)
        {
            return NGX_DECLINED;
        }
        /* Filter out GREASE extensions */
        for (i = 0; i < c->ssl->ciphers_sz; ++i)
        {
            // convert sipher from network byte order to host byte order
            us = ntohs(c->ssl->ciphers[i]);
            // if not a grease value, add it to the list of ciphers
            if (!ngx_ssl_ja4_is_ext_greased(us))
            {
                ja4->ciphers[ja4->ciphers_sz++] = us;
            }
        }
        /* Now, let's sort the ja4->ciphers array */
        qsort(ja4->ciphers, ja4->ciphers_sz, sizeof(unsigned short), compare_ciphers);
    }

    // check if we got ciphers
    if (ja4->ciphers && ja4->ciphers_sz)
    {
        // SHA256_DIGEST_LENGTH should be 32 bytes (256 bits)
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        // declare a context structure needed by openssl to compute hash
        SHA256_CTX sha256;
        // initialize the context
        SHA256_Init(&sha256);

        // iterate each cipher and add data to the context
        for (i = 0; i < ja4->ciphers_sz; i++)
        {
            SHA256_Update(&sha256, &(ja4->ciphers[i]), sizeof(unsigned short));
        }
        // compute hash, stored in hash_result
        SHA256_Final(hash_result, &sha256);

        // Convert the hash result to hex
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(&ja4->cipher_hash[i * 2], "%02x", hash_result[i]);
        }
        ja4->cipher_hash[2 * SHA256_DIGEST_LENGTH] = '\0'; // Null-terminate the hex string

        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->cipher_hash_truncated, ja4->cipher_hash, 12);
        ja4->cipher_hash_truncated[12] = '\0'; // Null-terminate the truncated hex string
    }

    /* Extensions */
    ja4->extensions = NULL;
    ja4->extensions_sz = 0;
    if (c->ssl->extensions_sz && c->ssl->extensions)
    {
        len = c->ssl->extensions_sz * sizeof(unsigned short);
        ja4->extensions = ngx_pnalloc(pool, len);
        if (ja4->extensions == NULL)
        {
            return NGX_DECLINED;
        }
        for (i = 0; i < c->ssl->extensions_sz; ++i)
        {
            if (!ngx_ssl_ja4_is_ext_greased(c->ssl->extensions[i]))
            {
                ja4->extensions[ja4->extensions_sz++] = c->ssl->extensions[i];
            }
        }
        /* Now, let's sort the ja4->extensions array */
        qsort(ja4->extensions, ja4->extensions_sz, sizeof(unsigned short), compare_ciphers);
    }

    if (ja4->extensions && ja4->extensions_sz)
    {
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        for (i = 0; i < ja4->extensions_sz; i++)
        {
            SHA256_Update(&sha256, &(ja4->extensions[i]), sizeof(unsigned short));
        }

        SHA256_Final(hash_result, &sha256);

        // Convert the full hash to hexadecimal format
        char hex_hash[2 * SHA256_DIGEST_LENGTH + 1]; // +1 for null-terminator
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(hex_hash + 2 * i, "%02x", hash_result[i]);
        }
        ngx_memcpy(ja4->extension_hash, hex_hash, 2 * SHA256_DIGEST_LENGTH);

        // Convert the truncated hash to hexadecimal format
        char hex_hash_truncated[2 * 6 + 1]; // 6 bytes, 2 characters each = 12 characters plus null-terminator
        for (i = 0; i < 6; i++)
        {
            sprintf(hex_hash_truncated + 2 * i, "%02x", hash_result[i]);
        }
        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->extension_hash_truncated, hex_hash_truncated, 12);
        ja4->extension_hash_truncated[12] = '\0';
    }

    return NGX_OK;
}
