#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>
#include <openssl/sha.h>
#include <stdint.h> // for uint8_t, uint16_t, etc.

typedef struct ngx_ssl_ja4_s
{
    const char *version; // TLS version

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz;       // Count of ciphers
    unsigned short *ciphers; // List of ciphers

    size_t extensions_sz;       // Count of extensions
    unsigned short *extensions; // List of extensions

    // For the entire ALPN extension value
    size_t alpn_sz;
    char *alpn_values;

    // For the first and last ALPN extension values
    char alpn_first_value;
    char alpn_last_value;

    char cipher_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char cipher_hash_truncated[13]; // 12 bytes * 2 characters/byte + 1 for '\0'

    char extension_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char extension_hash_truncated[13]; // 6 bytes * 2 characters/byte + 1 for '\0'
} ngx_ssl_ja4_t;

typedef struct ngx_ssl_ja4_l_s
{
    uint16_t distance_miles;                   // a whole number - max is in the thousands
    uint16_t handshake_roundtrip_microseconds; // a whole number - max is probably thousands
    uint8_t ttl;                               // time to live - a whole number - max is 255
    uint8_t hop_count;                         // a whole number - max is less than 255
} ngx_ssl_ja4_l_t;

int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);
int ngx_ssl_ja4_l(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_l_t *ja4_l);
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
void ngx_ssl_ja4_fp_string(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
void ngx_ssl_ja4_l_fp(ngx_pool_t *pool, ngx_ssl_ja4_l_t *ja4_l, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_l(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

/* http_json_log config preparation */
// adds a function that executes after configuraiton finishes..? not sure
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
// creates a module w/ a context/configuration? maybe?
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

// I think this function sets the http variable value
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
static ngx_int_t
ngx_http_ssl_ja4_string(ngx_http_request_t *r,
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

    // ngx_ssl_ja4_fp(r->pool, &ja4, &fp);
    // replace w/ function that assigns the string instead of the hashed version
    ngx_ssl_ja4_fp_string(r->pool, &ja4, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

// I think this function sets the http variable value
static ngx_int_t
ngx_http_ssl_ja4_l(ngx_http_request_t *r,
                   ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_l_t ja4_l;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_l(r->connection, r->pool, &ja4_l) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4_l_fp(r->pool, &ja4_l, &fp);

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
    {ngx_string("http_ssl_ja4_string"),
     NULL,
     ngx_http_ssl_ja4_string,
     0, 0, 0},
    {ngx_string("http_ssl_ja4_l"),
     NULL,
     ngx_http_ssl_ja4_l,
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
ngx_ssl_ja4_l_detail_print(ngx_pool_t *pool, ngx_ssl_ja4_l_t *ja4l)
{

    /* Distance in miles */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4_l: Distance in miles: %d",
                   ja4l->distance_miles);

    /* Time in microseconds */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4_l: Time in microseconds: %d",
                   ja4l->handshake_roundtrip_microseconds);

    /* TTL */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4_l: TTL: %d",
                   ja4l->ttl);

    /* Hop Count */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4_l: Hop Count: %d",
                   ja4l->hop_count);
}

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
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: ALPN Value: %d\n",
                   ja4->alpn_values);
}
#endif

void ngx_ssl_ja4_l_fp(ngx_pool_t *pool, ngx_ssl_ja4_l_t *ja4_l, ngx_str_t *out)
{
    // Calculate the maximum lengths of the variables
    const size_t max_time_len = 5;      // uint16_t max is 65535, which is 5 characters
    const size_t max_ttl_len = 3;       // uint8_t max is 255, which is 3 characters
    const size_t max_hop_count_len = 3; // uint8_t max is 255, which is 3 characters

    // init stuff
    double propagation_delay_factor; // Declare the variable to store the propagation delay factor
    uint8_t initial_ttl;

    // Include space for 2 underscores and the null-terminator
    size_t total_len = max_time_len + max_ttl_len + max_hop_count_len + 2 + 1;

    // Allocate memory
    out->data = ngx_palloc(pool, total_len);
    if (out->data == NULL)
    {
        // Handle memory allocation failure
        return;
    }

    // All routes on the Internet have less than 64 hops.
    // Therefore if the TTL value is within 65-128, the estimated initial TTL is 128.
    // If the TTL value is 0-64, the estimated initial TTL is 64.
    // And if the TTL is >128 then the estimated initial TTL is 255.
    if (ja4_l->ttl > 128)
    {
        initial_ttl = 255;
    }
    else if (ja4_l->ttl > 64)
    {
        initial_ttl = 128;
    }
    else
    {
        initial_ttl = 64;
    }

    ja4_l->hop_count = initial_ttl - ja4_l->ttl;

    if (ja4_l->hop_count <= 21)
    {
        propagation_delay_factor = 1.5;
    }
    else if (ja4_l->hop_count == 22)
    {
        propagation_delay_factor = 1.6;
    }
    else if (ja4_l->hop_count == 23)
    {
        propagation_delay_factor = 1.7;
    }
    else if (ja4_l->hop_count == 24)
    {
        propagation_delay_factor = 1.8;
    }
    else if (ja4_l->hop_count == 25)
    {
        propagation_delay_factor = 1.9;
    }
    else if (ja4_l->hop_count >= 26)
    {
        propagation_delay_factor = 2.0;
    }

    // This is effectively
    // time message takes to get from client to server * miles light travels per microsecond adjusted with propagation delay factor
    ja4_l->distance_miles = (ja4_l->handshake_roundtrip_microseconds / 2) * 0.13 / propagation_delay_factor;

    // Create the concatenated string
    int written = snprintf((char *)out->data, total_len, "%u_%u_%u",
                           ja4_l->handshake_roundtrip_microseconds / 2,
                           ja4_l->ttl,
                           ja4_l->hop_count);

    if (written < 0)
    {
        // Handle snprintf failure
        return;
    }

    out->len = (size_t)written;

#if (NGX_DEBUG)
    ngx_ssl_ja4_l_detail_print(pool, ja4_l);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4_l: fp: [%V]\n", out);
#endif
}

// this function calculates the ja4 fingerprint but it doesn't has extensions and ciphers
// instead, it just comma separates them
void ngx_ssl_ja4_fp_string(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // Estimate memory requirements for output
    size_t len = 1                        // for q/t
                 + 2                      // TLS version
                 + 1                      // d/i for SNI
                 + 2                      // count of ciphers
                 + 2                      // count of extensions

                 + ja4->ciphers_sz * 6    // ciphers and commas
                 + ja4->extensions_sz * 6  // extensions and commas
                 + 2                      // first and last characters of ALPN
                 + 4;                     // separators

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }

    size_t cur = 0;

    // t for TCP
    out->data[cur++] = 't';

    // 2 character TLS version
    memcpy(out->data + cur, ja4->version, 2);
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    ngx_snprintf(out->data + cur, 3, "%02zu", ja4->ciphers_sz);
    cur += 2;
    // 2 character count of extensions
    ngx_snprintf(out->data + cur, 3, "%02zu", ja4->extensions_sz);
    cur += 2;

    out->data[cur++] = ja4->alpn_first_value;
    out->data[cur++] = ja4->alpn_last_value;

    // Separator
    out->data[cur++] = '_';

    // Ciphers
    // if (ja4->ciphers_sz > 0)
    // {
    //     memcpy(out->data + cur, ja4->ciphers, ja4->ciphers_sz);
    //     cur += ja4->ciphers_sz;
    // }

    // add ciphers
    size_t i;
    for (i = 0; i < ja4->ciphers_sz; ++i)
    {
        // ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
        //                pool->log, 0, "ssl_ja4: |    strextension: 0x%04uxD -> %d",
        //                ja4->extensions[i],
        //                ja4->extensions[i]);

        // convert the cipher hex to a string
        // cipher = cipher[i]
        // convert cipher to string
        // add cipher to out->data
        // add comma to out->data

        // memcpy(out->data + cur, ja4->ciphers[i], 2);
        // int cipher_value = 34; // Example cipher value with two digits
        int n = ngx_snprintf(out->data + cur, 6, "%05d,", ja4->ciphers[i]) - out->data - cur;
        cur += n;
    }

    if (ja4->ciphers_sz > 0)
    {
        cur--; // Remove the trailing comma
    }

    // Separator
    out->data[cur++] = '_';
    // out->data[cur++] = '_';

    // ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: before extensions: fp_string: [%V]\n", out);

    // add extensions
    size_t j;
    for (j = 0; j < ja4->extensions_sz; ++j)
    {
        // ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
        //                pool->log, 0, "ssl_ja4: |    strextension: 0x%04uxD -> %d",
        //                ja4->extensions[i],
        //                ja4->extensions[i]);

        // convert the extension hex to a string
        // extension = extension[i]
        // convert extension to string
        // add extension to out->data
        // add comma to out->data

        // memcpy(out->data + cur, ja4->extensions[i], 2);
        // int extension_value = 34; // Example extension value with two digits
        int n = ngx_snprintf(out->data + cur, 6, "%05d,", ja4->extensions[j]) - out->data - cur;
        cur += n;
    }

    if (ja4->extensions_sz > 0)
    {
        cur--; // Remove the trailing comma
    }

    out->len = cur;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp_string: [%V]\n", out);
#endif
}

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
    out->data[cur++] = ja4->has_sni;
    // 2 character count of ciphers
    ngx_snprintf(out->data + cur, 3, "%02zu", ja4->ciphers_sz);
    cur += 2;
    // 2 character count of extensions
    ngx_snprintf(out->data + cur, 3, "%02zu", ja4->extensions_sz);
    cur += 2;

    out->data[cur++] = ja4->alpn_first_value;
    out->data[cur++] = ja4->alpn_last_value;

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
// this function sets stuff on the ja4_l struct so the fingerprint can easily, and clearly be formed in a separate function
int ngx_ssl_ja4_l(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_l_t *ja4_l)
{

    SSL *ssl;

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

    // transfer ssl connection variables to the ja4_l struct
    ja4_l->handshake_roundtrip_microseconds = c->ssl->handshake_roundtrip_microseconds;
    ja4_l->ttl = c->ssl->ttl;

    return NGX_OK;
}

// this function sets stuff on the ja4 struct so the fingerprint can easily, and clearly be formed in a separate function
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

    // 3. Fetch the ALPN value:
    // the ALPN value could be many things according to spec: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    // for example "http/1.1" or "sip/2"
    // the fingerprint needs the first and last characters
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

        // first value
        ja4->alpn_first_value = ja4->alpn_values[0];
        // last value
        ja4->alpn_last_value = ja4->alpn_values[ja4->alpn_sz - 1];
    }
    else
    {
        ja4->alpn_sz = 0;
        ja4->alpn_values = NULL;

        // first value, just a zero
        ja4->alpn_first_value = '0';
        // last value, just a zero
        ja4->alpn_last_value = '0';
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
