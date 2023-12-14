# Darksail Nginx

This is a custom patched version of Nginx that adds runtime variables: `http_ssl_ja4`, `http_ssl_ja4_l` additionally string versions of ja4 `http_ssl_ja4_string`.

## JA4

JA4 is calculated according to the following attributes: TODO

## Configure with QUIC

The configuration parameter --with-http_v3_module will enable QUIC. However, since we still rely on OpenSSL, we are vulnerable to replay attacks.

## Run QUIC with Docker

Simply run `docker-compose up` in the root directory of this repository.

## Running and Compiling

First, the project must be set up with settings you desire.

`./auto/configure --with-debug --with-compat --add-module=./module --with-http_ssl_module --prefix=$(pwd)/nginx_local`

Then, the project can be compiled with `make` and installed with `make install`.

### Server Configuration

In `nginx_utils`, drop the site.conf file into `nginx_local/`

Then, you can start the server with `sudo ./nginx_local/sbin/nginx -g "daemon off;"`.

## Debugging

We have a few debugging print commands in our module like:

`ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: |    cipher: 0x%04uxD -> %d", ja4->ciphers[i], ja4->ciphers[i]);`

This produces logged output in `nginx_local/logs/error.log`

## Shipping

Most importantly, this repository expects the project darksail-web to sit beside it. The `copy-utils` command in the YaMakefile assumes this.

1. Make sure you have your changes inside branch `darksail-mod` and that is the checked out branch
2. `make -f YaMakefile create-patch`
3. `make -f YaMakefile copy-utils`
4. Go to darksail-web repo and commit the changes,

## lo

[JA3 Fullstring: 771,10794-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,19018-13-45-65281-18-51-35-23-10-43-16-5-17513-27-65037-11-47802-41,43690-29-23-24,0]
