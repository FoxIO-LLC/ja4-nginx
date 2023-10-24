# Darksail Nginx

This is a custom patched version of Nginx that adds runtime variables: `http_ssl_ja4`, `http_ssl_ja4_l` additionally string versions of ja4 `http_ssl_ja4_string`.

## JA4

JA4 is calculated according to the following attributes:

## Running and Compiling

First, the project must be set up with settings you desire.

`./auto/configure --with-debug --with-compat --add-module=./module --with-http_ssl_module --prefix=$(pwd)/nginx_local`

Then, the project can be compiled with `make` and installed with `make install`.

Then, you can start the server with `sudo ./nginx_local/sbin/nginx -g "daemon off;"`.

## Shipping

Most importantly, this repository expects the project darksail-web to sit beside it. The `copy-utils` command in the YaMakefile assumes this.

1. Make sure you have your changes inside branch `darksail-mod` and that is the checked out branch
2. `make -f YaMakefile create-patch`
3. `make -f YaMakefile copy-utils`
4. Go to darksail-web repo and commit the changes,
