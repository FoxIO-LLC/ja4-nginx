# JA4 Nginx

This fork of Nginx adds a small modification to the core of nginx to use in conjunction with the [JA4 module](https://github.com/FoxIO-LLC/ja4-plus-nginx). That means, to use the JA4 module, you'll need to use this fork of Nginx when compiling.

## Developer Guide

For those working on the JA4 Nginx module, this guide will help you get started.

### Integrating the JA4 Module

To work with the JA4 module with this fork of Nginx, start by cloning the JA4 module into the root of this project.

`git clone git@github.com:FoxIO-LLC/ja4-nginx-module.git`

Now, the module code will be available when building nginx.

### Build

The following commands can be used to build the project (sudo may be required):

`./auto/configure --with-debug --with-compat --add-module=./ja4-nginx-module/src --with-http_ssl_module --prefix=$(pwd)/nginx_local`

`make`

When you make changes to the code and want to rebuild, only the following command is required:

`make install`

#### Build with OpenSSL Fork

If you are using the OpenSSL fork, you will need to build with the following command:

`./auto/configure --with-debug --with-compat --add-module=./ja4-nginx-module/src --with-http_ssl_module --with-openssl=$(pwd)/ja4-openssl --prefix=$(pwd)/nginx_local`

### Run Server

Nginx servers can be optionally configured with a custom nginx.conf file. This instructs the server how to responds to requests across different ports and controls other global settings. In `./nginx_utils`, there is a sample nginx.conf which returns the necessary JA4 fingerprint variables in a text response. Additionally, you will need there are `server.crt` and `server.key` files which are necessary for SSL connections and thus necessary for generating JA4 fingerprints. There is a handy command in the YaMakefile to generate locally signed versions of these files.

After building the software, copy `./nginx_utils/nginx.conf` and your `server.crt` and `server.key` files to `./nginx_local/conf` and then run the server with the following command:

`sudo ./nginx_local/sbin/nginx -g "daemon off;"`

### Logging/Debugging

You can log data to `nginx_local/logs/error.log` like this:

`ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: |    cipher: 0x%04uxD -> %d", ja4->ciphers[i], ja4->ciphers[i]);`

### Parity with Nginx

When updates come into Nginx, we need to update our fork. We can simply do these by adding nginx as a remote upstream repository:

`git remote add upstream git@github.com:nginx/nginx.git`

Then, merging updates with our main branch:

`git pull upstream master`
`git checkout main`
`git merge upstream/master`

### Creating a Patch

Because the JA4 module requires a small change to nginx core, we ship the module via GitHub releases along with a patch file. To create a patch file, make sure you have retrieved most recent nginx as specified in section: [Parity with Nginx](#parity-with-nginx). Then:

`(git diff upstream/master:src/event/ngx_event_openssl.c ./src/event/ngx_event_openssl.c && git diff upstream/master:src/event/ngx_event_openssl.h ./src/event/ngx_event_openssl.h && git diff upstream/master:src/http/modules/ngx_http_ssl_module.c ./src/http/modules/ngx_http_ssl_module.c)> ja4-nginx-module/patches/nginx.patch`

### Parity with OpenSSL

The JA4 nginx module also requires a patch to the underlying OpenSSL library which must included when compiling Nginx.

We need to maintain an updated fork of OpenSSL. We can simply do these by adding OpenSSL as a remote upstream repository:

`ja4-openssl` should be cloned within this repository.

Then, add the official OpenSSL repository as a remote upstream repository:

`cd ../ja4-openssl`
`git remote add upstream git@github.com:openssl/openssl.git`

Then, merging updates with our master branch:

`git pull upstream master`
`git checkout master`
`git merge upstream/master`

### Creating a Patch for OpenSSL

Because the JA4 module requires a small change to OpenSSL, we ship the module via GitHub releases along with a patch file. To create a patch file, make sure you have retrieved most recent OpenSSL as specified in section: [Parity with OpenSSL](#parity-with-openssl). Then:

`(git diff upstream/master:ssl/ssl_lib.c ./ssl/ssl_lib.c && git diff upstream/master:include/openssl/ssl.h.in ./include/openssl/ssl.h.in) > ../ja4-nginx-module/patches/openssl.patch`