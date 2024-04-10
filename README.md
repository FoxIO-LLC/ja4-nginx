# JA4 Nginx

This fork of Nginx adds a small modification to the core of nginx to use in conjunction with the [JA4 module](https://github.com/FoxIO-LLC/ja4-nginx-module). That means, to use the JA4 module, you'll need to use this fork of Nginx when compiling. Additionally, this fork requires a [patched version of OpenSSL](https://github.com/FoxIO-LLC/ja4-openssl).

## Getting Started

To run the JA4 module, you'll first need to pull it into this repository. Then, you'll need to pull the OpenSSL fork into this repository. After that, you can build the software and run the server.

### Integrating the JA4 Module

Start by cloning the JA4 module into the root of this project.

`git clone git@github.com:FoxIO-LLC/ja4-nginx-module.git`

Now, the module code will be available when building nginx.

### Integrating the OpenSSL Fork

The Nginx patch required by the JA4 module requires an OpenSSL patch.
Clone it into the root of this project:

`git clone git@github.com:FoxIO-LLC/ja4-openssl.git`

### Build

If you are using the OpenSSL fork, you will need to build with the following command:

`./auto/configure --with-debug --with-compat --add-module=./ja4-nginx-module/src --with-http_ssl_module --with-openssl=$(pwd)/ja4-openssl --prefix=$(pwd)/nginx_local`

`make`

`make install`

NOTE:
When you make changes to the nginx code or the module code, you only need to run `make install` to rebuild the project.

### Run Server

Nginx servers can be optionally configured with a custom nginx.conf file. This instructs the server how to respond to requests across different ports and controls other global settings, like logging configurations. In `./nginx_utils`, there is a sample nginx.conf which returns the JA4 fingerprint variables in a text response. Additionally, you will need there are `server.crt` and `server.key` files which are necessary for SSL connections and thus necessary for generating JA4 fingerprints. There is a handy command in the YaMakefile to generate locally signed versions of these files.

After building the software, copy `./nginx_utils/nginx.conf` and your `server.crt` and `server.key` files to `./nginx_local/conf` and then run the server with the following command:

`sudo ./nginx_local/sbin/nginx -g "daemon off;"`

### Logging/Debugging

You can log data to `nginx_local/logs/error.log` like this:

`ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: |    cipher: 0x%04uxD -> %d", ja4->ciphers[i], ja4->ciphers[i]);`

### Parity with Nginx

Since we are building off of a stable branch, these steps shouldn't ever be required.

When updates come into Nginx, we need to update our fork. We can simply do these by adding nginx as a remote upstream repository:

`git remote add upstream git@github.com:nginx/nginx.git`

Then, merging updates with our main branch:

`git pull upstream branches/stable-1.24`
`git checkout ja4-nginx-1.24`
`git merge upstream/branches/stable-1.24`

### Creating a Patch

Because the JA4 module requires a small change to nginx core, we ship the module via GitHub releases along with a patch file. To create a patch file, make sure you have retrieved most recent nginx as specified in section: [Parity with Nginx](#parity-with-nginx). Then:

`(git diff upstream/branches/stable-1.24:src/event/ngx_event_openssl.c ./src/event/ngx_event_openssl.c && git diff upstream/branches/stable-1.24:src/event/ngx_event_openssl.h ./src/event/ngx_event_openssl.h && git diff upstream/branches/stable-1.24:src/http/modules/ngx_http_ssl_module.c ./src/http/modules/ngx_http_ssl_module.c)> ja4-nginx-module/patches/nginx.patch`

### Parity with OpenSSL

Since we are building off of a stable branch, these steps shouldn't ever be required.

The JA4 nginx module also requires a patch to the underlying OpenSSL library which must included when compiling Nginx.

We need to maintain an updated fork of OpenSSL. We can simply do these by adding OpenSSL as a remote upstream repository:

`ja4-openssl` should be cloned within this repository.

Then, add the official OpenSSL repository as a remote upstream repository:

`cd ja4-openssl`
`git remote add upstream git@github.com:openssl/openssl.git`

Then, merging updates with our master branch:

`git pull upstream openssl-3.2`
`git checkout ja4-openssl-3.2`
`git merge upstream/openssl-3.2`

### Creating a Patch for OpenSSL

Because the JA4 module requires a small change to OpenSSL, we ship the module via GitHub releases along with a patch file. To create a patch file, make sure you have pulled most recent changes from OpenSSL as specified in section: [Parity with OpenSSL](#parity-with-openssl). Then:

`(git diff upstream/openssl-3.2:ssl/ssl_lib.c ./ssl/ssl_lib.c && git diff upstream/openssl-3.2:include/openssl/ssl.h.in ./include/openssl/ssl.h.in) > ../ja4-nginx-module/patches/openssl.patch`

## Architecture

### Nginx Patch

File: `src/event/ngx_event_openssl.h`
Data Structure Modified: `ngx_ssl_connection_s`
Purpose: Adds some members to store data captured by TLS handshake for JA4 fingerprint.

File: `src/event/ngx_event_openssl.c`
Function Added: `ngx_SSL_client_features`
Purpose: Captures cipher suites and signature algorithms from the SSL handshake and stores them in the Nginx connection structure.

Function modified: `ngx_ssl_handshake`
Purpose: Does client hello callback to retrieve extensions. Calls `ngx_SSL_client_features` to capture Cipher suites and signature algorithms. Collected data is added to `ngx_ssl_connection_s` structure.

Function modified: `ngx_SSL_early_cb_fn`
Purpose: This callback function notably uses an OpenSSL API function we patched in: `SSL_client_hello_getall_extensions_present`. It collects the extensions present in the ClientHello packet and collected data is added to `ngx_ssl_connection_s` structure.

File: `http/modules/ngx_http_ssl_module.c`
Function Modified: `ngx_http_ssl_alpn_select`
Purpose: Stores the client's preferred ALPN value in the Nginx connection structure. Collected data is added to `ngx_ssl_connection_s` structure.

### OpenSSL Patch

Files: `ssl/ssl_lib.c` and `include/openssl/ssl.h.in`
Function Added: `SSL_client_hello_getall_extensions_present`
Purpose: Adds a new function to the OpenSSL library to retrieve all extensions present in the ClientHello packet.
