/*
    Apache 2.2/2.4 mod_myfixip -- Author: G.Grandes
    
    v0.1 - 2011.05.07, Init version (SSL)
    v0.2 - 2011.05.28, Mix version (SSL & Non-SSL)
    v0.3 - 2014.12.06, Support for PROXY protocol v1 (haproxy)
    v0.4 - 2014.12.06, Porting to Apache 2.4
    v0.5 - 2015.01.14, Backport to Apache 2.2 with dual support 2.2/2.4
                       Fix fragmented TCP frames in AWS-ELB
    
    = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
    In HTTP (no SSL): this will fix "useragent_ip" field if the request 
    contains an "X-Cluster-Client-Ip" header field, and the request came 
    directly from a one of the IP Addresses specified in the configuration 
    file (RewriteIPAllow directive).

    In HTTPS (SSL): this will fix "useragent_ip" field if any of:
    1) the connection buffer begins with "HELOxxxx" (there xxxx is IPv4 in 
       binary format -netorder-)
    2) buffer follow PROXY protocol v1

       - TCP/IPv4 :
         "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"
         => 5 + 1 + 4 + 1 + 15 + 1 + 15 + 1 + 5 + 1 + 5 + 2 = 56 chars

       - TCP/IPv6 :
         "PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
         => 5 + 1 + 4 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 104 chars

       - unknown connection (short form) :
         "PROXY UNKNOWN\r\n"
         => 5 + 1 + 7 + 2 = 15 chars

       - worst case (optional fields set to 0xff) :
         "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
         => 5 + 1 + 7 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 107 chars

       Complete Proxy-Protocol: 
         http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt

    The rewrite address of request is allowed from a one of the IP Addresses 
    specified in the configuration file (RewriteIPAllow directive).
    
    
    Usage:
    
    # Global
    <IfModule mod_myfixip.c>
      RewriteIPResetHeader off
      RewriteIPHookPortSSL 443
      RewriteIPAllow 192.168.0.0/16 127.0.0.1
    </IfModule>
    
    # VirtualHost
    <VirtualHost *:443>
      <IfModule mod_myfixip.c>
        RewriteIPResetHeader on
      </IfModule>
    </VirtualHost>
    
    To play with this module first compile it into a
    DSO file and install it into Apache's modules directory
    by running:
    
    $ apxs2 -c -i mod_myfixip.c

    = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
    http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

// References:
// http://ci.apache.org/projects/httpd/trunk/doxygen/
// http://apr.apache.org/docs/apr/1.5/
// http://httpd.apache.org/docs/2.4/developer/
// http://onlamp.com/pub/ct/38
// http://svn.apache.org/repos/asf/httpd/httpd/tags/2.4.0/modules/metadata/mod_remoteip.c
// http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-listener-config.html
// http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/enable-proxy-protocol.html
// http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
// http://blog.haproxy.com/haproxy/proxy-protocol/

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include "http_core.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MODULE_NAME "mod_myfixip"
#define MODULE_VERSION "0.5"

module AP_MODULE_DECLARE_DATA myfixip_module;

#define DEFAULT_PORT          443
#define PROXY                 "PROXY"
#define HELO                  "HELO"
#define TEST                  "TEST"
#define TEST_RES_OK           "OK" "\n"

#define NOTE_ORIGINAL_IP      "FIXIP_ORIGINAL_USERAGENT_IP"
#define NOTE_REWRITE_IP       "FIXIP_REWRITE_USERAGENT_IP"
#define NOTE_CLIENT_TRUST     "FIXIP_CLIENT_TRUSTED"

#ifndef HDR_USERAGENT_IP
#define HDR_USERAGENT_IP      "X-Cluster-Client-Ip" // FIXME: Do configurable name
#endif

//#define DEBUG
#define PROXY_MAX_LENGTH 107

// Apache 2.4 or 2.2
#if AP_SERVER_MINORVERSION_NUMBER > 3
#define _REMOTE_HOST    c->remote_host
#define _CLIENT_IP      c->client_ip
#define _CLIENT_ADDR    c->client_addr
#define _USERAGENT_IP   r->useragent_ip
#define _USERAGENT_ADDR r->useragent_addr
#else
#define _REMOTE_HOST    c->remote_host
#define _CLIENT_IP      c->remote_ip
#define _CLIENT_ADDR    c->remote_addr
#define _USERAGENT_IP   c->remote_ip
#define _USERAGENT_ADDR c->remote_addr
#endif

typedef struct
{
    apr_port_t port;
    apr_array_header_t *allows;
    int resetHeader;
} my_config;

typedef struct {
    apr_ipsubnet_t *ip;
} accesslist;

typedef struct
{
    int iter;
} my_ctx;

static const char *const myfixip_filter_name = "myfixip_filter_name";

/**
 * Create per-server configuration structure
 */
static void *create_config(apr_pool_t *p, server_rec *s)
{
    my_config *conf = apr_palloc(p, sizeof(my_config));

    conf->port = DEFAULT_PORT;
    conf->allows = apr_array_make(p, 1, sizeof(accesslist));
    conf->resetHeader = 0;

    return conf;
}

/**
 * Merge per-server configuration structure
 */
static void *merge_config(apr_pool_t *p, void *parent_server1_conf, void *add_server2_conf)
{
    my_config *merged_config = (my_config *) apr_pcalloc(p, sizeof(my_config));
    memcpy(merged_config, parent_server1_conf, sizeof(my_config));
    my_config *s1conf = (my_config *) parent_server1_conf;
    my_config *s2conf = (my_config *) add_server2_conf;

    //merged_config->port = (s1conf->port == s2conf->port) ? s1conf->port : s2conf->port;
    //merged_config->allows = (s1conf->allows == s2conf->allows) ? s1conf->allows : s2conf->allows;
    merged_config->resetHeader = (s1conf->resetHeader == s2conf->resetHeader) ? s1conf->resetHeader : s2conf->resetHeader;

    return (void *) merged_config;
}

/**
 * Parse the RewriteIPResetHeader directive
 */
static const char *reset_header_config_cmd(cmd_parms *parms, void *mconfig, int flag)
{
    my_config *conf = ap_get_module_config(parms->server->module_config, &myfixip_module);
    const char *err = ap_check_cmd_context (parms, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);

    if (err != NULL) {
        return err;
    }

    conf->resetHeader = flag ? TRUE : FALSE;
    return NULL;
}

/**
 * Parse the RewriteIPHookPortSSL directive
 */
static const char *port_config_cmd(cmd_parms *parms, void *mconfig, const char *arg)
{
    my_config *conf = ap_get_module_config(parms->server->module_config, &myfixip_module);
    const char *err = ap_check_cmd_context (parms, GLOBAL_ONLY);
    
    if (err != NULL) {
        return err;
    }
    
    unsigned long int port = strtol(arg, (char **) NULL, 10);

    if ((port > 65535) || (port < 1)) {
        return "Integer overflow or invalid number";
    }

    conf->port = port;
    return NULL;
}

/**
 * Parse the RewriteIPAllow directive
 */
static const char *allow_config_cmd(cmd_parms *cmd, void *dv, const char *where_c)
{
    my_config *d = ap_get_module_config(cmd->server->module_config, &myfixip_module);
    accesslist *a;
    char *where = apr_pstrdup(cmd->pool, where_c);
    char *s;
    char msgbuf[120];
    apr_status_t rv;

    a = (accesslist *) apr_array_push(d->allows);

    if ((s = ap_strchr(where, '/'))) {
        *s++ = '\0';
        rv = apr_ipsubnet_create(&a->ip, where, s, cmd->pool);
        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return "An IP address was expected";
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
    }
    else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->ip, where, NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
    }
    else { /* no slash, didn't look like an IP address => must be a host */
        return "An IP address was expected";
    }

    return NULL;
}

/**
 * Array describing structure of configuration directives
 */
static command_rec cmds[] = {
    AP_INIT_FLAG("RewriteIPResetHeader", reset_header_config_cmd, NULL, RSRC_CONF, "Reset HTTP-Header in this SSL vhost?"),
    AP_INIT_TAKE1("RewriteIPHookPortSSL", port_config_cmd, NULL, RSRC_CONF, "TCP Port where hack"),
    AP_INIT_ITERATE("RewriteIPAllow", allow_config_cmd, NULL, RSRC_CONF, "IP-address wildcards"),
    {NULL}
};

/**
 * Set up startup-time initialization
 */
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME " " MODULE_VERSION " started");
    return OK;
}

/**
 * Find remote_addr in ACL
 */
static int find_accesslist(apr_array_header_t *a, apr_sockaddr_t *remote_addr)
{
    accesslist *ap = (accesslist *) a->elts;
    int i;

    for (i = 0; i < a->nelts; ++i) {
        if (apr_ipsubnet_test(ap[i].ip, remote_addr)) {
            return 1;
        }
    }

    return 0;
}

/**
 * Check if client_ip is trusted
 */
static int check_trusted( conn_rec *c, my_config *conf )
{
    const char *trusted;

    trusted = apr_table_get( c->notes, NOTE_CLIENT_TRUST);
    if (trusted) return (trusted[0] == 'Y');

    // Find Access List & Permit/Deny rewrite IP of Client
    if (find_accesslist(conf->allows, _CLIENT_ADDR)) {
        apr_table_setn(c->notes, NOTE_CLIENT_TRUST, "Y");
        return 1;
    }

    apr_table_setn(c->notes, NOTE_CLIENT_TRUST, "N");
    return 0;
}

/**
 * Process Connection
 */
static int process_connection(conn_rec *c)
{
    my_config *conf = ap_get_module_config (c->base_server->module_config, &myfixip_module);
    
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::process_connection IP Connection from: %s to port=%d (1)", _CLIENT_IP, c->local_addr->port);
#endif

    if (c->local_addr->port != conf->port) {
        return DECLINED;
    }

    if (!check_trusted(c, conf)) { // Not Trusted
        return DECLINED;
    }

    my_ctx *cctx = apr_palloc(c->pool, sizeof(my_ctx));
    cctx->iter = 0;

    ap_add_input_filter(myfixip_filter_name, cctx, NULL, c);

    return DECLINED;
}

/**
 * Transform binary-network-address to human
 */
static const char *fromBinIPtoString(apr_pool_t *p, const char *binip)
{
    // Rewrite IP
    struct in_addr inp;
    memcpy((char *)&inp, binip, 4);
    char *str_ip = inet_ntoa(inp);
    if (inet_aton(str_ip, &inp) == 0) {
        return NULL;
    }
    return apr_pstrdup( p, str_ip );
}

/**
 * Save original UserAgent IP in connection note
 */
static void save_req_ip(request_rec *r)
{
    conn_rec *c = r->connection;

    const char *old_ip = apr_table_get(c->notes, NOTE_ORIGINAL_IP);
    if (!old_ip) {
        apr_table_set(c->notes, NOTE_ORIGINAL_IP, _USERAGENT_IP);
    }
}

/**
 * Rewrite UserAgent IP
 */
static void rewrite_req_ip(request_rec *r, const char *new_ip)
{
    conn_rec *c = r->connection;
    // Rewrite IP
    apr_sockaddr_t *temp_sa = _USERAGENT_ADDR;
    apr_sockaddr_info_get(&temp_sa, new_ip,
                                    APR_UNSPEC, temp_sa->port,
                                    APR_IPV4_ADDR_OK, c->pool);
    _USERAGENT_ADDR = temp_sa;
    apr_sockaddr_ip_get(&_USERAGENT_IP, _USERAGENT_ADDR);
    apr_sockaddr_ip_get(&_REMOTE_HOST, _USERAGENT_ADDR);
    //c->remote_host = NULL; // Force DNS re-resolution
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::rewrite_req_ip IP Connection from: %s [%s] to port=%d newip=%s (OK)", _CLIENT_IP, _USERAGENT_IP, c->local_addr->port, new_ip);
#endif
}

/**
 * Process input stream
 */
static apr_status_t helocon_filter_in(ap_filter_t *f, apr_bucket_brigade *b, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    conn_rec *c = f->c;
    my_ctx *ctx = f->ctx;
    const char *str = NULL;
    apr_size_t length = 0;
    apr_bucket *e = NULL, *d = NULL;

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in IP Connection from: %s to port=%d (1)", _CLIENT_IP, c->local_addr->port);
#endif

    // Fail quickly if the connection has already been aborted.
    if (c->aborted) {
        apr_brigade_cleanup(b);
        return APR_ECONNABORTED;
    }

    ap_get_brigade(f->next, b, mode, block, readbytes);
    e = APR_BRIGADE_FIRST(b);

    if (APR_BRIGADE_EMPTY(b)) {
        return APR_SUCCESS;
    }

    if (e->type == NULL) {
        return APR_SUCCESS;
    }

    if (ctx->iter) {
        return APR_SUCCESS;
    } else {
        ctx->iter = 1;
    }

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in IP Connection from: %s to port=%d (2)", _CLIENT_IP, c->local_addr->port);
#endif

    // Read first bucket (we need few bytes)
    apr_status_t s = apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
    if (s != APR_SUCCESS)
        return s;

    // TEST Command
    if (strncmp(TEST, str, 4) == 0) {
        apr_socket_t *csd = ap_get_module_config(c->conn_config, &core_module);

        length = strlen(TEST_RES_OK);
        apr_socket_send(csd, TEST_RES_OK, &length);
        apr_socket_shutdown(csd, APR_SHUTDOWN_WRITE);
        apr_socket_close(csd);

#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: CMD=TEST OK");
#endif

        // No need to check for SUCCESS, we did that above
        c->aborted = 1;
        return APR_ECONNABORTED;
    }
    // HELO Command
    if (strncmp(HELO, str, 4) == 0) {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: CMD=HELO OK");
#endif
        // delete HELO header
        apr_bucket_split(e, 8);
        d = e;
        e = APR_BUCKET_NEXT(e);
        APR_BUCKET_REMOVE(d);
        d = NULL;

        // REWRITE CLIENT IP
        const char *new_ip = fromBinIPtoString(c->pool, str+4);
        if (!new_ip) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in ERROR: HELO+IP invalid");
            return APR_SUCCESS;
        }

        apr_table_set(c->notes, NOTE_REWRITE_IP, new_ip);
        return APR_SUCCESS;
    }
    // PROXY Command
    if (strncmp(PROXY, str, 5) == 0) {
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: CMD=PROXY OK");
#endif
        // Read full header from buckets
        apr_uint32_t offset = 0;
        char buf[PROXY_MAX_LENGTH + 1]; // worst case
        while ((offset < PROXY_MAX_LENGTH) && (e != APR_BRIGADE_SENTINEL(b))) {
            apr_status_t s = apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
            if (s != APR_SUCCESS) {
                return s;
            }
            if ((offset + length) > PROXY_MAX_LENGTH) { // Overflow
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in ERROR: PROXY protocol header overflow from=%s to port=%d length=%d", _CLIENT_IP, c->local_addr->port, (length + offset));
                goto ABORT_CONN2;
            }
#ifdef DEBUG
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: Data read from: %s to port=%d (3) length=%d off=%d", _CLIENT_IP, c->local_addr->port, length, offset);
#endif
            char *end = memchr(str, '\r', length - 1);
            if (end) {
                length = end - str;
                length += 2;
                apr_bucket_split(e, length);
            }
            memcpy(buf + offset, str, length);
            offset += length;
            buf[offset] = 0;
#ifdef DEBUG
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: Data read from: %s to port=%d (4) length=%d newoff=%d (%s)", _CLIENT_IP, c->local_addr->port, length, offset, buf);
#endif
            d = e;
            e = APR_BUCKET_NEXT(e);
            APR_BUCKET_REMOVE(d);
            d = NULL;
            if (end) {
                break;
            }
        }

        char *end = buf + offset - 2;
        if ((end[0] != '\r') || (end[1] != '\n')) {
            goto ABORT_CONN;
        }
        end[0] = ' '; // for next split
        end[1] = 0;
#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: CMD=PROXY header=%s", buf);
#endif
        length = (end + 2 - buf);
        int size = length - 1;
        char *ptr = (char *) buf;
        int tok = 0;
        char *srcip = NULL, *dstip = NULL, *srcport = NULL, *dstport = NULL;
        while (ptr) {
            char *f = memchr(ptr, ' ', size);
            if (!f) {
                break;
            }
            *f = '\0';
#ifdef DEBUG
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in DEBUG: CMD=PROXY token=%s [%d]", ptr, tok);
#endif
            // PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535
            switch (tok) {
                case 0: // PROXY
                    break;
                case 2: // SRCIP
                    srcip = ptr;
                    break;
                case 3: // DSTIP
                    dstip = ptr;
                    break;
                case 4: // SRCPORT
                    srcport = ptr;
                    break;
                case 5: // DSTPORT
                    dstport = ptr;
                    break;
                case 1: // PROTO
                    if (strncmp("TCP", ptr, 3) == 0) {
                        if ((ptr[3] == '4') ||
                            (ptr[3] == '6')) {
                            break;
                        }
                    }
                default:
                    srcip = dstip = srcport = dstport = NULL;
                    goto ABORT_CONN;
            }
            size -= (f + 1 - ptr);
            ptr = f + 1;
            tok++;
        }
        if (!dstport) {
            goto ABORT_CONN;
        }
        apr_table_set(c->notes, NOTE_REWRITE_IP, srcip);
        return APR_SUCCESS;

    ABORT_CONN:
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::helocon_filter_in ERROR: PROXY protocol header invalid from=%s to port=%d", _CLIENT_IP, c->local_addr->port);
    ABORT_CONN2:
        c->aborted = 1;
        return APR_ECONNABORTED;
    }

    //ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME " DEBUG-ED!!");

    return APR_SUCCESS;
}

static int post_read_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    my_config *conf = ap_get_module_config (c->base_server->module_config, &myfixip_module);

    const char *new_ip = NULL;

    // Save original IP
    save_req_ip(r);

    new_ip = apr_table_get(c->notes, NOTE_REWRITE_IP);
    if (conf->resetHeader || new_ip || !check_trusted(c, conf)) {
        apr_table_unset(r->headers_in, HDR_USERAGENT_IP);
    }
    if (new_ip) {
        // Set Header
        apr_table_set(r->headers_in, HDR_USERAGENT_IP, new_ip);
    } else {
        // Get Header
        new_ip = apr_table_get(r->headers_in, HDR_USERAGENT_IP);
    }

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL, MODULE_NAME "::post_read_handler IP Connection from: %s [%s] to port=%d newip=%s (OK)", _CLIENT_IP, _USERAGENT_IP, c->local_addr->port, new_ip);
#endif
    if (new_ip && strcmp(_USERAGENT_IP, new_ip)) { // Change
        rewrite_req_ip(r, new_ip);
    }

    return DECLINED;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
}

static void register_hooks(apr_pool_t *p)
{
    /*
     * mod_ssl is AP_FTYPE_CONNECTION + 5 and mod_myfixip needs to
     * be called before mod_ssl.
     */
    ap_register_input_filter(myfixip_filter_name, helocon_filter_in, NULL, AP_FTYPE_CONNECTION + 9);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);    
    ap_hook_process_connection(process_connection, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_read_request(post_read_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA myfixip_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       // create per-dir config structures
    NULL,                       // merge  per-dir    config structures
    create_config,              // create per-server config structures
    merge_config,               // merge  per-server config structures
    cmds,                       // table of config file commands
    register_hooks              // register hooks
};
