/* libhttpd.h - defines for libhttpd
**
** Copyright � 1995,1998,1999,2000,2001 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#ifndef _LIBHTTPD_H_
#define _LIBHTTPD_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_NETINET_SCTP_H
#define USE_SCTP
#endif
#define USE_IPV6



/* A few convenient defines. */

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
/* constant new to allocate arrays whose size is not reallocated */
#define CNEW(t,n) ((t*) calloc( (n), sizeof(t) ))

/* memory allocation and reallocation */
#define NEW(t,n) ((t*) malloc( sizeof(t) * (n) ))
#define RENEW(o,t,n) ((t*) realloc( (void*) o, sizeof(t) * (n) ))


/* The httpd structs. */

/* A multi-family sockaddr. */
typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
#ifdef HAVE_SOCKADDR_IN6
    struct sockaddr_in6 sa_in6;
#endif /* HAVE_SOCKADDR_IN6 */
#ifdef HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage sa_stor;
#endif /* HAVE_SOCKADDR_STORAGE */
    } httpd_sockaddr;


typedef struct {
    char* cli_pattern;	/* pattern, see also: match() */
    char* cli_path;	/* CGI-Command-Language-Interpreter, absolute path */
    } httpd_cgicli_entry;

typedef struct {
    int cnt_cgicli;	/* counter of elements in cgicli_tab */
    int max_cgicli;	/* max. elements in cgicli_tab[] */
    httpd_cgicli_entry cgicli_tab[1];
    } httpd_cgicli_vrec;

/* A server. */
typedef struct {
    char* binding_hostname;
    char* server_hostname;
    int port;
    char* cgi_pattern;
    httpd_cgicli_vrec* cgicli_vrec;
    char* charset;
    int   max_age;
    char* def_mime_type;
    int   def_mime_type_len;
    char* def_mime_typeb;
    int   def_mime_typeb_len;
    char* cwd;
    size_t cwd_len;
    int listen4_fd, listen6_fd;
#ifdef USE_SCTP
    int listensctp_fd;
#endif
    int no_log;
    FILE* logfp;
    int no_symlink;
    int vhost;
    int global_passwd;
    char* url_pattern;
    char* local_pattern;
    int no_empty_referers;
    int do_generate_indexes;
    int do_keepalive_conns;
    time_t nowtime;
    } httpd_server;

/* A connection. ALLOC=allocated memory */
typedef struct {
    int initialized;
    httpd_server* hs;
    httpd_sockaddr client_addr;
    char* read_buf;		/* ALLOC */
    int read_size;
    int read_idx;
    int checked_idx;
    int checked_state;
    int method;
    int status;
    int allowed_methods;
    off_t bytes_to_send;
    off_t bytes_sent;
    char* encodedurl;
    char* decodedurl;		/* ALLOC */
    char* protocol;
    int   protocol_len;
    int   encodedurl_len;
    int   decodedurl_len;
    char* origfilename;		/* ALLOC */
    char* expnfilename;		/* ALLOC */
    char* encodings;		/* ALLOC */
    int   encodings_len;
    int   origfn_len;
    int   expnfn_len;
    char* pathinfo;		/* ALLOC */
    char* query;		/* ALLOC */
    char* referer;
    char* useragent;
#ifdef EXECUTE_CGI
    char* accept;		/* ALLOC */
    char* accepte;		/* ALLOC */
    char* acceptl;
#endif /* EXECUTE_CGI */
    char* cookie;
    char* contenttype;
    char* reqhost;		/* ALLOC */
    char* hdrhost;
    char* hostdir;		/* ALLOC */
#ifdef AUTH_FILE
    char* authorization;
    char* remoteuser;		/* ALLOC */
#endif /* AUTH_FILE */
    char* response;		/* ALLOC */
    int maxdecodedurl, maxorigfilename, maxexpnfilename, maxencodings,
	maxpathinfo, maxquery,
#ifdef EXECUTE_CGI
	maxaccept, maxaccepte,
#endif /* EXECUTE_CGI */
	maxreqhost, maxhostdir,
#ifdef AUTH_FILE
	maxremoteuser,
#endif /* AUTH_FILE */
	maxresponse;
#ifdef TILDE_MAP_2
    char* altdir;		/* ALLOC */
    int maxaltdir;
#endif /* TILDE_MAP_2 */
    int responselen;
    time_t if_modified_since, range_if;
    off_t contentlength;
    char* type;		/* not malloc()ed */
    int   type_len;
    char* hostname;	/* not malloc()ed */
    int mime_flag;
    int one_one;	/* HTTP/1.1 or better */
    int got_range;
    int tildemapped;	/* this connection got tilde-mapped */
    off_t init_byte_loc, end_byte_loc;
    int keep_alive_tmo;
    int do_keep_alive;	/* 0/1 */
    int should_linger;	/* 0/1 */
    struct stat sb;
    int conn_fd;
#ifdef USE_SCTP
    int is_sctp;
    unsigned int no_i_streams;
    unsigned int no_o_streams;
    size_t send_at_once_limit;
    int use_eeor;
#endif
    int file_fd;
    char* file_address;
#ifdef USE_LAYOUT
/* Layout vars per each connection */
    int layout;
    int lheaderfile_len, lfooterfile_len;
#endif /* USE_LAYOUT */
    } httpd_conn;

/* Methods (values must be numbered sequentially). */
#define METHOD_UNKNOWN   0	/* must be 0 */
    /* supported methods */
#define METHOD_GET       1
#define METHOD_HEAD      2
#define METHOD_POST      3
   /* unsupported methods */
#define METHOD_OPTIONS   4
#define METHOD_PUT       5
#define METHOD_DELETE    6
#define METHOD_TRACE     7
#define METHOD_CONNECT   8

#define NR_METHODS       9

/* Conversion from a valid method id. (!= METHOD_UNKNOWN) to method bit */
#define METHOD_ID2BIT(id)	( 1 << ( (id) - 1 ) )

/* States for checked_state. */
#define CHST_FIRSTCRLF	0
#define CHST_FIRSTWORD	1
#define CHST_FIRSTWS	2
#define CHST_SECONDWORD	3
#define CHST_SECONDWS	4
#define CHST_THIRDWORD	5
#define CHST_THIRDWS	6
#define CHST_LINE	7
#define CHST_LF		8
#define CHST_CR		9
#define CHST_CRLF	10
#define CHST_CRLFCR	11
#define CHST_BOGUS	12

/* Mime Types (they must NOT contain: charset=%s) */
#define MIME_TYPE_TEXT_HTML	"text/html"

/* Allocate a CGI-CLI pattern table.
*/
extern httpd_cgicli_vrec* httpd_alloc_cgicli_vrec( void );

/* Free a CGI-CLI pattern table.
*/
extern void httpd_free_cgicli_vrec( httpd_cgicli_vrec* pvrec );

/* Add a CGI-CLI association (pattern - CGI-CLI path) to pattern table.
*/
extern int httpd_add_cgicli_entry( httpd_cgicli_vrec* pvrec,
				char* clipattern, char *clipath );

/* Initializes.  Does the socket(), bind(), and listen().   Returns an
** httpd_server* which includes a socket fd that you can select() on.
** Return (httpd_server*) 0 on error.
*/
extern httpd_server* httpd_initialize(
    char* hostname, httpd_sockaddr* sa4P, httpd_sockaddr* sa6P, int port,
    char* cgi_pattern, httpd_cgicli_vrec* cgicli_vrec,
    char* charset, int max_age, char* cwd, int no_log, FILE* logfp,
    int no_symlink, int vhost, int global_passwd, char* url_pattern,
    char* local_pattern, int no_empty_referers, int do_generate_indexes,
    int do_keepalive_conns, int conn_SO_RCVBUF, int conn_SO_SNDBUF );

/* Change the log file. */
extern void httpd_set_logfp( httpd_server* hs, FILE* logfp );

/* Flush the log file. */
extern void httpd_flush_logfp( httpd_server* hs );

/* Call to shut down. */
extern void httpd_terminate( httpd_server* hs );

/* Call to unlisten server sockets. */
extern void httpd_unlisten( httpd_server* hs );

/* When a listen fd is ready to read, call this.  It does the accept() and
** returns an httpd_conn* which includes the fd to read the request from and
** write the response to.  Returns an indication of whether the accept()
** failed, succeeded, or if there were no more connections to accept.
**
** In order to minimize malloc()s, the caller passes in the httpd_conn.
** The caller is also responsible for setting initialized to zero before the
** first call using each different httpd_conn.
*/
extern int httpd_get_conn( httpd_server* hs, int listen_fd, httpd_conn* hc, int is_sctp );
//extern int httpd_get_conn( httpd_server* hs, int listen_fd, httpd_conn* hc );
#define GC_OK      0
#define GC_NO_MORE 1
#define GC_ABORT   2
#define GC_FAIL    4

/* Resets fields in hc->* before headers of first request
** of a connection are read.
*/
extern int httpd_request_reset( httpd_conn* hc );

/* Resets fields in hc->* before headers, of a non first request
** (when keep alive is enabled) are read.
** Besides this it move unread header contents (pipelined request)
** in front of the input buffer.
*/
extern int httpd_request_reset2( httpd_conn* hc );

/* Checks whether the data in hc->read_buf constitutes a complete request
** yet.  The caller reads data into hc->read_buf[hc->read_idx] and advances
** hc->read_idx.  This routine checks what has been read so far, using
** hc->checked_idx and hc->checked_state to keep track, and returns an
** indication of whether there is no complete request yet, there is a
** complete request, or there won't be a valid request due to a syntax error.
*/
extern int httpd_got_request( httpd_conn* hc );
#define GR_NO_REQUEST		0
#define GR_GOT_REQUEST		1
#define GR_BAD_REQUEST_CRLF	2
#define GR_BAD_REQUEST_CRLF2	3
#define GR_BAD_REQUEST		4

/* Verify whether there is another request already read into read_buffer.
**
** Returns 1 if yes, 0 if no.
*/
extern int httpd_is_next_request( httpd_conn* hc );

/* Parses the request in hc->read_buf.  Fills in lots of fields in hc,
** like the URL and the various headers.
**
** Returns -1 on error.
*/
extern int httpd_parse_request( httpd_conn* hc );

/* Starts sending data back to the client.  In some cases (directories,
** CGI programs), finishes sending by itself - in those cases, hc->file_fd
** is < 0.  If there is more data to be sent, then hc->file_fd is a file
** descriptor for the file to send.  If you don't have a current timeval
** handy just pass in 0.
** You have to pass the current number of active connections (numconn)
** the max. number of connections (maxconn) and
** 0 or the max. size allowed to a file in order to keep a connection alive.
**
** Returns -1 on error.
*/
extern int httpd_start_request( httpd_conn* hc, struct timeval* nowP,
			int numconn, int maxconn, int MaxKeepAliveFileSize );

/* Actually clears any buffered response text */
extern void httpd_clear_response( httpd_conn* hc );

/* Actually sends any buffered response text in blocking / delay mode */
extern void httpd_write_blk_response( httpd_conn* hc );

/* Call this to complete a HTTP reply without closing a connection;
** it logs the request and eventually unmaps replied content.
*/
extern void httpd_complete_request( httpd_conn* hc, struct timeval* nowP,
					int logit );
#define CR_NO_LOGIT	0
#define CR_DO_LOGIT	1

/* Call this to close down only output (write) stream of a connection.
** Useful to speed up connection close before lingering
** waiting to receive EOF from client.
*/
extern void httpd_close_conn_wr( httpd_conn* hc );

/* Call this to close down a connection and free the data.  A fine point,
** if you fork() with a connection open you should still call this in the
** parent process - the connection will stay open in the child.
** If you don't have a current timeval handy just pass in 0.
*/
extern void httpd_close_conn( httpd_conn* hc, struct timeval* nowP );

/* Call this to de-initialize a connection struct and *really* free the
** mallocced strings.
*/
extern void httpd_destroy_conn( httpd_conn* hc );

/* Translate a HTTP error status to a default error title (en). */
extern char* httpd_err_title( int status );

/* Translate a HTTP error status to a default error title length. */
extern int   httpd_err_titlelen( int status );

/* Translate a HTTP error status to a default error form (en). */
extern char* httpd_err_form( int status );

/* Send an error message back to the client. */
extern void httpd_send_err(
	httpd_conn* hc, int status, char* title, int titlelen,
	char* extraheads, char* form, const char* arg );

/* Generate a string representation of a method number. */
extern const char* httpd_method_str( int method );

/* Given method string, returns method id. (including METHOD_UNKNOWN). */
extern int httpd_method_id( char* method_str );

/* Reallocate a string. */
extern void httpd_realloc_str( char** strP, int* maxsizeP, int size );

/* Format a network socket to a string representation. */
extern char* httpd_ntoa( httpd_sockaddr* saP );

/* options */

#define SOPT_OFF  0	/* set option OFF */
#define SOPT_ON   1	/* set option ON */
#define SOPT_MAX  2	/* max. number of SOPT values */

/* Get NDELAY / NONBLOCK mode from a socket (SOPT_ON|SOPT_OFF). */
extern int  httpd_get_nonblock( int fd, int *ponoff );

/* Set NDELAY / NONBLOCK mode on a socket (SOPT_ON|SOPT_OFF). */
extern int  httpd_set_nonblock( int fd, int onoff );

/* Get NO-NAGLE mode (SOPT_ON|SOPT_OFF) */
extern int httpd_get_nonagle( int fd, int *ponoff );

/* Set NO-NAGLE mode (SOPT_ON|SOPT_OFF) */
extern int httpd_set_nonagle( int fd, int onoff );

/* Get CORK mode (NAGLE with infinite timeout) */
extern int httpd_get_cork( int fd, int *ponoff );

/* Set CORK mode (to not output partial TCP/IP segments) */
extern int httpd_set_cork( int fd, int onoff );

/* return a string about type of available sendfile(). */
extern const char*
	httpd_typeof_sendfile( void );

/* Get sendfile max. block size */
extern size_t httpd_get_sf_blksize( void );

/* Set sendfile max. block size */
extern size_t httpd_set_sf_blksize( size_t sf_blk_size );

/* send a file to a socket */
extern ssize_t
	httpd_sendfile( int fdout, int fdin, off_t offset, size_t bytes );

/* Generate debugging statistics syslog message. */
extern void httpd_logstats( long secs );

#endif /* _LIBHTTPD_H_ */
