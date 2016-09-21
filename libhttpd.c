/* libhttpd.c - HTTP protocol library
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


#include "config.h"
#include "version.h"

#ifdef SHOW_SERVER_VERSION
#define EXPOSED_SERVER_SOFTWARE SERVER_SOFTWARE
#else /* SHOW_SERVER_VERSION */
#define EXPOSED_SERVER_SOFTWARE SERVER_NAME
#endif /* SHOW_SERVER_VERSION */

#ifdef __FreeBSD__
#define _WITH_DPRINTF
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif /* HAVE_MEMORY_H */
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdarg.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif


#ifdef HAVE_OSRELDATE_H
#include <osreldate.h>
#endif /* HAVE_OSRELDATE_H */

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#if defined(HAVE_BSD_SENDFILE)
#include <sys/uio.h>
#elif defined(HAVE_LINUX_SENDFILE)
#include <netinet/tcp.h>
#include <sys/sendfile.h>
#elif defined(HAVE_SOLARIS_SENDFILE) || defined(HAVE_SOLARIS_SENDFILEV)
#include <sys/sendfile.h>
#endif

#ifdef AUTH_FILE
extern char* crypt( const char* key, const char* setting );
#endif

#include "libhttpd.h"
#include "mmc.h"
#include "timers.h"
#include "match.h"
#include "tdate_parse.h"

#ifdef __CYGWIN__
#define timezone _timezone
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef	SHUT_WR
#define	SHUT_WR	1			/* for shutdown(2) */
#endif

#ifndef FD_CLOEXEC
#define FD_CLOEXEC	1		/* fcntl(2): close-on-exec bit */
#endif /* FD_CLOEXEC */

#ifndef O_NONBLOCK
#define O_NONBLOCK	O_NDELAY	/* fcntl(2): non-blocking mode */
#endif

#ifdef ALLOW_ACCESS_GRP
#define S_IRACC		S_IRGRP
#define S_IWACC		S_IWGRP
#define S_IXACC		S_IXGRP
#else
#define S_IRACC		S_IROTH
#define S_IWACC		S_IWOTH
#define S_IXACC		S_IXOTH
#endif

/* HTTP, special characters (separators or header line terminators) */
#define CHR_TAB		'\t'
#define CHR_LF		'\n'
#define CHR_CR		'\r'
#define CHR_BLANK	' '
#define CHR_COMMA	','

/* HTTP, token separators */
#define HTTP_BTAB_STR	" \t"
#define HTTP_BTAB_LEN	2
#define HTTP_BTC_STR	" ,\t"
#define HTTP_BTC_LEN	3
#define HTTP_BTLFCR_STR	" \t\n\r"
#define HTTP_BTLFCR_LEN	4

/* HTTP, header line terminators */
#define HTTP_LF_STR	"\n"
#define HTTP_LF_LEN	1
#define HTTP_CRLF_STR	"\r\n"
#define HTTP_CRLF_LEN	2

#ifdef notdef
#define NO_MYSNP	1	/* NO my_snprintf() */
#define NO_TMF		1	/* NO time conversion in fast mode */
#define SMF_DEBUG	1	/* send mime fast in debug mode */
#endif

/* Forwards. */
#ifdef EXECUTE_CHILD
static void child_reaper( ClientData client_data, struct timeval* nowP );
static int  do_reap( void );
static void do_cond_reap( void );
#endif /* EXECUTE_CHILD */

#ifdef EXECUTE_CGICLI
static httpd_cgicli_vrec* httpd_dup_cgicli_vrec( httpd_cgicli_vrec* pvrec );
#endif /* EXECUTE_CGICLI */
static void check_options( void );
static void free_httpd_server( httpd_server* hs );
static int initialize_listen_socket( httpd_sockaddr* saP,
				int conn_SO_RCVBUF, int conn_SO_SNDBUF );
#ifdef USE_SCTP
static int initialize_listen_sctp_socket( httpd_sockaddr* sa4P, httpd_sockaddr* sa6P );
#endif

/* #define NO_OVL_STRCPY	1 */
#ifndef NO_OVL_STRCPY
static char *ovl_strcpy( char *dst, const char *src );
#else
#define ovl_strcpy	strcpy
#endif /* NO_OVL_STRCPY */
static void add_response( httpd_conn* hc, const char* str );
static void add_responselen( httpd_conn* hc, const char* str, int len );
static void add_allowed_methods( httpd_conn* hc );
static void send_mime( httpd_conn* hc, int status,
	const char* title, int titlelen,
	const char* extraheads, int length, time_t mod );
static void send_response( httpd_conn* hc, int status,
	char* title, int titlelen,
	char* extraheads, char* form, const char* arg );
static void send_response_tail( httpd_conn* hc, int headers_len );
static int  need_defang( const char* str );
static void defang( const char* str, char* dfstr, int dfsize );
#if defined(ERR_DIR) || defined(ERR_VHOST_DIR)
static int send_err_file( httpd_conn* hc, int status,
	char* title, int titlelen, char* extraheads, char* filename );
#endif /* ERR_DIR || ERR_VHOST_DIR */
static void httpd_send_err405( httpd_conn* hc, int allowed_methods,
				const char* method_str );
static void httpd_send_err501( httpd_conn* hc,
				const char* method_str );
#ifdef AUTH_FILE
static void send_authenticate( httpd_conn* hc, char* realm );
static int b64_decode( const char* str, unsigned char* space, int size );
static int auth_check( httpd_conn* hc, char* dirname  );
static int auth_check2( httpd_conn* hc, char* dirname  );
#endif /* AUTH_FILE */

static void send_redirect( httpd_conn* hc, char *encodedurl, size_t url_len );
static void send_dirredirect( httpd_conn* hc );
static inline int get_method_id( char* method_str );
static void strdecode( char* to, char* from );

#ifdef GENERATE_INDEXES
static void strencode( char* to, int tosize, char* from );
#endif /* GENERATE_INDEXES */

#ifdef TILDE_MAP_1
static int tilde_map_1( httpd_conn* hc );
#endif /* TILDE_MAP_1 */

#ifdef TILDE_MAP_2
static int tilde_map_2( httpd_conn* hc );
#endif /* TILDE_MAP_2 */

static int vhost_map( httpd_conn* hc );
static char* expand_symlinks( char* path, int path_len, int *checkedlenP,
                              char** restP, int no_symlink, int tildemapped,
                              struct stat* sbP );
static int httpd_request_reset0( httpd_conn* hc );
static char* bufgets( httpd_conn* hc );
static int de_dotdot( char* file );
static unsigned int hash_mime( char *buf, size_t len );
static int  init_mime( httpd_server * hs );
static void figure_mime( httpd_conn* hc );

#if	defined(EXECUTE_CHILD) && defined(CGI_TIMELIMIT)
static void cgi_kill2( ClientData client_data, struct timeval* nowP );
static void cgi_kill( ClientData client_data, struct timeval* nowP );
#endif /* EXECUTE_CHILD && CGI_TIMELIMIT */

#ifdef GENERATE_INDEXES
static int ls( httpd_conn* hc );
#endif /* GENERATE_INDEXES */

#ifdef SERVER_NAME_LIST
static char* hostname_map( char* hostname );
#endif /* SERVER_NAME_LIST */

#ifdef EXECUTE_CGI
static char* build_env( const char* fmt, const char* arg );
static char** make_envp( httpd_conn* hc, char *cgipattern );
static char** make_argp( httpd_conn* hc, char *cliprogram );
static void cgi_interpose_input( httpd_conn* hc, int wfd );
static void post_post_garbage_hack( httpd_conn* hc );
static void cgi_interpose_output( httpd_conn* hc, int rfd );
static void cgi_child( httpd_conn* hc, char* cliprogram, char* cgipattern );
static int cgi( httpd_conn* hc, char* cliprogram, char *cgipattern );
#endif /* EXECUTE_CGI */

static int really_start_request( httpd_conn* hc, struct timeval* nowP,
		int numconn, int maxconn, int MaxKeepAliveFileSize );
static void make_log_entry( httpd_conn* hc, struct timeval* nowP );
static int fmt_cern_time   ( char* buftime, size_t bufsize, time_t tnow );
#ifndef NO_TMF
static struct tm time_to_tm( time_t t1 );
#endif /* NO_TMF */
static int fmt_rfc1123_time( char* buftime, size_t bufsize, time_t tnow );
static int check_referer( httpd_conn* hc );
static int really_check_referer( httpd_conn* hc );
static int sockaddr_check( httpd_sockaddr* saP );
static size_t sockaddr_len( httpd_sockaddr* saP );
#ifndef NO_MYSNP
static int my_snprintf( char* str, size_t size, const char* format, ... );
#else
#define my_snprintf	snprintf
#endif
static size_t fmt_ulong10( char *psz, const unsigned long culNum );

#ifdef EXECUTE_CHILD

static int reap_time;		/* interval between calls to do_reap() */
static int reap_count;		/* max. number of children before do_reap() */

static void
child_reaper( ClientData client_data, struct timeval* nowP )
    {
    int child_count;
    static int prev_child_count = 0;

    child_count = do_reap();

    /* Reschedule reaping, with adaptively changed time. */
    if ( child_count > prev_child_count * 3 / 2 )
	reap_time = MAX( reap_time / 2, MIN_REAP_TIME );
    else if ( child_count < prev_child_count * 2 / 3 )
	reap_time = MIN( reap_time * 5 / 4, MAX_REAP_TIME );
    if ( tmr_create( nowP, child_reaper, JunkClientData,
		reap_time * 1000L, TMR_ONE_SHOT ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(child_reaper) failed" );
	exit( 100 );
	}
    }

static int
do_reap( void )
    {
    int child_count;
    pid_t pid;
    int status;

    /* reset reap_count */
    reap_count = 0;

    /* Reap defunct children until there aren't any more. */
    for ( child_count = 0; ; ++child_count )
	{
#ifdef HAVE_WAITPID
	pid = waitpid( (pid_t) -1, &status, WNOHANG );
#else /* HAVE_WAITPID */
	pid = wait3( &status, WNOHANG, (struct rusage*) 0 );
#endif /* HAVE_WAITPID */
	if ( (int) pid == 0 )           /* none left */
	    break;
	if ( (int) pid < 0 )
	    {
	    if ( errno == EINTR )       /* because of ptrace */
		continue;
	    /* ECHILD shouldn't happen with the WNOHANG option, but with
	    ** some kernels it does anyway.  Ignore it.
	    */
	    if ( errno != ECHILD )
		syslog( LOG_ERR, "waitpid - %m" );
	    break;
	    }
	}
    return child_count;
    }

static void
do_cond_reap( void )
    {
    /* conditional reap children */
    if ( ++reap_count < MAX_REAP_COUNT )
	return;
    (void) do_reap();
    }

#endif /* EXECUTE_CHILD */


#ifdef EXECUTE_CGICLI


httpd_cgicli_vrec*
httpd_alloc_cgicli_vrec( void )
    {
    httpd_cgicli_vrec* pvrec;

    pvrec = (httpd_cgicli_vrec*) calloc( 1, sizeof( httpd_cgicli_vrec ) +
			MAX_CGICLI_ENTRIES * sizeof( httpd_cgicli_entry ) );
    if ( pvrec != (httpd_cgicli_vrec*) 0 )
	pvrec->max_cgicli = MAX_CGICLI_ENTRIES;
    return pvrec;
    }


void
httpd_free_cgicli_vrec( httpd_cgicli_vrec* pvrec )
    {
    int i;
    if ( pvrec == (httpd_cgicli_vrec*) 0 )
	return;
    for ( i = 0; i < pvrec->cnt_cgicli; ++i )
	{
	free( pvrec->cgicli_tab[i].cli_pattern );
	free( pvrec->cgicli_tab[i].cli_path );
	}
    free( pvrec );
    }


/* Adds a cgicli entry to the already allocated record table.
*/
int
httpd_add_cgicli_entry( httpd_cgicli_vrec* pvrec,
			char* clipattern, char* clipath )
    {
    int	i = 0;
    httpd_cgicli_entry* pcli;

    /* Check formal parameters */
    if ( pvrec == (httpd_cgicli_vrec*) 0 ||
	 pvrec->max_cgicli < 1 ||
	 pvrec->max_cgicli > MAX_CGICLI_ENTRIES ||
	 clipattern == (char*) 0 || !clipattern[0] ||
	 clipath    == (char*) 0 || !clipath[0] )
	return -1;

    /* Check if table is full */
    if ( pvrec->cnt_cgicli >= pvrec->max_cgicli )
	return 99;

    for ( i = 0; i < pvrec->cnt_cgicli; ++i )
	{
	pcli = &( pvrec->cgicli_tab[i] );

	if ( strcmp( pcli->cli_pattern, clipattern ) == 0 )
	    /* Already exists */
	    return 100;
	}
    pcli = &( pvrec->cgicli_tab[i] );

    /* Fill entry values */
    pcli->cli_pattern = strdup( clipattern );
    if ( pcli->cli_pattern == (char*) 0 )
	return 1;
    pcli->cli_path = strdup( clipath );
    if ( pcli->cli_path == (char*) 0 )
	{
	free( pcli->cli_pattern );
	pcli->cli_pattern = (char*) 0;
	return 2;
	}

    /* Entry added, increment counter */
    ++pvrec->cnt_cgicli;

    return 0;
    }


static httpd_cgicli_vrec*
httpd_dup_cgicli_vrec( httpd_cgicli_vrec* pvrec )
    {
    int i;
    httpd_cgicli_vrec* pvrec2 = httpd_alloc_cgicli_vrec();

    if ( pvrec2 == (httpd_cgicli_vrec*) 0 )
	return pvrec2;

    for ( i = 0; i < pvrec->cnt_cgicli; ++i )
	{
	if ( httpd_add_cgicli_entry( pvrec2,
		pvrec->cgicli_tab[i].cli_pattern,
		pvrec->cgicli_tab[i].cli_path ) != 0 )
	    {
	    httpd_free_cgicli_vrec( pvrec2 );
	    return (httpd_cgicli_vrec*) 0;
	    }
	}
    return pvrec2;
    }

#endif /* EXECUTE_CGICLI */


static void
check_options( void )
    {
#if defined(TILDE_MAP_1) && defined(TILDE_MAP_2)
    syslog( LOG_CRIT, "both TILDE_MAP_1 and TILDE_MAP_2 are defined" );
    exit( 101 );
#endif /* both */
    }


static void
free_httpd_server( httpd_server* hs )
    {
    if ( hs == (httpd_server*) 0 )
	return;
    free( (void*) hs->binding_hostname );
    free( (void*) hs->cwd );
    free( (void*) hs->cgi_pattern );
#ifdef EXECUTE_CGICLI
    httpd_free_cgicli_vrec( hs->cgicli_vrec );
#endif /* EXECUTE_CGICLI */
    free( (void*) hs->charset );
    free( (void*) hs->def_mime_type );
    free( (void*) hs->def_mime_typeb );
    free( (void*) hs->url_pattern );
    free( (void*) hs->local_pattern );
    memset( hs, 0, sizeof(*hs) );
    free( (void*) hs );
    }


/* cgicli_vrec is not copied, thus it must be persistent.
*/
httpd_server*
httpd_initialize(
    char* hostname, httpd_sockaddr* sa4P, httpd_sockaddr* sa6P, int port,
    char* cgi_pattern, httpd_cgicli_vrec* cgicli_vrec,
    char* charset, int max_age, char* cwd, int no_log, FILE* logfp,
    int no_symlink, int vhost, int global_passwd, char* url_pattern,
    char* local_pattern, int no_empty_referers, int do_generate_indexes,
    int do_keepalive_conns, int conn_SO_RCVBUF, int conn_SO_SNDBUF )
    {
    httpd_server* hs;
    static char ghnbuf[256];

    check_options();

#ifdef EXECUTE_CHILD
    if ( cgi_pattern != (char*)0 ||
#ifdef EXECUTE_CGICLI
	( cgicli_vrec != (httpd_cgicli_vrec*) 0 &&
	  cgicli_vrec->cnt_cgicli > 0 ) ||
#endif /* EXECUTE_CGICLI */
	do_generate_indexes )
	{
	/* Set up child-process reaper. */
	reap_count = 0;
	reap_time = MIN( MIN_REAP_TIME * 4, MAX_REAP_TIME );
	if ( tmr_create( (struct timeval*) 0, child_reaper, JunkClientData,
		reap_time * 1000L, TMR_ONE_SHOT ) == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(child_reaper) failed" );
	    return (httpd_server*) 0;
	    }
	}
#endif /* EXECUTE_CHILD */

    hs = CNEW( httpd_server, 1 );
    if ( hs == (httpd_server*) 0 )
	{
	syslog( LOG_CRIT, "out of memory allocating an httpd_server" );
	return (httpd_server*) 0;
	}

    if ( hostname != (char*) 0 )
	{
	hs->binding_hostname = strdup( hostname );
	if ( hs->binding_hostname == (char*) 0 )
	    {
	    syslog( LOG_CRIT, "out of memory copying hostname" );
	    return (httpd_server*) 0;
	    }
	hs->server_hostname = hs->binding_hostname;
	}
    else
	{
	hs->binding_hostname = (char*) 0;
	hs->server_hostname = (char*) 0;
	if ( gethostname( ghnbuf, sizeof(ghnbuf) - 1 ) < 0 )
	    ghnbuf[0] = '\0';
	ghnbuf[sizeof(ghnbuf)-1] = '\0';
#ifdef SERVER_NAME_LIST
	if ( ghnbuf[0] != '\0' )
	    hs->server_hostname = hostname_map( ghnbuf );
#endif /* SERVER_NAME_LIST */
	if ( hs->server_hostname == (char*) 0 )
	    {
#ifdef SERVER_NAME
	    hs->server_hostname = SERVER_NAME;
#else /* SERVER_NAME */
	    if ( ghnbuf[0] != '\0' )
		hs->server_hostname = ghnbuf;
#endif /* SERVER_NAME */
	    }
	}

    hs->port = port;

    if ( cgi_pattern == (char*) 0 )
	hs->cgi_pattern = (char*) 0;
    else
	{
	hs->cgi_pattern = strdup( cgi_pattern );
	if ( hs->cgi_pattern == (char*) 0 )
	    {
	    syslog( LOG_CRIT, "out of memory copying cgi_pattern" );
	    return (httpd_server*) 0;
	    }
	match_nuke_slashpat( hs->cgi_pattern );
	}

#ifdef EXECUTE_CGICLI
    if ( cgicli_vrec == (httpd_cgicli_vrec*) 0 ||
	 cgicli_vrec->cnt_cgicli < 1 )
#endif /* EXECUTE_CGICLI */
	hs->cgicli_vrec = (httpd_cgicli_vrec*) 0;
#ifdef EXECUTE_CGICLI
    else
	{
	hs->cgicli_vrec = httpd_dup_cgicli_vrec( cgicli_vrec );
	if ( hs->cgicli_vrec == (httpd_cgicli_vrec*) 0 )
	    {
	    syslog( LOG_CRIT, "out of memory copying cgicli_vrec" );
	    return (httpd_server*) 0;
	    }
	}
#endif /* EXECUTE_CGICLI */

    hs->charset = strdup( charset );
    if ( hs->charset == (char*) 0 )
	{
	syslog( LOG_CRIT, "out of memory copying charset" );
	return (httpd_server*) 0;
	}

    hs->max_age = max_age;

    hs->cwd = strdup( cwd );
    if ( hs->cwd == (char*) 0 )
	{
	syslog( LOG_CRIT, "out of memory copying cwd" );
	free( hs->charset );
	return (httpd_server*) 0;
	}
    hs->cwd_len = strlen( hs->cwd );
    if ( url_pattern == (char*) 0 )
	hs->url_pattern = (char*) 0;
    else
	{
	hs->url_pattern = strdup( url_pattern );
	if ( hs->url_pattern == (char*) 0 )
	    {
	    syslog( LOG_CRIT, "out of memory copying url_pattern" );
	    free( hs->charset );
	    free( hs->cwd );
	    return (httpd_server*) 0;
	    }
	}
    if ( local_pattern == (char*) 0 )
	hs->local_pattern = (char*) 0;
    else
	{
	hs->local_pattern = strdup( local_pattern );
	if ( hs->local_pattern == (char*) 0 )
	    {
	    syslog( LOG_CRIT, "out of memory copying local_pattern" );
	    free( hs->charset );
	    free( hs->cwd );
	    if ( hs->url_pattern != (char*)0 )
		free( hs->url_pattern );
	    return (httpd_server*) 0;
	    }
	}
    hs->no_log = no_log;
    hs->logfp = (FILE*) 0;
    httpd_set_logfp( hs, logfp );
    hs->no_symlink = no_symlink;
    hs->vhost = vhost;
    hs->global_passwd = global_passwd;
    hs->no_empty_referers = no_empty_referers;
    hs->do_generate_indexes = !!do_generate_indexes;
    hs->do_keepalive_conns  = !!do_keepalive_conns;
    hs->nowtime             = 0L;
    hs->def_mime_type       = (char*) 0;
    hs->def_mime_typeb      = (char*) 0;

    if ( init_mime( hs ) != 0 )
	{
	free_httpd_server( hs );
	return (httpd_server*) 0;
	}

    /* Initialize listen sockets.  Try v6 first because of a Linux peculiarity;
    ** unlike other systems, it has magical v6 sockets that also listen for v4,
    ** but if you bind a v4 socket first then the v6 bind fails.
    */
    if ( sa6P == (httpd_sockaddr*) 0 )
	hs->listen6_fd = -1;
    else
	hs->listen6_fd = initialize_listen_socket(
		sa6P, conn_SO_RCVBUF, conn_SO_SNDBUF );
    if ( sa4P == (httpd_sockaddr*) 0 )
	hs->listen4_fd = -1;
    else
	hs->listen4_fd = initialize_listen_socket(
		sa4P, conn_SO_RCVBUF, conn_SO_SNDBUF );

#ifdef USE_SCTP
    hs->listensctp_fd = initialize_listen_sctp_socket( sa4P, sa6P );
#endif

    /* If we didn't get any valid sockets, fail. */
	#ifdef USE_SCTP
	    if ( hs->listen4_fd == -1 &&
		 hs->listen6_fd == -1 &&
		 hs->listensctp_fd == -1 )
	#else
	    if ( hs->listen4_fd == -1 && hs->listen6_fd == -1 )
	#endif
	{
	free_httpd_server( hs );
	return (httpd_server*) 0;
	}

    /* Done initializing. */
    if ( hs->binding_hostname == (char*) 0 )
	syslog( LOG_NOTICE, "%.80s listening on port %d", SERVER_SOFTWARE,
	    hs->port );
    else
	syslog(
	    LOG_NOTICE, "%.80s listening on %.80s, port %d", SERVER_SOFTWARE,
	    httpd_ntoa( hs->listen4_fd != -1 ? sa4P : sa6P ), hs->port );
    return hs;
    }


/* Don't change these limits (unless you know what you do).
*/

#define MIN_SO_RCVBUF	4096
#define MAX_SO_RCVBUF	1048576
#define MIN_SO_SNDBUF	4096
#define MAX_SO_SNDBUF	4194304

static int
initialize_listen_socket( httpd_sockaddr* saP,
			int conn_SO_RCVBUF, int conn_SO_SNDBUF )
    {
    int listen_fd;
    int soptval, flags;
    socklen_t soptlen;

    /* Check sockaddr. */
    if ( ! sockaddr_check( saP ) )
	{
	syslog( LOG_CRIT, "unknown sockaddr family on listen socket" );
	return -1;
	}

    /* Create socket. */
    listen_fd = socket( saP->sa.sa_family, SOCK_STREAM, 0 );
    if ( listen_fd < 0 )
	{
	syslog( LOG_CRIT, "socket %.80s - %m", httpd_ntoa( saP ) );
	return -1;
	}
    if ( fcntl( listen_fd, F_SETFD, FD_CLOEXEC ) < 0 )
	{
	syslog( LOG_CRIT, "fcntl FD_CLOEXEC - %m" );
	(void) close( listen_fd );
	return -1;
	}

    /* Allow reuse of local addresses. */
    soptval = 1;
    soptlen = sizeof(soptval);
    if ( setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR,
		(char*) &soptval, soptlen ) < 0 )
	syslog( LOG_CRIT, "setsockopt SO_REUSEADDR - %m" );
	/* Make v6 sockets v6 only */
	if ( saP->sa.sa_family == AF_INET6 )
	if ( setsockopt( listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &soptval, sizeof(soptval) ) < 0 )
		syslog( LOG_CRIT, "setsockopt IPV6_V6ONLY - %m" );



    /* Get, set and get again receive socket buffer size */

    soptval = 0;
    soptlen = sizeof(soptval);
    if ( getsockopt(
	listen_fd, SOL_SOCKET, SO_RCVBUF, &soptval, &soptlen ) < 0 )
	syslog( LOG_CRIT, "getsockopt SO_RCVBUF - %m" );
    else /* for the first call we do an additional check */
    if ( soptlen != sizeof(soptval) )
	syslog( LOG_CRIT,
		"getsockopt SO_RCVBUF: soptlen %lu != %lu sizeof(soptval)",
		(uint64_t)soptlen, sizeof(soptval) );
    else
	syslog( LOG_NOTICE, "default SO_RCVBUF: %d", soptval );

    if ( conn_SO_RCVBUF >= MIN_SO_RCVBUF &&
	 conn_SO_RCVBUF <= MAX_SO_RCVBUF )
	{
	soptval = conn_SO_RCVBUF;
	soptlen = sizeof(soptval);
	if ( setsockopt(
	     listen_fd, SOL_SOCKET, SO_RCVBUF, (char*)&soptval, soptlen ) < 0 )
	    {
	    syslog( LOG_CRIT, "setsockopt SO_RCVBUF(%d) - %m", soptval );
	    (void) close( listen_fd );
	    return -1;
	    }
	syslog( LOG_NOTICE, "set NEW SO_RCVBUF: %d", soptval );

	soptval = 0;
	soptlen = sizeof(soptval);
	if ( getsockopt(
	    listen_fd, SOL_SOCKET, SO_RCVBUF, &soptval, &soptlen ) < 0 )
	    syslog( LOG_CRIT, "getsockopt SO_RCVBUF - %m" );
	else
	    syslog( LOG_NOTICE, "current SO_RCVBUF: %d", soptval );
	}

    /* Get, set and get again send socket buffer size */

    soptval = 0;
    soptlen = sizeof(soptval);
    if ( getsockopt(
	listen_fd, SOL_SOCKET, SO_SNDBUF, &soptval, &soptlen ) < 0 )
	syslog( LOG_CRIT, "getsockopt SO_SNDBUF - %m" );
    else
	syslog( LOG_NOTICE, "default SO_SNDBUF: %d", soptval );

    if ( conn_SO_SNDBUF >= MIN_SO_SNDBUF &&
	 conn_SO_SNDBUF <= MAX_SO_SNDBUF )
	{
	soptval = conn_SO_SNDBUF;
	soptlen = sizeof(soptval);
	if ( setsockopt(
	     listen_fd, SOL_SOCKET, SO_SNDBUF, (char*)&soptval, soptlen ) < 0 )
	    {
	    syslog( LOG_CRIT, "setsockopt SO_SNDBUF(%d) - %m", soptval );
	    (void) close( listen_fd );
	    return -1;
	    }
	syslog( LOG_NOTICE, "set NEW SO_SNDBUF: %d", soptval );

	soptval = 0;
	soptlen = sizeof(soptval);
	if ( getsockopt(
	    listen_fd, SOL_SOCKET, SO_SNDBUF, &soptval, &soptlen ) < 0 )
	    syslog( LOG_CRIT, "getsockopt SO_SNDBUF - %m" );
	else
	    syslog( LOG_NOTICE, "current SO_SNDBUF: %d", soptval );
	}

    /* Bind to it. */
    if ( bind( listen_fd, &saP->sa, sockaddr_len( saP ) ) < 0 )
	{
	syslog(
	    LOG_CRIT, "bind %.80s - %m", httpd_ntoa( saP ) );
	(void) close( listen_fd );
	return -1;
	}

    /* Set the listen file descriptor to non-blocking mode. */
    flags = httpd_set_nonblock( listen_fd, SOPT_ON );
    if ( flags == -1 )
	{
	syslog( LOG_CRIT, "httpd_set_nonblock(listen_fd, ON): fcntl - %m" );
	(void) close( listen_fd );
	return -1;
	}

    /* Start a listen going. */
    if ( listen( listen_fd, LISTEN_BACKLOG ) < 0 )
	{
	syslog( LOG_CRIT, "listen - %m" );
	(void) close( listen_fd );
	return -1;
	}

    /* Use accept filtering, if available. */

#ifdef USE_ACCEPT_FILTER

#if defined( SO_ACCEPTFILTER )
    /* FreeBSD */
    {
#if ( __FreeBSD_version >= 411000 )
#define ACCEPT_FILTER_NAME "httpready"
#else
#define ACCEPT_FILTER_NAME "dataready"
#endif
    struct accept_filter_arg af;
    (void) bzero( &af, sizeof(af) );
    (void) strcpy( af.af_name, ACCEPT_FILTER_NAME );
    if ( setsockopt( listen_fd, SOL_SOCKET, SO_ACCEPTFILTER,
	(char*) &af, sizeof(af) ) == -1 )
	syslog( LOG_ERR, "setsockopt: SO_ACCEPTFILTER(%s) - %m", af.af_name );
    else
	syslog( LOG_NOTICE, "Accept Filter: SO_ACCEPTFILTER(%s)", af.af_name );
    }
    /* SO_ACCEPTFILTER */

#elif defined( TCP_DEFER_ACCEPT ) && defined( SOL_TCP )
    /* Linux */
    /* max. time to receive first data packet */
    soptval = IDLE_READ_TIMELIMIT;
    if ( setsockopt( listen_fd, SOL_TCP, TCP_DEFER_ACCEPT,
	(char*) &soptval, sizeof(soptval) ) == -1 )
	syslog( LOG_ERR,
		"setsockopt: TCP_DEFER_ACCEPT(%d sec.) - %m", soptval );
    else
	syslog( LOG_NOTICE,
		"Accept Filter: TCP_DEFER_ACCEPT(%d sec.)", soptval );

#endif	/* TCP_DEFER_ACCEPT */

#endif	/* USE_ACCEPT_FILTER */

    return listen_fd;
    }

#ifdef USE_SCTP
static int
initialize_listen_sctp_socket( httpd_sockaddr* sa4P, httpd_sockaddr* sa6P )
    {
    struct sctp_initmsg initmsg;
    int listen_fd;
    int flags;
#ifdef USE_IPV6
    int off;
#endif
#ifdef SCTP_RECVRCVINFO
	int on;
#endif
#if defined(SCTP_ECN_SUPPORTED) || defined(SCTP_PR_SUPPORTED) || defined(SCTP_ASCONF_SUPPORTED) || defined(SCTP_AUTH_SUPPORTED) || defined(SCTP_RECONFIG_SUPPORTED) || defined(SCTP_NRSACK_SUPPORTED) || defined(SCTP_PKTDROP_SUPPORTED)
    struct sctp_assoc_value assoc_value;
#endif

    if ( ( sa4P == (httpd_sockaddr*) 0 ) && ( sa6P == (httpd_sockaddr*) 0 ) )
	{
	syslog( LOG_CRIT, "no addresses for listen socket" );
	return -1;
	}
    /* Check sockaddr. */
    if ( ( sa4P != (httpd_sockaddr*) 0 ) && ! sockaddr_check( sa4P ) )
	{
	syslog( LOG_CRIT, "unknown sockaddr family on listen socket" );
	return -1;
	}
    if ( ( sa6P != (httpd_sockaddr*) 0 ) && ! sockaddr_check( sa6P ) )
	{
	syslog( LOG_CRIT, "unknown sockaddr family on listen socket" );
	return -1;
	}

    /* Create socket. */
    listen_fd = socket( sa6P ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_SCTP );
    if ( listen_fd < 0 )
	{
	syslog( LOG_CRIT, "SCTP socket - %m");
	return -1;
	}
    (void) fcntl( listen_fd, F_SETFD, 1 );

#ifdef USE_IPV6
    if ( ( sa4P != (httpd_sockaddr*) 0 ) && ( sa6P != (httpd_sockaddr*) 0 ) )
	{
	off = 0;
	if ( setsockopt(
		 listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &off,
		 sizeof(off) ) < 0 )
	    {
	    syslog( LOG_CRIT, "setsockopt IPV6_ONLY - %m" );
	    (void) close( listen_fd );
	    return -1;
	    }
	}
#endif

    /* Ensure an appropriate number of stream will be negotated. */
    initmsg.sinit_num_ostreams = 100;   /* For now, only a single stream */
    initmsg.sinit_max_instreams = 100;  /* For now, only a single stream */
    initmsg.sinit_max_attempts = 0;   /* Use default */
    initmsg.sinit_max_init_timeo = 0; /* Use default */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_INITMSG, (char*) &initmsg,
	     sizeof(initmsg) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_INITMSG - %m" );
	(void) close( listen_fd );
	return -1;
	}

#if defined(SCTP_ECN_SUPPORTED) || defined(SCTP_PR_SUPPORTED) || defined(SCTP_ASCONF_SUPPORTED) || defined(SCTP_AUTH_SUPPORTED) || defined(SCTP_RECONFIG_SUPPORTED) || defined(SCTP_NRSACK_SUPPORTED) || defined(SCTP_PKTDROP_SUPPORTED)
    assoc_value.assoc_id = 0;
    assoc_value.assoc_value = 0;
#endif
#if defined(SCTP_ECN_SUPPORTED)
    /* Disable the Explicit Congestion Notification extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_ECN_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_ECN_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_PR_SUPPORTED)
    /* Disable the Partial Reliability extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_PR_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_PR_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_ASCONF_SUPPORTED)
    /* Disable the Address Reconfiguration extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_ASCONF_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_ASCONF_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_AUTH_SUPPORTED)
    /* Disable the Authentication extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_AUTH_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_AUTH_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_RECONFIG_SUPPORTED)
    /* Disable the Stream Reconfiguration extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_RECONFIG_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_RECONFIG_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_NRSACK_SUPPORTED)
    /* Disable the NR-SACK extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_NRSACK_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_NRSACK_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_PKTDROP_SUPPORTED)
    /* Disable the Packet Drop Report extension */
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_PKTDROP_SUPPORTED, (char*) &assoc_value,
	     sizeof(assoc_value) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_PKTDROP_SUPPORTED - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif
#if defined(SCTP_RECVRCVINFO)
    /* Enable RCVINFO delivery */
	on = 1;
    if ( setsockopt(
	     listen_fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, (char*) &on,
		 sizeof(on) ) < 0 )
	{
	syslog( LOG_CRIT, "setsockopt SCTP_RECVRCVINFO - %m" );
	(void) close( listen_fd );
	return -1;
	}
#endif

    /* Bind to it. */
    if ( sa6P != (httpd_sockaddr*) 0 )
	if ( sctp_bindx( listen_fd, &sa6P->sa, 1, SCTP_BINDX_ADD_ADDR) < 0 )
	    {
	    syslog(
		LOG_CRIT, "sctp_bindx %.80s - %m", httpd_ntoa( sa6P ) );
	    (void) close( listen_fd );
	    return -1;
	    }

    if ( sa4P != (httpd_sockaddr*) 0 )
	{
#ifdef USE_IPV6
	if ( (sa6P == (httpd_sockaddr*) 0) ||
	     ((sa6P != (httpd_sockaddr*) 0) &&
	      !IN6_IS_ADDR_UNSPECIFIED(&(sa6P->sa_in6.sin6_addr))) )
#endif
	    if ( sctp_bindx( listen_fd, &sa4P->sa, 1, SCTP_BINDX_ADD_ADDR) < 0 )
		{
		syslog(
		    LOG_CRIT, "sctp_bindx %.80s - %m", httpd_ntoa( sa4P ) );
		(void) close( listen_fd );
		return -1;
		}
	}

    /* Set the listen file descriptor to no-delay / non-blocking mode. */
    flags = fcntl( listen_fd, F_GETFL, 0 );
    if ( flags == -1 )
	{
	syslog( LOG_CRIT, "fcntl F_GETFL - %m" );
	(void) close( listen_fd );
	return -1;
	}
    if ( fcntl( listen_fd, F_SETFL, flags | O_NDELAY ) < 0 )
	{
	syslog( LOG_CRIT, "fcntl O_NDELAY - %m" );
	(void) close( listen_fd );
	return -1;
	}

    /* Start a listen going. */
    if ( listen( listen_fd, LISTEN_BACKLOG ) < 0 )
	{
	syslog( LOG_CRIT, "listen - %m" );
	(void) close( listen_fd );
	return -1;
	}

    return listen_fd;
    }
#endif



void
httpd_set_logfp( httpd_server* hs, FILE* logfp )
    {
    if ( hs->logfp != (FILE*) 0 )
	(void) fclose( hs->logfp );
    hs->logfp = logfp;
    }


void
httpd_flush_logfp( httpd_server* hs )
    {
    if ( hs == (httpd_server*) 0 ||
	 hs->no_log ||
	 hs->logfp == (FILE*) 0 )
	return;
    fflush( hs->logfp );
    }


void
httpd_terminate( httpd_server* hs )
    {
    if ( hs == (httpd_server*) 0 )
	return;
    httpd_unlisten( hs );
    if ( hs->logfp != (FILE*) 0 )
	{
	(void) fclose( hs->logfp );
	hs->logfp = (FILE*) 0;
	}
    free_httpd_server( hs );
    }


void
httpd_unlisten( httpd_server* hs )
    {
    if ( hs == (httpd_server*) 0 )
	return;
    if ( hs->listen4_fd != -1 )
	{
	(void) close( hs->listen4_fd );
	hs->listen4_fd = -1;
	}
    if ( hs->listen6_fd != -1 )
	{
	(void) close( hs->listen6_fd );
	hs->listen6_fd = -1;
	}
#ifdef USE_SCTP
    if ( hs->listensctp_fd != -1 )
	{
	(void) close( hs->listensctp_fd );
	hs->listensctp_fd = -1;
	}
#endif

    }


/* Conditional macro to allow two alternate forms for use in the built-in
** error pages.  If EXPLICIT_ERROR_PAGES is defined, the second and more
** explicit error form is used; otherwise, the first and more generic
** form is used.
*/
#ifdef EXPLICIT_ERROR_PAGES
#define ERROR_FORM(a,b) b
#else /* EXPLICIT_ERROR_PAGES */
#define ERROR_FORM(a,b) a
#endif /* EXPLICIT_ERROR_PAGES */

	/* NOTE: C ANSI compiler required ! */
#define SZLEN(s)   ((int) sizeof(s) - 1)

#define      ok200title      "OK"
#define      ok200titlelen   SZLEN(ok200title)

#define      ok206title      "Partial Content"
#define      ok206titlelen   SZLEN(ok206title)

#define      err302title     "Found"
#define      err302titlelen  SZLEN(err302title)
static char* err302form    = "The actual URL is '%.80s'.\n";

#define      err304title     "Not Modified"
#define      err304titlelen  SZLEN(err304title)

#define      err400title     "Bad Request"
#define      err400titlelen  SZLEN(err400title)
static char* err400form     =
    "Your request has bad syntax or is inherently impossible to satisfy.%.80s\n";

#ifdef AUTH_FILE
#define      err401title     "Unauthorized"
#define      err401titlelen  SZLEN(err401title)
static char* err401form    =
    "Authorization required for the URL '%.80s'.\n";
#endif /* AUTH_FILE */

#define      err403title     "Forbidden"
#define      err403titlelen  SZLEN(err403title)
static char* err403form    =
    "You do not have permission to get URL '%.80s' from this server.\n";

#define      err404title     "Not Found"
#define      err404titlelen  SZLEN(err404title)
static char* err404form    =
    "The requested URL '%.80s' was not found on this server.\n";

#define      err405title     "Method Not Allowed"
#define      err405titlelen  SZLEN(err405title)
static char* err405form    =
    "The requested method '%.80s' is not allowed for this URL.\n";

#define      err408title     "Request Timeout"
#define      err408titlelen  SZLEN(err408title)
static char* err408form    =
    "No request appeared within a reasonable time period.\n";

#define      err413title     "Request Entity too large"
#define      err413titlelen  SZLEN(err413title)
static char* err413form    =
    "The request is too large to be accepted.\n";

#define      err414title     "Request-URI Too Long"
#define      err414titlelen  SZLEN(err414title)
static char* err414form    =
    "The request-URI is too long to be handled.\n";

#define      err416title     "Requested range not satisfiable"
#define      err416titlelen  SZLEN(err416title)
static char* err416form    =
    "The requested range, URL '%.80s', was not satisfiable (ini_loc >= len).\n";

#define      err500title     "Internal Error"
#define      err500titlelen  SZLEN(err500title)
static char* err500form    =
    "There was an unusual problem serving the requested URL '%.80s'.\n";

#define      err501title     "Not Implemented"
#define      err501titlelen  SZLEN(err501title)
static char* err501form    =
    "The requested method '%.80s' is not implemented by this server.\n";

#define      err503title     "Service Temporarily Overloaded"
#define      err503titlelen  SZLEN(err503title)
static char* err503form     =
    "The requested URL '%.80s' is temporarily overloaded.  Please try again later.\n";

#define      err505title     "HTTP Version not supported"
#define      err505titlelen  SZLEN(err505title)
static char* err505form    =
    "HTTP version '%.20s' is not supported by this server.\n";


#ifndef NO_OVL_STRCPY
/*
** Handles properly overlapping source and destination
** memory in order to work around strcpy(3) undefined behaviour.
*/
static char *
ovl_strcpy( char *dst, const char *psrc )
    {
    char *pdst = dst;

    while ( ( *pdst++ = *psrc++ ) != '\0' )
	;

    return dst;
    }
#endif /* !NO_OVL_STRCPY */


#define alloc_maxresponse_M( hc, len )	\
    httpd_realloc_str( &((hc)->response), &((hc)->maxresponse),	\
		(len) )


#define alloc_responselen_M( hc, len )	\
    httpd_realloc_str( &((hc)->response), &((hc)->maxresponse),	\
		( (hc)->responselen + (len) ) )


#define add_responselen_M( hc, str, len )	\
    do	\
    {	\
    (void) memcpy( &( (hc)->response[ (hc)->responselen ] ), (str), (len) ); \
    (hc)->responselen += (len);	\
    }	\
    while(0)


#define add_responseCHR_M( hc, c )	\
    (hc)->response[ (hc)->responselen++ ] = (c)


#define add_responseCRLF_M( hc )	\
    do	\
    {	\
    (hc)->response[ (hc)->responselen++ ] = CHR_CR;	\
    (hc)->response[ (hc)->responselen++ ] = CHR_LF;	\
    }	\
    while(0)


#define add_responseULong10_M( hc, uNum )	\
    (hc)->responselen += (int) fmt_ulong10(	\
	&( (hc)->response[ (hc)->responselen ] ), (uNum) )


/* Append a string to the buffer waiting to be sent as response. */
static void
add_response( httpd_conn* hc, const char* str )
    {
    int len = (int) strlen( str );
    alloc_responselen_M( hc, len );
    add_responselen_M( hc, str, len );
    }


/* Append a string to the buffer waiting to be sent as response. */
static void
add_responselen( httpd_conn* hc, const char* str, int len )
    {
    alloc_responselen_M( hc, len );
    add_responselen_M( hc, str, len );
    }



/* Clear the buffered response */
void
httpd_clear_response( httpd_conn* hc )
    {
	hc->responselen = 0;
    }

#ifdef USE_SCTP
ssize_t
httpd_write_sctp( int fd, const char * buf, size_t nbytes,
                  int use_eeor, int eor, uint32_t ppid, uint16_t sid )
{
    ssize_t r;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec iov;
#ifdef SCTP_SNDINFO
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    struct sctp_sndinfo *sndinfo;
#else // SCTP_SNDINFO
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct sctp_sndrcvinfo *sndrcvinfo;
#endif // SCTP_SNDINFO
    iov.iov_base = (void *)buf;
    iov.iov_len = nbytes;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    cmsg = (struct cmsghdr *)cmsgbuf;
    cmsg->cmsg_level = IPPROTO_SCTP;
#ifdef SCTP_SNDINFO
    cmsg->cmsg_type = SCTP_SNDINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
    sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
    sndinfo->snd_sid = sid;
    sndinfo->snd_flags = 0;
#ifdef SCTP_EXPLICIT_EOR
    if ( use_eeor && eor )
	{
	sndinfo->snd_flags |= SCTP_EOR;
#ifdef SCTP_SACK_IMMEDIATELY
	sndinfo->snd_flags |= SCTP_SACK_IMMEDIATELY;
#endif // SCTP_SACK_IMMEDIATELY
	}
#endif // SCTP_EXPLICIT_EOR
    sndinfo->snd_ppid = htonl(ppid);
    sndinfo->snd_context = 0;
    sndinfo->snd_assoc_id = 0;
    msg.msg_control = cmsg;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo));
#else // SCTP_SNDINFO
    cmsg->cmsg_type = SCTP_SNDRCV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
    sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
    sndrcvinfo->sinfo_stream = sid;
    sndrcvinfo->sinfo_flags = 0;
#ifdef SCTP_EXPLICIT_EOR
    if ( use_eeor && eor )
	{
	sndrcvinfo->sinfo_flags |= SCTP_EOR;
#ifdef SCTP_SACK_IMMEDIATELY
	sndrcvinfo->sinfo_flags |= SCTP_SACK_IMMEDIATELY;
#endif // SCTP_SACK_IMMEDIATELY
	}
#endif // SCTP_EXPLICIT_EOR
    sndrcvinfo->sinfo_ppid = htonl(ppid);
    sndrcvinfo->sinfo_context = 0;
    sndrcvinfo->sinfo_timetolive = 0;
    sndrcvinfo->sinfo_assoc_id = 0;
    msg.msg_control = cmsg;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
#endif // SCTP_SNDINFO
    msg.msg_flags = 0;
    r = sendmsg( fd, &msg, 0 );
    return r;
}

/* Write the requested buffer completely, accounting for interruptions. */
ssize_t
httpd_write_fully_sctp( httpd_conn* hc , const char * buf, size_t nbytes,
                        int use_eeor, int eor, size_t send_at_once_limit )
    {
    size_t nwritten;
    size_t nwrite;

    nwritten = 0;
    while ( nwritten < nbytes )
	{
	ssize_t r;

	if ( nbytes - nwritten > send_at_once_limit )
	    {
	    nwrite = send_at_once_limit;
	    eor = 0;
	    }
	else
	    {
	    nwrite = nbytes - nwritten;
	    }

	r = httpd_write_sctp( hc->conn_fd, (void *)(buf + nwritten), nwrite, use_eeor, eor, 0, hc->sid );

	if ( r < 0 && ( errno == EINTR || errno == EAGAIN ) )
	    {
	    sleep( 1 );
	    continue;
	    }
	if ( r < 0 )
	    return r;
	if ( r == 0 )
	    break;
	nwritten += r;
	}

    return nwritten;
    }
#endif

/* Write the requested buffer completely, accounting for interruptions. */
ssize_t
httpd_write_fully( int fd, const char* buf, size_t nbytes )
    {
    size_t nwritten;

    nwritten = 0;
    while ( nwritten < nbytes )
	{
	ssize_t r;

	r = write( fd, buf + nwritten, nbytes - nwritten );
	if ( r < 0 && ( errno == EINTR || errno == EAGAIN ) )
	    {
	    sleep( 1 );
	    continue;
	    }
	if ( r < 0 )
	    return r;
	if ( r == 0 )
	    break;
	nwritten += r;
	}

    return nwritten;
    }


/* Send the buffered response in blocking / delay mode */
void
httpd_write_blk_response( httpd_conn* hc )
    {
    /* Set blocking I/O mode. */
    (void) httpd_set_nonblock( hc->conn_fd, SOPT_OFF );

	if ( hc->responselen > 0 )
	{
#ifdef USE_SCTP
	if ( hc->is_sctp )
	    (void) httpd_write_fully_sctp( hc, hc->response, hc->responselen,
					   hc->use_eeor, 1, hc->send_at_once_limit );
	else
	    (void) httpd_write_fully( hc->conn_fd, hc->response, hc->responselen );
#else
	(void) httpd_write_fully( hc->conn_fd, hc->response, hc->responselen );
#endif
	hc->responselen = 0;
	}
	}


/* Get non blocking I/O mode (SOPT_ON, SOPT_OFF) from a socket. */
int
httpd_get_nonblock( int fd, int *ponoff )
    {
    int flags;

    flags = fcntl( fd, F_GETFL, 0 );
    if ( flags != -1 )
	{
	*ponoff = ( (flags & O_NONBLOCK) ? SOPT_ON : SOPT_OFF );
	}
    return flags;
    }


/* Set non blocking I/O mode (SOPT_ON, SOPT_OFF) on a socket. */
int
httpd_set_nonblock( int fd, int onoff )
    {
    static const int vmode[SOPT_MAX] = { 0, O_NONBLOCK };
    int flags, newflags;

    flags = fcntl( fd, F_GETFL, 0 );
    if ( flags != -1 )
	{
	newflags = (int) ( ( flags & ~O_NONBLOCK ) | vmode[ onoff & SOPT_ON ] );
	if ( newflags != flags )
	    flags = fcntl( fd, F_SETFL, newflags );
	}
    return flags;
    }


/* Get TCP/IP no-nagle mode from a socket. */
int
httpd_get_nonagle( int fd, int *ponoff )
    {
#ifdef TCP_NODELAY
    int status;
    socklen_t sz = sizeof( *ponoff );

    *ponoff = 0;
    status = getsockopt( fd, SOL_TCP, TCP_NODELAY, ponoff, &sz );
    if ( status < 0 )
	syslog( LOG_CRIT, "getsockopt TCP_NODELAY - %m" );
    return status;
#else
    *ponoff = 0;
    return -2;
#endif
    }


/* Set TCP/IP no-nagle mode on a socket. */
int
httpd_set_nonagle( int fd, int onoff )
    {
#ifdef TCP_NODELAY
    int status;
    status = setsockopt( fd, SOL_TCP, TCP_NODELAY, (char*) &onoff, sizeof(onoff) );
    if ( status < 0 )
	syslog( LOG_CRIT, "setsockopt TCP_NODELAY %d - %m", onoff );
    return status;
#else
    return -2;
#endif
    }


/* Get TCP/IP cork mode from a socket. */
int
httpd_get_cork( int fd, int *ponoff )
    {
#ifdef TCP_CORK
    int status;
    socklen_t sz = sizeof( *ponoff );

    *ponoff = 0;
    status = getsockopt( fd, SOL_TCP, TCP_CORK, ponoff, &sz );
    if ( status < 0 )
	syslog( LOG_CRIT, "getsockopt TCP_CORK - %m" );
    return status;
#else
    *ponoff = 0;
    return -2;
#endif
    }


/* Set TCP/IP cork mode on a socket. */
int
httpd_set_cork( int fd, int onoff )
    {
#ifdef TCP_CORK
    int status;
    status = setsockopt( fd, SOL_TCP, TCP_CORK, (char*)&onoff, sizeof(onoff) );
    if ( status < 0 )
	syslog( LOG_CRIT, "setsockopt TCP_CORK %d - %m", onoff );
    return status;
#else
    return -2;
#endif
    }


/* return a string about available sendfile().
** NOTE: keep these #defines syncronized with those in httpd_sendfile().
*/
const char *
httpd_typeof_sendfile( void )
    {
#if defined(HAVE_BSD_SENDFILE)
    return "BSD";
#elif defined(HAVE_LINUX_SENDFILE)
    return "Linux";
#elif defined(HAVE_SOLARIS_SENDFILE)
    return "Solaris";
#elif defined(HAVE_SOLARIS_SENDFILEV)
    return "Solaris-v";
#else
    return "emulated";
#endif
    }


/* DO NOT TOUCH these values (unless you know what you do) */
#define MIN_SF_BLK_SIZE	4096		/* size of 1 RAM page */
#define MID_SF_BLK_SIZE	65536		/* default value (n RAM pages) */
#define MAX_SF_BLK_SIZE	4194304		/* reasonable upper limit */

/* max. block size for sendfile() */
#if MAX_SENDFILE_BLK_SIZE >= MIN_SF_BLK_SIZE && \
    MAX_SENDFILE_BLK_SIZE <= MAX_SF_BLK_SIZE
static size_t MaxSFBlkSize = MAX_SENDFILE_BLK_SIZE;
#else
static size_t MaxSFBlkSize = MID_SF_BLK_SIZE;
#endif /* MAX_SENDFILE_BLK_SIZE */


/* Get the current value of max. sendfile block size;
** returns the current value.
*/
size_t
httpd_get_sf_blksize( void )
    {
    return MaxSFBlkSize;
    }


/* Set the current value of max. sendfile block size
** and returns the new value of it which may have been
** corrected to fit in the predefined range.
** NOTE: a value of 0 means, set default value.
*/
size_t
httpd_set_sf_blksize( size_t max_sf_blksize )
    {
    if ( max_sf_blksize == 0 )
	 max_sf_blksize = MID_SF_BLK_SIZE;
    else
    if ( max_sf_blksize < MIN_SF_BLK_SIZE )
	 max_sf_blksize = MIN_SF_BLK_SIZE;
    else
    if ( max_sf_blksize > MAX_SF_BLK_SIZE )
	 max_sf_blksize = MAX_SF_BLK_SIZE;

    if ( ( max_sf_blksize % MIN_SF_BLK_SIZE ) != 0 )
	{
	/* round up to the next upper size */
	size_t nblk = ( max_sf_blksize / MIN_SF_BLK_SIZE ) + 1;
	max_sf_blksize = nblk * MIN_SF_BLK_SIZE;
	}

    MaxSFBlkSize = max_sf_blksize;

    return MaxSFBlkSize;
    }


/* Send "bytes" from "fdin" (input file) to "fdout" (output socket)
** starting at input file "offset".
** NOTE: if native implemementation of sendfile() does not work well
**       in non-blocking mode then use emulation by read() + write().
** NOTE: sending headers and content by separate system calls
**       can lead to a slow TCP/IP start;  this is not too bad
**       because we use sendfile() only for big files and
**       we are not in a hurry to send them.
** NOTE: limiting the size of data to send by each sendfile call,
**       helps avoiding an almost "blocking" call when
**       network is much faster than disk I/O
**       (i.e. in a fast LAN >= 100 Mbit or in a localhost).
*/
ssize_t
httpd_sendfile( int fdout, int fdin, off_t offset, size_t bytes )
    {
/*
** Max. block size for sendfile,
** it should be >= the size of output socket buffer.
*/
    /* Avoid nasty cases (such as in BSD) where
    ** a value of 0 may have special meaning (i.e. send whole file, etc.).
    */
    if ( bytes == 0 )
	 return 0;

    if ( bytes > MaxSFBlkSize )
	 bytes = MaxSFBlkSize;

    errno = 0;

#if defined(HAVE_BSD_SENDFILE)
    {
    /* We assume FreeBSD 3.1 or higher eventually patched (without bugs).
    ** NOTE: we don't send headers, thus we can safely ignore the
    **       differences between versions pre and post 4.6.
    ** NOTE: bytes should be always > 0 (we don't want to send the
    **       whole file in a single call if we send at Gigabit speed).
    */

    off_t sbytes = 0;

    /* int
    **   sendfile( int in_fd, int out_fd, off_t offset, size_t bytes,
    **             struct sf_hdtr *hdtr, off_t *sbytes, int flags );
    */
    if ( sendfile( fdin, fdout, offset, bytes, NULL, &sbytes, 0 ) == -1 )
	{
	if ( errno == EAGAIN && sbytes > 0 )
	    /* OK, partial write */
	    return sbytes;
	return -1;
	}
    else
    if ( sbytes == 0 )
	{
	/* EOF and / or this kernel is broken;
	** we don't want to deal with either cases,
	** eventually use emulated sendfile() or disable it at all.
	*/
	return -1;
	}

    return sbytes;
    }
#elif defined(HAVE_LINUX_SENDFILE)
    {
    /* We assume Linux 2.2.x or higher and glibc 2.1 or higher.
    ** NOTE: Linux 2.2.x has the big kernel lock,
    **       thus you may prefer the emulated version of sendfile()
    **       or even the mmap() method when serving many multiple downloads
    **       for the same big file.
    */

    off_t soffset = offset;

    /* ssize_t
    **     sendfile( int out_fd, int in_fd, off_t *offset, size_t bytes );
    */
    return sendfile( fdout, fdin, &soffset, bytes );
    }
#elif defined(HAVE_SOLARIS_SENDFILE)
    {
    /* We assume Solaris 8 or even previous versions (if patched).
    ** NOTE: eventually add -lsendfile to link options in Makefile.
    */

    off_t soffset = offset;

    /* ssize_t
    **     sendfile( int out_fd, int in_fd, off_t *offset, size_t bytes );
    */
    return sendfile( fdout, fdin, &soffset, bytes );
    }
#elif defined(HAVE_SOLARIS_SENDFILEV)
    {
    /* This syscall is used to emulate a missing sendfile();
    ** it is being available in SunOS since mid-2001.
    ** NOTE: eventually add -lsendfile to link options in Makefile.
    */

    ssize_t	status;
    size_t	xferred = 0;
    sendfilevec_t vec[1];
    vec[0].sfv_fd    = fdin;
    vec[0].sfv_flag  = 0;
    vec[0].sfv_off   = offset;
    vec[0].sfv_len   = bytes;

    /* ssize_t
    **     sendfilev( int out_fd, const sendfilevec_t *vec, int sfvcnt,
    **                size_t *xferred );
    */
    status = sendfilev( fdout, vec, 1, &xferred );

    /* NOTE: we never try to send more than ssize_t - 1 bytes. */
    if ( xferred > 0 )
	return (ssize_t) xferred;

    /* this might be an error */
    return status;
    }
#else
    {
# warning ------------------------------------------------------
# warning USING SLOW / EMULATED sendfile() !
# warning SEE: config.h to learn HOW to enable a NATIVE sendfile.
# warning ------------------------------------------------------

# define IO_BUFSIZE	8192	/* ideally it should be:
				**  (size of output socket buffer) -
				**   LOW_WATER_MARK;
				** it has to be greater than LOW_WATER_MARK;
				** 8192 should be fine for 8 KB - 64 KB
				** socket output buffer.
				*/
    char buf[IO_BUFSIZE];
    ssize_t nread;

    if ( lseek( fdin, offset, SEEK_SET) == -1 )
	return -1;

    /* read data */
    nread = read( fdin, buf, (bytes < IO_BUFSIZE) ? bytes : IO_BUFSIZE );
    if (nread <= 0)
	/* -1 or 0 */
	return nread;

    /* write it out */
    /* -1, 0, 1 - nread (a partial write is OK) */
    return write( fdout, buf, nread );

# undef IO_BUFSIZE
    }
#endif /* SENDFILE */
    }


/* Append "allowed methods" HTTP header to response string */
static void
add_allowed_methods( httpd_conn* hc )
    {
	/* this should happen only for 405 and 501 error responses */
	struct s_allm_headers
	    {
		const char *str;
		const int   len;
	    };
	/* NOTE: C ANSI compiler required ! */
#define ALLOW_STR	"Allow: "
#define ALLOW_LEN	7
#define ALLOW_REC(s1)	\
	ALLOW_STR s1 HTTP_CRLF_STR,	\
	(ALLOW_LEN + SZLEN(s1) + HTTP_CRLF_LEN)

#define MAX_ALLOW_METHODS_LEN	( ALLOW_LEN + 16 + HTTP_CRLF_LEN )

	static struct s_allm_headers allowed_methods_tab[] =
	    {
		{    ALLOW_REC("?")		},
		{    ALLOW_REC("GET")		},
		{    ALLOW_REC("HEAD")		},
		{    ALLOW_REC("GET, HEAD")	},
		{    ALLOW_REC("POST")		},
		{    ALLOW_REC("GET, POST")	},
		{    ALLOW_REC("HEAD, POST")	},
		{    ALLOW_REC("GET, HEAD, POST")	}
		};

	struct s_allm_headers *pam =
		&allowed_methods_tab[ hc->allowed_methods &
		( METHOD_ID2BIT(METHOD_GET) |
		  METHOD_ID2BIT(METHOD_HEAD) |
		  METHOD_ID2BIT(METHOD_POST) ) ];

	add_responselen( hc, pam->str, pam->len );

#undef  ALLOW_STR
#undef  ALLOW_REC
    }


static void
send_mime( httpd_conn* hc, int status, const char* title, int titlelen,
	const char* extraheads, int length, time_t mod )
    {
    static time_t nowtime;
    static time_t modtime;
#ifdef USE_EXPIRES
    static time_t exptime;
#endif /* USE_EXPIRES */
    int         resplen = 0;
    int         extraheads_len = 0;
    static int  nowbuflen;
    static int  modbuflen;
#ifdef USE_EXPIRES
    static int  expbuflen;
#endif /* USE_EXPIRES */
    static char nowbuf[64];
    static char modbuf[64];
#ifdef USE_EXPIRES
    static char expbuf[64];
#endif /* USE_EXPIRES */


#ifdef SMF_DEBUG
    if ( hc->responselen != 0 )
	{
	syslog( LOG_ERR, "send_mime: responselen %d != 0 (maxresponse %d)",
		hc->responselen,
		hc->maxresponse
		);
	exit( 98 );
	}
    if ( hc->response == (char*) 0 )
	{
	syslog( LOG_ERR, "send_mime: response NULL" );
	exit( 98 );
	}
#endif	/* SMF_DEBUG */

    if ( extraheads && extraheads[0] != '\0' )
	extraheads_len = (int) strlen( extraheads );

    hc->status = status;
    hc->bytes_to_send = length;

    if ( hc->mime_flag == 0 )
	return;

	/* HTTP headers are allowed */

	if ( status == 200 && hc->got_range && length > 0 &&
	     ( hc->end_byte_loc >= hc->init_byte_loc ) &&
	     ( hc->init_byte_loc >= 0 ) &&
	     ( ( hc->end_byte_loc != length - 1 ) ||
	       ( hc->init_byte_loc != 0 ) ) &&
	     ( hc->range_if == (time_t) -1 ||
	       hc->range_if == hc->sb.st_mtime ) )
	    {
	    /* partial_content = 1, hc->got_range == 1 */
	    hc->status = status = 206;
	    title    = ok206title;
	    titlelen = ok206titlelen;
	    }
	else if ( hc->got_range != 0 )
	    {
	    /* partial_content = 0, disable got_range */
	    hc->got_range = 0;
	    }

	/* Date and Last-Modified values.
	** "Last-Modified:" value must be <= "Date:" value.
	** NOTE: for now thttpd violates RFC (it should also be mod <= now)
	**       but this is justified by the side effects of this issue.
	*/

	if ( mod == (time_t) 0 )
	    mod = hc->hs->nowtime;

	if ( nowtime != hc->hs->nowtime )
	    {
	    nowtime = hc->hs->nowtime;
	    nowbuflen = fmt_rfc1123_time( nowbuf, sizeof(nowbuf), nowtime );
	    }

	if ( modtime != mod )
	    {
	    modtime = mod;
	    modbuflen = fmt_rfc1123_time( modbuf, sizeof(modbuf), modtime );
	    }

	resplen = hc->protocol_len + 16 + titlelen +
		  8 + 20 + HTTP_CRLF_LEN * 3 + SZLEN(EXPOSED_SERVER_SOFTWARE) +
		 30 + nowbuflen + modbuflen +
		 hc->type_len + 14 + HTTP_CRLF_LEN +
		 18 + HTTP_CRLF_LEN + hc->encodings_len + extraheads_len +
		 22 + HTTP_CRLF_LEN * 2 +	/* Connection: */
	        (16 + HTTP_CRLF_LEN + 1 * 11 * ( sizeof(long) / 4 )) +/*Length*/
	        (23 + HTTP_CRLF_LEN + 3 * 11 * ( sizeof(long) / 4 )) +/*Range*/
	        (23 + HTTP_CRLF_LEN + 1 * 11 * ( sizeof(long) / 4 )) +/*Cache*/
#ifdef USE_EXPIRES
	        ( 9 + HTTP_CRLF_LEN + 30 ) +		/* Expires */
#endif /* USE_EXPIRES */
		MAX_ALLOW_METHODS_LEN +			/* Allow: methods */
		(22 + HTTP_CRLF_LEN * 2);		/* Connection: */

	alloc_responselen_M( hc, resplen );

	/* NOTE: protocol length is already limited to max. 12 characters
	**       by httpd_parse_request().
	*/

	add_responselen_M( hc, hc->protocol, hc->protocol_len );
	add_responseCHR_M( hc, ' ' );
	add_responseULong10_M( hc, (unsigned long) status );
	add_responseCHR_M( hc, ' ' );
	add_responselen_M( hc, title, titlelen );

	add_responselen_M( hc,                     HTTP_CRLF_STR	\
		"Server: " EXPOSED_SERVER_SOFTWARE HTTP_CRLF_STR	\
		"Accept-Ranges: bytes"             HTTP_CRLF_STR,	\
		( HTTP_CRLF_LEN + 8 + \
		SZLEN(EXPOSED_SERVER_SOFTWARE) + HTTP_CRLF_LEN +	\
		20 + HTTP_CRLF_LEN ) );

	add_responselen_M( hc, "Date: ", 6 );
	add_responselen_M( hc, nowbuf, nowbuflen );
	add_responseCRLF_M( hc );

	add_responselen_M( hc, "Last-Modified: ", 15 );
	add_responselen_M( hc, modbuf, modbuflen );
	add_responseCRLF_M( hc );

	if ( hc->type_len > 0 )
	    {	/* length has already been added above */
	    add_responselen_M( hc, "Content-Type: ", 14 );
	    add_responselen_M( hc, hc->type, hc->type_len );
	    add_responseCRLF_M( hc );
	    }

	if ( hc->encodings_len > 0 )
	    {	/* length has already been added above */
	    add_responselen_M( hc, "Content-Encoding: ", 18 );
	    add_responselen_M( hc, hc->encodings, hc->encodings_len );
	    add_responseCRLF_M( hc );
	    }

	if ( hc->got_range )
	    {	/* length > 0 */
	    /* length has already been added above */
	    add_responselen_M( hc, "Content-Length: ", 16 );
	    add_responseULong10_M( hc, (unsigned long)
		( hc->end_byte_loc - hc->init_byte_loc + 1 ) );
	    add_responseCRLF_M( hc );

	    /* length has already been added above */
	    add_responselen_M( hc, "Content-Range: bytes ", 21 );
	    add_responseULong10_M( hc, (unsigned long) hc->init_byte_loc );
	    add_responseCHR_M( hc, '-' );
	    add_responseULong10_M( hc, (unsigned long) hc->end_byte_loc );
	    add_responseCHR_M( hc, '/' );
	    add_responseULong10_M( hc, (unsigned long) length );
	    add_responseCRLF_M( hc );
	    }
	else if ( length >= 0 )
	    {
	    /* length has already been added above */
	    add_responselen_M( hc, "Content-Length: ", 16 );
	    add_responseULong10_M( hc, (unsigned long) length );
	    add_responseCRLF_M( hc );
	    }
	else
	    {
	    if ( status == 416 )
		{	/* infrequent error response */
		unsigned long maxlength = (unsigned long) ( hc->sb.st_size );
		/* length has already been added above */
		add_responselen_M( hc, "Content-Range: bytes */", 23 );
		add_responseULong10_M( hc, (unsigned long) maxlength );
		add_responseCRLF_M( hc );
		}
	    if ( hc->do_keep_alive &&
		  hc->method != METHOD_HEAD &&
		  status != 304 && status != 204 &&
		( status < 100 || status > 199 ) )
		{	/* unknown length (-1), close connection */
		hc->do_keep_alive = 0;
		}
	    }

	if ( hc->hs->max_age >= 0 &&
	     ( status == 200 || status == 304 ) )
	    {
	    /* for now, send cache-control header also to HTTP/1.0 clients,
	    ** because some of them understand HTTP/1.1 headers too.
	    */
	    /* length has already been added above */
	    add_responselen_M( hc, "Cache-Control: max-age=", 23 );
	    add_responseULong10_M( hc, (unsigned long) hc->hs->max_age );
	    add_responseCRLF_M( hc );

#ifdef USE_EXPIRES
	    if ( !hc->one_one )
		{
		if ( exptime != nowtime + hc->hs->max_age )
		    {
		    exptime = nowtime + hc->hs->max_age;
		    expbuflen =
			fmt_rfc1123_time( expbuf, sizeof(expbuf), exptime );
		    }
		/* length has already been added above */
		add_responselen_M( hc, "Expires: ", 9 );
		add_responselen_M( hc, expbuf, expbuflen );
		add_responseCRLF_M( hc );
		}
#endif /* USE_EXPIRES */
	    }

	if ( hc->allowed_methods != METHOD_UNKNOWN )
	    /* this should happen only for 405 and 501 error responses */
	    add_allowed_methods( hc );

	if ( extraheads_len > 0 )
	    add_responselen( hc, extraheads, extraheads_len );

	/* Connection + EOH: End of HTTP headers,
	** length has already been added above.
	*/
	if ( hc->do_keep_alive )
	    add_responselen_M( hc, "Connection: Keep-Alive"
				HTTP_CRLF_STR HTTP_CRLF_STR,
				(22 + HTTP_CRLF_LEN * 2) );
	else
	    add_responselen_M( hc, "Connection: close"
				HTTP_CRLF_STR HTTP_CRLF_STR,
				(17 + HTTP_CRLF_LEN * 2) );
    }


#ifdef DO_ALLOC_STATS
static int str_alloc_count = 0;
static long str_alloc_size = 0;
#endif

void
httpd_realloc_str( char** strP, int* maxsizeP, int size )
    {
    if ( *maxsizeP <= 0 )
	{
	*maxsizeP = MAX( size, 60 );
	*strP = NEW( char, *maxsizeP + 4 );
#ifdef DO_ALLOC_STATS
	++str_alloc_count;
	str_alloc_size += *maxsizeP;
#endif
	}
    else if ( size > *maxsizeP )
	{
	char *ptr = *strP;
#ifdef DO_ALLOC_STATS
	str_alloc_size -= *maxsizeP;
#endif
	if ( size <= *maxsizeP * 2 )
	    *maxsizeP *= 2;
	else
	    *maxsizeP = size + size / 4;
	*strP = RENEW( ptr, char, *maxsizeP + 4 );
#ifdef DO_ALLOC_STATS
	str_alloc_size += *maxsizeP;
#endif
	}
    else
	return;
    if ( *strP == (char*) 0 )
	{
	syslog(
	    LOG_ERR, "out of memory reallocating a string to %d bytes",
	    *maxsizeP );
	exit( 102 );
	}
    }


static void
send_response( httpd_conn* hc, int status, char* title, int titlelen,
		char* extraheads, char* form, const char* arg )
    {
    int  headers_len = 0;
    char buf[1024];

    hc->encodings[0]  = '\0';
    hc->encodings_len = 0;

    if ( form == (char*) 0 )
	{    /* don't send any body content */
	hc->type     = "";
	hc->type_len = 0;
	send_mime( hc, status, title, titlelen, extraheads, -1, (time_t) 0 );
	return;
	}

    /* Allocate / reserve enough memory space.
    ** NOTE: pad message line must be shorter than 128 (see below).
    */
    alloc_maxresponse_M( hc, ( 512 + 252 ) );

    hc->type     =       MIME_TYPE_TEXT_HTML;
    hc->type_len = SZLEN(MIME_TYPE_TEXT_HTML);

    headers_len = hc->responselen;

#define MY_HTML_STR1	"\
<HTML>\n\
<HEAD><TITLE>"

#define MY_HTML_STR2	"\
</TITLE></HEAD>\n\
<BODY BGCOLOR=\"#cc9999\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
<H2>"

#define MY_HTML_STR3	"\
</H2>\n"

    add_responselen_M( hc, MY_HTML_STR1, SZLEN( MY_HTML_STR1 ) );
    add_responseULong10_M( hc, (unsigned long) status );
    add_responseCHR_M( hc, ' ' );
    add_responselen_M( hc, title, titlelen );
    add_responselen_M( hc, MY_HTML_STR2, SZLEN( MY_HTML_STR2 ) );
    add_responseULong10_M( hc, (unsigned long) status );
    add_responseCHR_M( hc, ' ' );
    add_responselen_M( hc, title, titlelen );
    add_responselen_M( hc, MY_HTML_STR3, SZLEN( MY_HTML_STR3 ) );

#undef  MY_HTML_STR3
#undef  MY_HTML_STR2
#undef  MY_HTML_STR1

    if ( *form != '\0' )
	{
	char defanged_arg[256];

	buf[0] = '\0';
	defanged_arg[0] = '\0';

	if ( need_defang( arg ) )
	    {
	    defang( arg, defanged_arg, sizeof(defanged_arg) - 4 );
	    (void) my_snprintf( buf, sizeof( buf ), form, defanged_arg );
	    }
	else
	    {
	    (void) my_snprintf( buf, sizeof( buf ), form, arg );
	    }
	buf[sizeof(buf)-1] = '\0';
	add_response( hc, buf );
	}

    send_response_tail( hc, headers_len );

    memcpy(buf, hc->response, hc->responselen);
    int buflen = hc->responselen;
    buf[buflen] = '\0';
    hc->responselen = 0;
    send_mime( hc, status, title, titlelen, extraheads, buflen, (time_t) 0 );
    add_response(hc, buf);

    }


static void
send_response_tail( httpd_conn* hc, int headers_len )
    {

    /* NOTE: C ANSI required for string concatenation */
#ifdef ERR_HREF_SERVER_ADDRESS

#define MY_TAIL_MSG	"\
<HR>\n\
<ADDRESS>Server: <A HREF=\"" SERVER_ADDRESS "\">" EXPOSED_SERVER_SOFTWARE \
"</A></ADDRESS>\n"

    add_responselen( hc, MY_TAIL_MSG, SZLEN(MY_TAIL_MSG) );

#undef MY_TAIL_MSG

#else

#define MY_TAIL_MSG	"\
<HR>\n\
<ADDRESS>Server: " EXPOSED_SERVER_SOFTWARE "</ADDRESS>\n"

    add_responselen( hc, MY_TAIL_MSG, SZLEN(MY_TAIL_MSG) );

#undef MY_TAIL_MSG

#endif /* ERR_HREF_SERVER_ADDRESS */

#define MY_END_MSG	"\
</BODY>\n\
</HTML>\n"

#ifdef ERR_PAD_MSIE
    {
    int minresplen = headers_len + 512 - SZLEN(MY_END_MSG) + 1;

    if ( hc->responselen <= minresplen &&
	match( "**MSIE**", hc->useragent ) )
	{
	add_responselen( hc, "<!--\n", 5 );
	/* subtract start + end comment */
	minresplen -= 5 + 4;
	while ( hc->responselen < minresplen )
	    {
#define MY_PAD_MSG	\
"Padding so that MSIE deigns to show this error instead of its own canned one.\n"
	    add_responselen( hc, MY_PAD_MSG, SZLEN(MY_PAD_MSG) );
#undef MY_PAD_MSG
	    }
	add_responselen( hc, "-->\n", 4 );
	}
    }
#endif /* ERR_PAD_MSIE */

    add_responselen( hc, MY_END_MSG, SZLEN(MY_END_MSG) );

#undef MY_END_MSG
    }


/*
** Check if argument needs to be escaped.
** return TRUE/FALSE.
*/
static int
need_defang( const char* str )
    {
    if ( str == (char*) 0 )
	return 0;
    /* '-' should not be needed, ' ' may be added if desired.
    ** Keep character list in sync with defang().
    */
    return( strpbrk( str, "<>&\"" ) != (char*) 0 );
    }


/*
** Escape main HTML entities and return length of defanged argument.
*/
static void
defang( const char* str, char* dfstr, int dfsize )
    {
    const char* cp1;
    char* cp2;
    char* cp3;

    for ( cp1 = str, cp2 = dfstr, cp3 = &dfstr[dfsize - 8];
	  cp2 < cp3 && *cp1 != '\0';
	  ++cp1, ++cp2 )
	{
	/* '-' should not be needed, ' ' may be added if desidered.
	** Keep escaped character list in sync with need_defang().
	*/
	switch ( *cp1 )
	    {
	    case '<':
	    *cp2++ = '&';
	    *cp2++ = 'l';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;

	    case '>':
	    *cp2++ = '&';
	    *cp2++ = 'g';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;

	    case '&':
	    *cp2++ = '&';
	    *cp2++ = 'a';
	    *cp2++ = 'm';
	    *cp2++ = 'p';
	    *cp2 = ';';
	    break;

	    case '"':
	    *cp2++ = '&';
	    *cp2++ = 'q';
	    *cp2++ = 'u';
	    *cp2++ = 'o';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;

	    default:
	    *cp2 = *cp1;
	    break;
	    }
	}
    *cp2 = '\0';

    return;
    }


char*
httpd_err_title( int status )
    {
    char* title = "";
    static char errbuf[64];

    switch( status )
	{
	case 200: title = ok200title; break;
	case 206: title = ok206title; break;
	case 302: title = err302title; break;
	case 304: title = err304title; break;
	case 400: title = err400title; break;
#ifdef AUTH_FILE
	case 401: title = err401title; break;
#endif /* AUTH_FILE */
	case 403: title = err403title; break;
	case 404: title = err404title; break;
	case 405: title = err405title; break;
	case 408: title = err408title; break;
	case 413: title = err413title; break;
	case 414: title = err414title; break;
	case 416: title = err416title; break;
	case 500: title = err500title; break;
	case 501: title = err501title; break;
	case 503: title = err503title; break;
	case 505: title = err505title; break;
	default:
	    errbuf[0] = '\0';
	    (void) my_snprintf( errbuf, sizeof( errbuf ),
			"Error %d (unknown)", status );
	    title = errbuf;
	    break;
	}
    return title;
    }


int
httpd_err_titlelen( int status )
    {
    int titlelen = 0;

    switch( status )
	{
	case 200: titlelen = ok200titlelen; break;
	case 206: titlelen = ok206titlelen; break;
	case 302: titlelen = err302titlelen; break;
	case 304: titlelen = err304titlelen; break;
	case 400: titlelen = err400titlelen; break;
#ifdef AUTH_FILE
	case 401: titlelen = err401titlelen; break;
#endif /* AUTH_FILE */
	case 403: titlelen = err403titlelen; break;
	case 404: titlelen = err404titlelen; break;
	case 405: titlelen = err405titlelen; break;
	case 408: titlelen = err408titlelen; break;
	case 413: titlelen = err413titlelen; break;
	case 414: titlelen = err414titlelen; break;
	case 416: titlelen = err416titlelen; break;
	case 500: titlelen = err500titlelen; break;
	case 501: titlelen = err501titlelen; break;
	case 503: titlelen = err503titlelen; break;
	case 505: titlelen = err505titlelen; break;
	default:
	    {
	    char errbuf[64];
	    errbuf[0] = '\0';
	    (void) my_snprintf( errbuf, sizeof(errbuf),
			"Error %d (unknown)", status );
	    titlelen = (int) strlen( errbuf );
	    }
	    break;
	}
    return titlelen;
    }


char*
httpd_err_form( int status )
    {
    char* form = "";
    static char formbuf[64];

    switch( status )
	{
	case 200: form = ok200title; break;
	case 206: form = ok206title; break;
	case 302: form = err302form; break;
	case 304: form = err304title; break;
	case 400: form = err400form; break;
#ifdef AUTH_FILE
	case 401: form = err401form; break;
#endif /* AUTH_FILE */
	case 403: form = err403form; break;
	case 404: form = err404form; break;
	case 405: form = err405form; break;
	case 408: form = err408form; break;
	case 413: form = err413form; break;
	case 414: form = err414form; break;
	case 416: form = err416form; break;
	case 500: form = err500form; break;
	case 501: form = err501form; break;
	case 503: form = err503form; break;
	case 505: form = err505form; break;
	default:
	    formbuf[0] = '\0';
	    (void) my_snprintf( formbuf, sizeof(formbuf),
			"Error %d (unknown)", status );
	    form = formbuf;
	    break;
	}
    return form;
    }


void
httpd_send_err( httpd_conn* hc, int status, char* title, int titlelen,
		 char* extraheads, char* form, const char* arg )
    {
#if defined(ERR_DIR) || defined(ERR_VHOST_DIR)
    char filename[1000];
#endif

    /* Be sure to disable keep alive because
    ** the connection will be closed anyway.
    */
    /* if ( hc->do_keep_alive )
	hc->do_keep_alive = 0; */

    /* These tests should work also for HTTP/0.9 because
    ** it has only GET method without any headers,
    ** thus server never replies with status 304, 204, etc.
    */
    if ( form == (char*) 0 ||
	hc->method == METHOD_HEAD ||
	( status == 304 || status == 204 ||
	( status >= 100 && status <= 199 ) ) )
	{   /* no body content */
	send_response( hc, status, title, titlelen, extraheads, (char*) 0, "" );
	return;
	}

#ifdef ERR_VHOST_DIR
    /* Try virtual host error page. */
    if ( hc->hs->vhost && hc->hostdir[0] != '\0' )
	{
	(void) my_snprintf( filename, sizeof(filename),
	    "%s/%s/err%d.html", hc->hostdir, ERR_VHOST_DIR, status );
	if ( send_err_file( hc, status, title, titlelen,
		extraheads, filename ) )
	    return;
	}
#endif /* ERR_VHOST_DIR */

#ifdef ERR_DIR
    /* Try server-wide error page. */
    (void) my_snprintf( filename, sizeof(filename),
	"%s/err%d.html", ERR_DIR, status );
    if ( send_err_file( hc, status, title, titlelen, extraheads, filename ) )
	return;
    /* Fall back on built-in error page. */
#endif /* ERR_DIR */

    send_response( hc, status, title, titlelen, extraheads, form, arg );
    }


#if defined(ERR_DIR) || defined(ERR_VHOST_DIR)
/*
** NOTE: administrator should fill error files with at least 512 bytes,
**        see MSIE padding.
*/
static int
send_err_file( httpd_conn* hc, int status, char* title, int titlelen,
		char* extraheads, char* filename )
    {
    FILE* fp;
    char buf[2048+sizeof(long)];
    int r;
    int headers_len = 0;

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	return 0;

    hc->encodings[0]  = '\0';
    hc->encodings_len = 0;
    hc->type     =       MIME_TYPE_TEXT_HTML;
    hc->type_len = SZLEN(MIME_TYPE_TEXT_HTML);
    send_mime( hc, status, title, titlelen, extraheads, -1, (time_t) 0 );
    headers_len = hc->responselen;

    for (;;)
	{
	buf[0] = '\0';
	r = fread( buf, 1, sizeof(buf) - sizeof(long), fp );
	if ( r <= 0 )
	    break;
	buf[r] = '\0';
	add_responselen( hc, buf, r );
	/* we don't want to send big error files */
	break;
	}
    (void) fclose( fp );

#ifdef ERR_APPEND_SERVER_INFO
    send_response_tail( hc, headers_len );
#endif /* ERR_APPEND_SERVER_INFO */

    return 1;
    }
#endif /* ERR_DIR || ERR_VHOST_DIR */


static void
httpd_send_err405( httpd_conn* hc, int allowed_methods, const char* method_str )
    {
    /* methods mask, i.e.: METHOD_ID2BIT(METHOD_GET) | ... */
    hc->allowed_methods = allowed_methods;
    httpd_send_err( hc, 405, err405title, err405titlelen, "", err405form,
	method_str );
    }


static void
httpd_send_err501( httpd_conn* hc, const char* method_str )
    {
    hc->allowed_methods =
	METHOD_ID2BIT(METHOD_GET)
	| METHOD_ID2BIT(METHOD_HEAD)
#ifdef EXECUTE_CGI
	| METHOD_ID2BIT(METHOD_POST)
#endif /* EXECUTE_CGI */
	;
    httpd_send_err( hc, 501, err501title, err501titlelen, "", err501form,
	method_str );
    }


#ifdef AUTH_FILE

static void
send_authenticate( httpd_conn* hc, char* realm )
    {
    static char* header;
    static int maxheader = 0;
    static char headstr[] = "WWW-Authenticate: Basic realm=\"";

    httpd_realloc_str(
	&header, &maxheader, sizeof(headstr) + strlen( realm ) + 3 );
    (void) my_snprintf( header, maxheader, "%s%s\"" HTTP_CRLF_STR,
		headstr, realm );
    httpd_send_err( hc, 401, err401title, err401titlelen,
	header, err401form, hc->encodedurl );
    /* If the request was a POST then there might still be data to be read,
    ** so we need to do a lingering close.
    */
    if ( hc->method == METHOD_POST )
	hc->should_linger = 1;
    }


/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

static const int b64_decode_tab[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
static int
b64_decode( const char* str, unsigned char* space, int size )
    {
    const char* cp;
    int space_idx, phase;
    int d, prev_d = 0;
    unsigned char c;

    space_idx = 0;
    phase = 0;
    for ( cp = str; *cp != '\0'; ++cp )
	{
	d = b64_decode_tab[(int) *cp];
	if ( d != -1 )
	    {
	    switch ( phase )
		{
		case 0:
		++phase;
		break;
		case 1:
		c = ( ( prev_d << 2 ) | ( ( d & 0x30 ) >> 4 ) );
		if ( space_idx < size )
		    space[space_idx++] = c;
		++phase;
		break;
		case 2:
		c = ( ( ( prev_d & 0xf ) << 4 ) | ( ( d & 0x3c ) >> 2 ) );
		if ( space_idx < size )
		    space[space_idx++] = c;
		++phase;
		break;
		case 3:
		c = ( ( ( prev_d & 0x03 ) << 6 ) | d );
		if ( space_idx < size )
		    space[space_idx++] = c;
		phase = 0;
		break;
		}
	    prev_d = d;
	    }
	}
    return space_idx;
    }


/* Returns -1 == unauthorized, 0 == no auth file, 1 = authorized. */
static int
auth_check( httpd_conn* hc, char* dirname  )
    {
    if ( hc->hs->global_passwd )
	{
	char* topdir;
	if ( hc->hs->vhost && hc->hostdir[0] != '\0' )
	    topdir = hc->hostdir;
	else
	    topdir = ".";
	switch ( auth_check2( hc, topdir ) )
	    {
	    case -1:
	    return -1;
	    case 1:
	    return 1;
	    }
	}
    return auth_check2( hc, dirname );
    }


/* Returns -1 == unauthorized, 0 == no auth file, 1 = authorized. */
static int
auth_check2( httpd_conn* hc, char* dirname  )
    {
    static char* authpath;
    static int maxauthpath = 0;
    struct stat sb;
    char authinfo[500];
    char* authpass;
    char* colon;
    int l;
    FILE* fp;
    char line[500];
    char* cryp;
    static char* prevauthpath;
    static int maxprevauthpath = 0;
    static time_t prevmtime;
    static char* prevuser;
    static int maxprevuser = 0;
    static char* prevcryp;
    static int maxprevcryp = 0;

    /* Construct auth filename. */
    httpd_realloc_str(
	&authpath, &maxauthpath, strlen( dirname ) + 1 + sizeof(AUTH_FILE) );
    (void) my_snprintf( authpath, maxauthpath, "%s/%s", dirname, AUTH_FILE );

    /* Does this directory have an auth file? */
    if ( stat( authpath, &sb ) < 0 )
	/* Nope, let the request go through. */
	return 0;

    /* Does this request contain basic authorization info? */
    if ( hc->authorization[0] == '\0' ||
	 strncmp( hc->authorization, "Basic ", 6 ) != 0 )
	{
	/* Nope, return a 401 Unauthorized. */
	send_authenticate( hc, dirname );
	return -1;
	}

    /* Decode it. */
    l = b64_decode(
	&(hc->authorization[6]), (unsigned char*) authinfo,
	sizeof(authinfo) - 1 );
    authinfo[l] = '\0';
    /* Split into user and password. */
    authpass = strchr( authinfo, ':' );
    if ( authpass == (char*) 0 )
	{
	/* No colon?  Bogus auth info. */
	send_authenticate( hc, dirname );
	return -1;
	}
    *authpass++ = '\0';
    /* If there are more fields, cut them off. */
    colon = strchr( authpass, ':' );
    if ( colon != (char*) 0 )
	*colon = '\0';

    /* See if we have a cached entry and can use it. */
    if ( maxprevauthpath != 0 &&
	 strcmp( authpath, prevauthpath ) == 0 &&
	 sb.st_mtime == prevmtime &&
	 strcmp( authinfo, prevuser ) == 0 )
	{
	/* Yes.  Check against the cached encrypted password. */
	if ( strcmp( crypt( authpass, prevcryp ), prevcryp ) == 0 )
	    {
	    /* Ok! */
	    httpd_realloc_str(
		&hc->remoteuser, &hc->maxremoteuser, strlen( authinfo ) );
	    (void) strcpy( hc->remoteuser, authinfo );
	    return 1;
	    }
	else
	    {
	    /* No. */
	    send_authenticate( hc, dirname );
	    return -1;
	    }
	}

    /* Open the password file. */
    fp = fopen( authpath, "r" );
    if ( fp == (FILE*) 0 )
	{
	/* The file exists but we can't open it?  Disallow access. */
	syslog(
	    LOG_ERR, "%.80s auth file %.80s could not be opened - %m",
	    httpd_ntoa( &hc->client_addr ), authpath );
	httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' is protected by an authentication file, but the authentication file cannot be opened.\n" ),
	    hc->encodedurl );
	return -1;
	}

    /* Read it. */
    while ( fgets( line, sizeof(line), fp ) != (char*) 0 )
	{
	/* Nuke newline. */
	l = strlen( line );
	while( l > 0 && ( line[--l] == '\r' || line[l] == '\n' ) )
	    line[l] = '\0';
	/* Split into user and encrypted password. */
	cryp = strchr( line, ':' );
	if ( cryp == (char*) 0 )
	    continue;
	*cryp++ = '\0';
	/* Is this the right user? */
	if ( strcmp( line, authinfo ) == 0 )
	    {
	    /* Yes. */
	    (void) fclose( fp );
	    /* So is the password right? */
	    if ( strcmp( crypt( authpass, cryp ), cryp ) == 0 )
		{
		/* Ok! */
		httpd_realloc_str(
		    &hc->remoteuser, &hc->maxremoteuser, strlen( line ) );
		(void) strcpy( hc->remoteuser, line );
		/* And cache this user's info for next time. */
		httpd_realloc_str(
		    &prevauthpath, &maxprevauthpath, strlen( authpath ) );
		(void) strcpy( prevauthpath, authpath );
		prevmtime = sb.st_mtime;
		httpd_realloc_str(
		    &prevuser, &maxprevuser, strlen( authinfo ) );
		(void) strcpy( prevuser, authinfo );
		httpd_realloc_str( &prevcryp, &maxprevcryp, strlen( cryp ) );
		(void) strcpy( prevcryp, cryp );
		return 1;
		}
	    else
		{
		/* No. */
		send_authenticate( hc, dirname );
		return -1;
		}
	    }
	}

    /* Didn't find that user.  Access denied. */
    (void) fclose( fp );
    send_authenticate( hc, dirname );
    return -1;
    }

#endif /* AUTH_FILE */


static void
send_redirect( httpd_conn* hc, char *encodedurl, size_t url_len )
    {
    static char* header;
    static int maxheader = 0;
#define Headstr		"Location: "
#define Headstr_len	10

    if ( encodedurl == ((char *) 0) || *encodedurl == '\0' )
	{
	encodedurl = hc->encodedurl;
	url_len = strlen( encodedurl );
	}
    httpd_realloc_str(
	&header, &maxheader,
	(int) ( url_len + ( Headstr_len + HTTP_CRLF_LEN ) ) );
    memcpy( header, Headstr, Headstr_len );
    memcpy( &header[Headstr_len], encodedurl, url_len );
    memcpy( &header[Headstr_len + url_len], HTTP_CRLF_STR, HTTP_CRLF_LEN + 1 );

    /* be sure to disable keep alive because */
    /* the connection will be closed anyway */
    hc->do_keep_alive = 0;
    send_response( hc, 302, err302title, err302titlelen,
		header, err302form, encodedurl );
#undef  Headstr
#undef  Headstr_len
    }


/* Redirect an URL, which resolves to a directory name,
** appending a slash to the end of directory name and preserving
** CGI-style query string (surely there is no pathinfo).
*/
static void
send_dirredirect( httpd_conn* hc )
    {
    static char* location;
    static int maxlocation = 0;
    size_t url_len;
    char* cp;

    url_len = strlen( hc->encodedurl );
    httpd_realloc_str( &location, &maxlocation, url_len + 2 );
    cp = strchr( hc->encodedurl, '?' );
    if ( cp != (char*) 0 )
	{
	size_t idxslash = (size_t) ( cp - hc->encodedurl );
	if ( idxslash != 0 )
	    memcpy( location, hc->encodedurl, idxslash );
	location[idxslash++] = '/';
	strcpy( &location[idxslash], cp );
	url_len++;
	}
    else
	{
	strcpy( location, hc->encodedurl );
	location[url_len++] = '/';
	location[url_len]   = '\0';
	}
    send_redirect( hc, location, url_len );
    }


typedef struct httpd_method_entry
    {
    const int   method_id;
    const char *method_str;
    } httpd_method_entry;

static const httpd_method_entry httpd_methods_tab[NR_METHODS+1] =
    {
    {	METHOD_UNKNOWN,	"UNKNOWN"	},
    {	METHOD_GET,	"GET"		},
    {	METHOD_HEAD,	"HEAD"		},
    {	METHOD_POST,	"POST"		},
    {	METHOD_OPTIONS,	"OPTIONS"	},
    {	METHOD_PUT,	"PUT"		},
    {	METHOD_DELETE,	"DELETE"	},
    {	METHOD_TRACE,	"TRACE"		},
    {	METHOD_CONNECT,	"CONNECT"	},
    {	METHOD_UNKNOWN,	"UNKNOWN"	}
    };

#define HTTPD_METHOD_STR(method)	httpd_methods_tab[(method)].method_str

const char*
httpd_method_str( int method )
    {
    if ( method <  0 ||
	 method >= NR_METHODS )
	method = METHOD_UNKNOWN;
    return HTTPD_METHOD_STR(method);
    }


static inline int
get_method_id( char* method_str )
    {
    int i = METHOD_UNKNOWN;
    while ( ++i < NR_METHODS &&
	strcasecmp( method_str, httpd_methods_tab[i].method_str ) != 0 )
	;
    /* TRICK: first and last element (NR_METHODS) in array */
    /*        are set to METHOD_UNKNOWN */
    return httpd_methods_tab[i].method_id;
    }


int
httpd_method_id( char* method_str )
    {
    return get_method_id( method_str );
    }


/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
static void
strdecode( char* to, char* from )
    {
static const char hex2dec_tab[256] = {
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 00-0F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 10-1F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 20-2F */
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,  /* 30-3F */
     0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 40-4F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 50-5F */
     0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 60-6F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 70-7F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 80-8F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 90-9F */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* A0-AF */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* B0-BF */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* C0-CF */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* D0-DF */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* E0-EF */
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   /* F0-FF */
    };
    char *cp;

#define hex2dec_m(c)	( (int) hex2dec_tab[ ( (unsigned char )(c) ) ] )

    /* check if decoding is needed */
    cp = strchr( from, '%' );
    if ( cp == (char *) 0 )
	{ /* no need to decode */
	/* copy is needed only if source and target string are not the same */
	if ( to != from )
	    (void) strcpy( to, from );
	return;
	}

    /* slow decode and copy */
    for ( ; *from != '\0'; ++to, ++from )
	{
	if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) )
	    {
	    *to = hex2dec_m( from[1] ) * 16 + hex2dec_m( from[2] );
	    from += 2;
	    }
	else
	    *to = *from;
	}
    *to = '\0';

#undef  hex2dec_m
    }


#ifdef GENERATE_INDEXES

/* Copies and encodes a string. */
static void
strencode( char* to, int tosize, char* from )
    {
    static const char dec2hex_tab[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f'
	};
    int tolen;
    int tosize2 = tosize - 4;

/* macro, (uc) is already masked with 0xf0 or 0x0f */
#define dec2hex_m( uc )	( dec2hex_tab[ ( uc ) ] )

    for ( tolen = 0; *from != '\0' && tolen < tosize2; ++from )
	{
	if ( isalnum(*from) || strchr( "/_.-~", *from ) != (char*) 0 )
	    {
	    *to = *from;
	    ++to;
	    ++tolen;
	    }
	else
	    {
	    *to++ = '%';
	    *to++ = dec2hex_m( ( *from & 0xf0 ) >> 4 );
	    *to++ = dec2hex_m( ( *from & 0x0f ) );
	    tolen += 3;
	    }
	}
    *to = '\0';

#undef dec2hex_m
    }
#endif /* GENERATE_INDEXES */


#ifdef TILDE_MAP_1
/* Map a ~username/whatever URL into <prefix>/username. */
static int
tilde_map_1( httpd_conn* hc )
    {
    static char* temp;
    static int maxtemp = 0;
    int len;
    static char* prefix = TILDE_MAP_1;
    int   prefix_len = SZLEN( TILDE_MAP_1 );

    len = --hc->expnfn_len;
    httpd_realloc_str( &temp, &maxtemp, len );
    (void) strcpy( temp, &hc->expnfilename[1] );
    httpd_realloc_str(
	&hc->expnfilename, &hc->maxexpnfilename, prefix_len + 1 + len );
    (void) strcpy( hc->expnfilename, prefix );
    if ( prefix[0] != '\0' )
	hc->expnfilename[prefix_len++] = '/';

    (void) strcpy( &hc->expnfilename[prefix_len], temp );

    hc->expnfn_len += prefix_len;

    return 1;
    }
#endif /* TILDE_MAP_1 */

#ifdef TILDE_MAP_2
/* Map a ~username/whatever URL into <user's homedir>/<postfix>. */
static int
tilde_map_2( httpd_conn* hc )
    {
    static char* temp;
    static int maxtemp = 0;
    static char* postfix = TILDE_MAP_2;
    int    postfix_len = SZLEN( TILDE_MAP_2 );
    int    altdir_len = 0;
    int    alt_len = 0;
    int    cp_len = 0;
    char* cp;
    struct passwd* pw;
    char* alt;
    char* rest = (char*) 0;

    /* Get the username. */
    httpd_realloc_str( &temp, &maxtemp, hc->expnfn_len );
    (void) strcpy( temp, &hc->expnfilename[1] );
    cp = strchr( temp, '/' );
    if ( cp != (char*) 0 )
	{
	*cp++ = '\0';
	cp_len = (int) strlen( cp );
	}
    else
	cp = "";

    /* Get the passwd entry. */
    pw = getpwnam( temp );
    if ( pw == (struct passwd*) 0 )
	return 0;

    /* Set up altdir. */
    altdir_len = (int) strlen( pw->pw_dir );
    httpd_realloc_str(
	&hc->altdir, &hc->maxaltdir,
	altdir_len + 1 + postfix_len );
    (void) strcpy( hc->altdir, pw->pw_dir );
    if ( postfix[0] != '\0' )
	{
	hc->altdir[altdir_len++] = '/';
	(void) strcpy( &hc->altdir[altdir_len], postfix );
	altdir_len += postfix_len;
	}
    alt = expand_symlinks( hc->altdir, altdir_len, &alt_len,
			&rest, 0, 1, (struct stat*) 0 );
    if ( rest[0] != '\0' )
	return 0;
    httpd_realloc_str( &hc->altdir, &hc->maxaltdir, alt_len );
    (void) strcpy( hc->altdir, alt );
    altdir_len = alt_len;

    /* And the filename becomes altdir plus the post-~ part of the original. */
    httpd_realloc_str(
	&hc->expnfilename, &hc->maxexpnfilename,
	altdir_len + 1 + cp_len );

    (void) strcpy( hc->expnfilename, hc->altdir );
    hc->expnfilename[altdir_len++] = '/';
    (void) strcpy( &hc->expnfilename[altdir_len], cp );

    hc->expnfn_len = altdir_len + cp_len;

    /* For this type of tilde mapping, we want to defeat vhost mapping. */
    hc->tildemapped = 1;

    return 1;
    }
#endif /* TILDE_MAP_2 */


/* Virtual host mapping. */
static int
vhost_map( httpd_conn* hc )
    {
    httpd_sockaddr sa;
    int sz;
    static char* tempfilename;
    static int maxtempfilename = 0;
    char* cp1;
    int hostname_len = 0;
    int hostdir_len = 0;
#ifdef VHOST_DIRLEVELS
    int i;
    char* cp2;
#endif /* VHOST_DIRLEVELS */

    /* Figure out the virtual hostname. */
    if ( hc->reqhost[0] != '\0' )
	hc->hostname = hc->reqhost;
    else if ( hc->hdrhost[0] != '\0' )
	hc->hostname = hc->hdrhost;
    else
	{
	sz = sizeof(sa);
	if ( getsockname( hc->conn_fd, &sa.sa, (socklen_t *)&sz ) < 0 )
	    {
	    syslog( LOG_ERR, "getsockname - %m" );
	    return 0;
	    }
	hc->hostname = httpd_ntoa( &sa );
	}
    /* Pound it to lower case. */
    for ( cp1 = hc->hostname; *cp1 != '\0'; ++cp1 )
	if ( isupper( *cp1 ) )
	    *cp1 = tolower( *cp1 );

    hostname_len = (int) ( cp1 - hc->hostname );

    if ( hc->tildemapped )
	return 1;

    /* fix against unwanted listings */
    if ( hc->hostname[0] == '.' || strchr( hc->hostname, '/' ) != (char*) 0 )
	return 0;

    /* Figure out the host directory. */
#ifdef VHOST_DIRLEVELS

    httpd_realloc_str(
	&hc->hostdir, &hc->maxhostdir,
	hostname_len + 2 * VHOST_DIRLEVELS );
    if ( strncmp( hc->hostname, "www.", 4 ) == 0 )
	cp1 = &hc->hostname[4];
    else
	cp1 = hc->hostname;
    for ( cp2 = hc->hostdir, i = 0; i < VHOST_DIRLEVELS; ++i )
	{
	/* Skip dots in the hostname.  If we don't, then we get vhost
	** directories in higher level of filestructure if dot gets
	** involved into path construction.  It's `while' used here instead
	** of `if' for it's possible to have a hostname formed with two
	** dots at the end of it.
	*/
	while ( *cp1 == '.' )
	    ++cp1;
	/* Copy a character from the hostname, or '_' if we ran out. */
	if ( *cp1 != '\0' )
	    *cp2++ = *cp1++;
	else
	    *cp2++ = '_';
	/* Copy a slash. */
	*cp2++ = '/';
	}
    (void) strcpy( cp2, hc->hostname );
    hostdir_len = hostname_len + (int) ( cp2 - hc->hostdir );

#else /* VHOST_DIRLEVELS */

    httpd_realloc_str( &hc->hostdir, &hc->maxhostdir, hostname_len );
    (void) strcpy( hc->hostdir, hc->hostname );
    hostdir_len = hostname_len;

#endif /* VHOST_DIRLEVELS */

    /* Prepend hostdir to the filename. */
    httpd_realloc_str( &tempfilename, &maxtempfilename, hc->expnfn_len );
    (void) strcpy( tempfilename, hc->expnfilename );
    httpd_realloc_str(
	&hc->expnfilename, &hc->maxexpnfilename,
	hostdir_len + 1 + hc->expnfn_len );
    (void) strcpy( hc->expnfilename, hc->hostdir );
    hc->expnfilename[hostdir_len++] = '/';
    (void) strcpy( &hc->expnfilename[hostdir_len], tempfilename );

    hc->expnfn_len += hostdir_len;

    return 1;
    }


/* Expands all symlinks in the given filename, eliding ..'s and leading /'s.
** Returns the expanded path (pointer to static string), or (char*) 0 on
** errors.  Also returns, in the string pointed to by restP, any trailing
** parts of the path that don't exist.
**
** This is a fairly nice little routine.  It handles any size filenames
** without excessive mallocs.
*/
static char*
expand_symlinks( char* path, int path_len, int *checkedlenP,
                 char** restP, int no_symlink, int tildemapped,
                 struct stat* sbP )
    {
    static char* checked;
    static char* rest;
    char link[MAXPATHLEN + 1];
    static int maxchecked = 0, maxrest = 0;
    int checkedlen, restlen, linklen, prevcheckedlen, prevrestlen, nlinks, i;
    char* r;
    char* cp1;
    char* cp2;

    if ( no_symlink )
	{
	/* If we are chrooted, we can actually skip the symlink-expansion,
	** since it's impossible to get out of the tree.  However, we still
	** need to do the pathinfo check, and the existing symlink expansion
	** code is a pretty reasonable way to do this.  So, what we do is
	** a single stat() of the whole filename - if it exists, then we
	** return it as is with nothing in restP.  If it doesn't exist, we
	** fall through to the existing code.
	**
	** One side-effect of this is that users can't symlink to central
	** approved CGIs any more.  The "workaround" is to use the central
	** URL for the CGI instead of a local symlinked one.
	**
	** Another one is that hc->pathinfo won't be filled in.
	**
	*/
	struct stat  sb;
	struct stat* sbP2 = &sb;

	if ( sbP != (struct stat*) 0 )
	    sbP2 = sbP;

	if ( stat( path, sbP2 ) == 0 )
	    {
	    checkedlen = path_len;
	    httpd_realloc_str( &checked, &maxchecked, checkedlen );
	    (void) strcpy( checked, path );
	    /* Trim trailing slashes. */
	    while ( checkedlen > 0 && checked[checkedlen - 1] == '/' )
		{
		checked[--checkedlen] = '\0';
		}
	    httpd_realloc_str( &rest, &maxrest, 124 );
	    rest[0] = '\0';
	    *restP = rest;

	    *checkedlenP = checkedlen;
	    return checked;
	    }
	}

    if ( sbP != (struct stat*) 0 )
	sbP->st_mtime = 0;

    /* Start out with nothing in checked and the whole filename in rest. */
    httpd_realloc_str( &checked, &maxchecked, 124 );
    checked[0] = '\0';
    checkedlen =
    *checkedlenP = 0;
    restlen = path_len;
    httpd_realloc_str( &rest, &maxrest, restlen );
    (void) strcpy( rest, path );
    if ( restlen > 0 && rest[restlen - 1] == '/' )
	rest[--restlen] = '\0';         /* trim trailing slash */
    if ( ! tildemapped )
	{
	/* Remove any leading slashes. */
	for ( i = 0; rest[i] == '/'; ++i )
	    ;
	if ( i > 0 )
	    {
	    if ( i < restlen )
		{
		(void) ovl_strcpy( rest, &rest[i] );
		restlen -= i;
		}
	    else
		{
		rest[0] = '\0';
		restlen = 0;
		}
	    }
	}
    r = rest;
    nlinks = 0;

    /* While there are still components to check... */
    while ( restlen > 0 )
	{
	/* Save current checkedlen in case we get a symlink.  Save current
	** restlen in case we get a non-existant component.
	*/
	prevcheckedlen = checkedlen;
	prevrestlen = restlen;

	/* Grab one component from r and transfer it to checked. */
	cp1 = strchr( r, '/' );
	if ( cp1 != (char*) 0 )
	    {
	    i = (int) ( cp1 - r );
	    if ( i == 0 )
		{
		/* Special case for absolute paths. */
		httpd_realloc_str( &checked, &maxchecked, checkedlen + 1 );
		checked[checkedlen++] = r[0];
		}
	    else if ( strncmp( r, "..", MAX( i, 2 ) ) == 0 )
		{
		/* Ignore ..'s that go above the start of the path. */
		if ( checkedlen != 0 )
		    {
		    cp2 = strrchr( checked, '/' );
		    if ( cp2 == (char*) 0 )
			checkedlen = 0;
		    else if ( cp2 == checked )
			checkedlen = 1;
		    else
			checkedlen = (int) ( cp2 - checked );
		    }
		}
	    else
		{
		httpd_realloc_str( &checked, &maxchecked, checkedlen + 1 + i );
		if ( checkedlen > 0 && checked[checkedlen-1] != '/' )
		    checked[checkedlen++] = '/';
		(void) memcpy( &checked[checkedlen], r, i );
		checkedlen += i;
		}
	    checked[checkedlen] = '\0';
	    r += i + 1;
	    restlen -= i + 1;
	    }
	else
	    {
	    /* No slashes remaining, r is all one component. */
	    if ( strcmp( r, ".." ) == 0 )
		{
		/* Ignore ..'s that go above the start of the path. */
		if ( checkedlen != 0 )
		    {
		    cp2 = strrchr( checked, '/' );
		    if ( cp2 == (char*) 0 )
			checkedlen = 0;
		    else if ( cp2 == checked )
			checkedlen = 1;
		    else
			checkedlen = (int) (cp2 - checked);
		    checked[checkedlen] = '\0';
		    }
		}
	    else
		{
		httpd_realloc_str(
		    &checked, &maxchecked, checkedlen + 1 + restlen );
		if ( checkedlen > 0 && checked[checkedlen-1] != '/' )
		    checked[checkedlen++] = '/';
		(void) strcpy( &checked[checkedlen], r );
		checkedlen += restlen;
		}
	    r += restlen;
	    restlen = 0;
	    }

	/* Try reading the current filename as a symlink */
	if ( checked[0] == '\0' )
	    continue;
	linklen = readlink( checked, link, ( sizeof(link) - 1 ) );
	if ( linklen == -1 )
	    {
	    if ( errno == EINVAL )
		continue;               /* not a symlink */
	    if ( errno == EACCES || errno == ENOENT || errno == ENOTDIR )
		{
		/* That last component was bogus.  Restore and return. */
		*restP = r - ( prevrestlen - restlen );
		if ( prevcheckedlen == 0 )
		    {
		    checked[0] = '.';
		    checked[1] = '\0';
		    checkedlen = 1;
		    }
		else
		    {
		    checked[prevcheckedlen] = '\0';
		    checkedlen = prevcheckedlen;
		    }
		*checkedlenP = checkedlen;
		return checked;
		}
	    syslog( LOG_ERR, "readlink %.80s - %m", checked );
	    return (char*) 0;
	    }
	++nlinks;
	if ( nlinks > MAX_LINKS )
	    {
	    syslog( LOG_ERR, "too many symlinks in %.80s", path );
	    return (char*) 0;
	    }
	link[linklen] = '\0';
	if ( linklen > 0 && link[linklen - 1] == '/' )
	    link[--linklen] = '\0';     /* trim trailing slash */

	/* Insert the link contents in front of the rest of the filename. */
	if ( restlen != 0 )
	    {
	    int i2 = restlen + linklen + 1;
	    (void) ovl_strcpy( rest, r );
	    httpd_realloc_str( &rest, &maxrest, i2 );
	    for ( i = restlen; i >= 0; --i, --i2 )
		rest[i2] = rest[i];
	    (void) strcpy( rest, link );
	    rest[linklen] = '/';
	    restlen += linklen + 1;
	    r = rest;
	    }
	else
	    {
	    /* There's nothing left in the filename, so the link contents
	    ** becomes the rest.
	    */
	    httpd_realloc_str( &rest, &maxrest, linklen );
	    (void) strcpy( rest, link );
	    restlen = linklen;
	    r = rest;
	    }

	if ( rest[0] == '/' )
	    {
	    /* There must have been an absolute symlink - zero out checked. */
	    checked[0] = '\0';
	    checkedlen = 0;
	    }
	else
	    {
	    /* Re-check this component. */
	    checkedlen = prevcheckedlen;
	    checked[checkedlen] = '\0';
	    }
	}

    /* Ok. */
    *restP = r;
    if ( checked[0] == '\0' )
	{
	checked[0] = '.';
	checked[1] = '\0';
	checkedlen = 1;
	}
    *checkedlenP = checkedlen;
    return checked;
    }


static int
httpd_request_reset0( httpd_conn* hc )
{
/*
** Don't reset the following fields because the callers have to deal with them.
**
**  hc->client_adddr = 0;
**  hc->read_idx = 0;
**  hc->checked_idx = 0;
**  hc->checked_state = CHST_FIRSTWORD;
**  hc->conn_fd = -1;
*/
    hc->method = METHOD_UNKNOWN;
    hc->status = 0;
    hc->allowed_methods = METHOD_UNKNOWN;
    hc->bytes_to_send = 0;
    hc->bytes_sent = 0;
    hc->encodedurl = "";
    hc->decodedurl[0] = '\0';
    hc->encodedurl_len = 0;
    hc->decodedurl_len = 0;
    hc->protocol = "HTTP/1.1";	/* reply with our version, not UNKNOWN */
    hc->protocol_len = 8;       /* replied HTTP version length is constant */
    hc->origfilename[0] = '\0';
    hc->expnfilename[0] = '\0';
    hc->origfn_len = 0;
    hc->expnfn_len = 0;
    hc->encodings[0] = '\0';
    hc->encodings_len = 0;
    hc->pathinfo[0] = '\0';
    hc->query[0] = '\0';
    hc->referer = "";
    hc->useragent = "";
#ifdef EXECUTE_CGI
    hc->accept[0] = '\0';
    hc->accepte[0] = '\0';
    hc->acceptl = "";
#endif /* EXECUTE_CGI */
    hc->cookie = "";
    hc->contenttype = "";
    hc->reqhost[0] = '\0';
    hc->hdrhost = "";
    hc->hostdir[0] = '\0';
#ifdef AUTH_FILE
    hc->authorization = "";
    hc->remoteuser[0] = '\0';
#endif /* AUTH_FILE */
    hc->response[0] = '\0';
#ifdef TILDE_MAP_2
    hc->altdir[0] = '\0';
#endif /* TILDE_MAP_2 */
    hc->responselen = 0;
    hc->if_modified_since = (time_t) -1;
    hc->range_if = (time_t) -1;
    hc->contentlength = -1;
    hc->type = "";
    hc->type_len = 0;
    hc->hostname = (char*) 0;
    hc->mime_flag = 1;
    hc->one_one = 0;
    hc->got_range = 0;
    hc->tildemapped = 0;
    hc->init_byte_loc = 0;
    hc->end_byte_loc = -1;
    hc->keep_alive_tmo = 0;
    hc->do_keep_alive = 0;
    hc->should_linger = 1;	/* linger by default */
    hc->sb.st_mtime = 0;
    hc->file_fd = EOF;
    hc->file_address = (char*) 0;
    return GC_OK;
}


int
httpd_request_reset(httpd_conn* hc )
{
    hc->read_buf[0] = '\0';
    hc->read_idx = 0;
    hc->checked_idx = 0;
    hc->checked_state = CHST_FIRSTWORD;
    return( httpd_request_reset0( hc ) );
}


int
httpd_request_reset2(httpd_conn* hc )
{
    if ( hc->checked_idx >= hc->read_idx )
	{
	hc->read_idx = 0;
	}
    else
	{  /* move contents to the front of buffer */
	hc->read_idx -= hc->checked_idx;
	/*  read_idx > 0 */
	if ( hc->checked_idx > 0 )
	    (void) memmove( hc->read_buf, &hc->read_buf[hc->checked_idx],
				hc->read_idx );
	}
    hc->read_buf[ hc->read_idx ] = '\0';
    hc->checked_idx = 0;
    hc->checked_state = CHST_FIRSTCRLF;
    return( httpd_request_reset0( hc ) );
}


int
httpd_get_conn( httpd_server* hs, int listen_fd, httpd_conn* hc, int is_sctp )
    {
    socklen_t sz;
    httpd_sockaddr sa;
#ifdef USE_SCTP
    int sb_size;
    struct sctp_status status;
#ifdef SCTP_EXPLICIT_EOR
    const int on = 1;
#endif
#endif


    if ( ! hc->initialized )
	{
	hc->read_size = 0;
	httpd_realloc_str( &hc->read_buf, &hc->read_size, 1536 );
	hc->maxdecodedurl =
	hc->maxorigfilename = hc->maxexpnfilename = hc->maxencodings =
	hc->maxpathinfo = hc->maxquery =
#ifdef EXECUTE_CGI
	hc->maxaccept = hc->maxaccepte =
#endif /* EXECUTE_CGI */
	hc->maxreqhost = hc->maxhostdir = 0;
#ifdef AUTH_FILE
	hc->maxremoteuser = 0;
#endif /* AUTH_FILE */
	hc->maxresponse = 0;
#ifdef TILDE_MAP_2
	hc->maxaltdir = 0;
#endif /* TILDE_MAP_2 */
	httpd_realloc_str( &hc->decodedurl, &hc->maxdecodedurl, 252 );
	httpd_realloc_str( &hc->origfilename, &hc->maxorigfilename, 252 );
	httpd_realloc_str( &hc->expnfilename, &hc->maxexpnfilename, 252 );
	httpd_realloc_str( &hc->encodings, &hc->maxencodings, 124 );
	httpd_realloc_str( &hc->pathinfo, &hc->maxpathinfo, 124 );
	httpd_realloc_str( &hc->query, &hc->maxquery, 252 );
#ifdef EXECUTE_CGI
	httpd_realloc_str( &hc->accept, &hc->maxaccept, 252 );
	httpd_realloc_str( &hc->accepte, &hc->maxaccepte, 60 );
#endif /* EXECUTE_CGI */
	httpd_realloc_str( &hc->reqhost, &hc->maxreqhost, 60 );
	httpd_realloc_str( &hc->hostdir, &hc->maxhostdir, 60 );
#ifdef AUTH_FILE
	httpd_realloc_str( &hc->remoteuser, &hc->maxremoteuser, 60 );
#endif /* AUTH_FILE */
	httpd_realloc_str( &hc->response, &hc->maxresponse, 508 );
#ifdef TILDE_MAP_2
	httpd_realloc_str( &hc->altdir, &hc->maxaltdir, 124 );
#endif /* TILDE_MAP_2 */
	hc->initialized = 1;
	}

    /* Accept the new connection. */
    sz = sizeof(sa);
    hc->conn_fd = accept( listen_fd, &sa.sa, &sz );
    if ( hc->conn_fd < 0 )
	{
	if ( errno == EWOULDBLOCK )
	    return GC_NO_MORE;
#ifdef ECONNABORTED
	if ( errno == ECONNABORTED )
	    return GC_ABORT;
#endif /* ECONNABORTED */
	syslog( LOG_ERR, "accept - %m" );
	return GC_FAIL;
	}
    if ( ! sockaddr_check( &sa ) )
	{
	syslog( LOG_ERR, "unknown sockaddr family" );
	(void) close( hc->conn_fd );
	hc->conn_fd = -1;
	return GC_FAIL;
	}

#ifdef TEST_INHERIT_SO_VALUES
    {
    int bufsz = 0;
    sz = sizeof(bufsz);
    if ( getsockopt(
	hc->conn_fd, SOL_SOCKET, SO_RCVBUF, &bufsz, &sz ) < 0 )
	syslog( LOG_CRIT, "getsockopt SO_RCVBUF - %m" );
    syslog( LOG_NOTICE, "getsockopt SO_RCVBUF1: %d", bufsz );
    }
#endif /* TEST_INHERIT_SO_VALUES */

#ifdef EXECUTE_CGI
    /* NOTE: ls() does not exec */
    if ( hs->cgi_pattern != (char*) 0
#ifdef EXECUTE_CGICLI
	|| hs->cgicli_vrec != (httpd_cgicli_vrec*) 0
#endif /* EXECUTE_CGICLI */
	)
	/* close-on-exec */
	(void) fcntl( hc->conn_fd, F_SETFD, FD_CLOEXEC );
#endif /* EXECUTE_CGI */
    hc->hs = hs;
    memset( &hc->client_addr, 0, sizeof(hc->client_addr) );
    memcpy( &hc->client_addr, &sa, sockaddr_len( &sa ) );

#ifdef USE_SCTP
    hc->is_sctp = is_sctp;
    if ( is_sctp )
	{
	sz = (socklen_t)sizeof(struct sctp_status);
	if ( getsockopt(hc->conn_fd, IPPROTO_SCTP, SCTP_STATUS, &status, &sz) < 0 )
	    {
	    syslog( LOG_CRIT, "getsockopt SCTP_STATUS - %m" );
	    close( hc->conn_fd );
	    hc->conn_fd = -1;
	    return GC_FAIL;
	    }
	hc->no_i_streams = status.sstat_instrms;
	hc->no_o_streams = status.sstat_outstrms;
	sz = (socklen_t)sizeof(int);
	if ( getsockopt(hc->conn_fd, SOL_SOCKET, SO_SNDBUF, &sb_size, &sz) < 0 )
	    {
	    syslog( LOG_CRIT, "getsockopt SO_SNDBUF - %m" );
	    close( hc->conn_fd );
	    hc->conn_fd = -1;
	    return GC_FAIL;
	    }
	hc->send_at_once_limit = sb_size / 4;
#ifdef SCTP_EXPLICIT_EOR
	sz = (socklen_t)sizeof(int);
	if ( setsockopt(hc->conn_fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &on, sz) < 0 )
	    {
	    syslog( LOG_CRIT, "getsockopt SCTP_EXPLICIT_EOR - %m" );
	    close( hc->conn_fd );
	    hc->conn_fd = -1;
	    return GC_FAIL;
	    }
	hc->use_eeor = 1;
#else
	hc->use_eeor = 0;
#endif
	}
    else
	{
	hc->no_i_streams = 0;
	hc->no_o_streams = 0;
	hc->send_at_once_limit = 0;
	hc->use_eeor = 0;
	hc->sid = 0;
	}
#endif


    (void) httpd_request_reset( hc );

    return GC_OK;
    }


/* Checks hc->read_buf to see whether a complete request has been read so far;
** either the first line has two words (an HTTP/0.9 request), or the first
** line has three words and there's a blank line present.
**
** hc->read_idx is how much has been read in; hc->checked_idx is how much we
** have checked so far; and hc->checked_state is the current state of the
** finite state machine.
*/
int
httpd_got_request( httpd_conn* hc )
    {
    char c;
    int checked_idx0;

    for ( checked_idx0 = hc->checked_idx;
	  hc->checked_idx < hc->read_idx;
	  hc->checked_idx++ )
	{
	c = hc->read_buf[hc->checked_idx];
	switch ( hc->checked_state )
	    {
	    case CHST_FIRSTCRLF:
#ifdef MAX_KEEPALIVE_EXTRA_CRLFs
	    switch ( c )
		{
		case CHR_LF: case CHR_CR:
		if ( hc->checked_idx > MAX_KEEPALIVE_EXTRA_CRLFs )
		    {
		    hc->checked_state = CHST_BOGUS;
		    return GR_BAD_REQUEST_CRLF;
		    }
		continue;
		case CHR_BLANK: case CHR_TAB:
		    {
		    hc->checked_state = CHST_BOGUS;
		    return GR_BAD_REQUEST;
		    }
		default:
		hc->checked_state = CHST_FIRSTWORD;
		checked_idx0 = hc->checked_idx;
		}
#else
	    hc->checked_state = CHST_FIRSTWORD;
#endif /* MAX_KEEPALIVE_EXTRA_CRLFs */
	    /* fall down */
	    case CHST_FIRSTWORD:
	    switch ( c )
		{
		case CHR_BLANK: case CHR_TAB:
		if ( hc->checked_idx < ++checked_idx0 )
		    {
		    hc->checked_state = CHST_BOGUS;
		    return GR_BAD_REQUEST;
		    }
		hc->checked_state = CHST_FIRSTWS;
		continue;
		case CHR_LF: case CHR_CR:
		hc->checked_state = CHST_BOGUS;
		return GR_BAD_REQUEST_CRLF2;
		default:
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_FIRSTWS:
	    switch ( c )
		{
		case CHR_BLANK: case CHR_TAB:
		continue;
		case CHR_LF: case CHR_CR:
		hc->checked_state = CHST_BOGUS;
		return GR_BAD_REQUEST;
		default:
		hc->checked_state = CHST_SECONDWORD;
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_SECONDWORD:
	    switch ( c )
		{
		case CHR_BLANK: case CHR_TAB:
		hc->checked_state = CHST_SECONDWS;
		continue;
		case CHR_LF: case CHR_CR:
		/* The first line has only two words - an HTTP/0.9 request. */
		hc->checked_idx++;
		return GR_GOT_REQUEST;
		default:
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_SECONDWS:
	    switch ( c )
		{
		case CHR_BLANK: case CHR_TAB:
		continue;
		case CHR_LF: case CHR_CR:
		hc->checked_state = CHST_BOGUS;
		return GR_BAD_REQUEST;
		default:
		hc->checked_state = CHST_THIRDWORD;
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_THIRDWORD:
	    switch ( c )
		{
		case CHR_BLANK: case CHR_TAB:
		hc->checked_state = CHST_THIRDWS;
		continue;
		case CHR_LF:
		hc->checked_state = CHST_LF;
		continue;
		case CHR_CR:
		hc->checked_state = CHST_CR;
		continue;
		default:
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_THIRDWS:
	    switch ( c )
		{
		case CHR_BLANK: case CHR_TAB:
		continue;
		case CHR_LF:
		hc->checked_state = CHST_LF;
		continue;
		case CHR_CR:
		hc->checked_state = CHST_CR;
		continue;
		default:
		hc->checked_state = CHST_BOGUS;
		return GR_BAD_REQUEST;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_LINE:
	    {
	    int checked_idx = hc->checked_idx;

	    /* fast search for CRLF */
	    do
		{
		if ( hc->read_buf[checked_idx] == CHR_LF )
		    break;
		if ( hc->read_buf[checked_idx] == CHR_CR )
		    break;
		++checked_idx;
		}
	    while ( checked_idx < hc->read_idx );
	    hc->checked_idx = checked_idx;
	    }
	    /* check if a CRLF character was found */
	    if ( hc->checked_idx >= hc->read_idx )
		{ /* no, CRLF not found */
		hc->checked_idx--;
		continue;
		}
	    c = hc->read_buf[hc->checked_idx];
	    switch ( c )
		{
		case CHR_LF:
		hc->checked_state = CHST_LF;
		continue;
		case CHR_CR:
		hc->checked_state = CHST_CR;
		continue;
		default:
		/* NOTREACHED */
		continue;
		}
	    /* NOTREACHED */
	    break;

	    case CHST_LF:
	    switch ( c )
		{
		case CHR_LF:
		/* Two newlines in a row - a blank line - end of request. */
		hc->checked_idx++;
		return GR_GOT_REQUEST;
		case CHR_CR:
		hc->checked_state = CHST_CR;
		continue;
		default:
		hc->checked_state = CHST_LINE;
		continue;
		}
	    break;
	    case CHST_CR:
	    switch ( c )
		{
		case CHR_LF:
		hc->checked_state = CHST_CRLF;
		continue;
		case CHR_CR:
		/* Two returns in a row - end of request. */
		hc->checked_idx++;
		return GR_GOT_REQUEST;
		default:
		hc->checked_state = CHST_LINE;
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_CRLF:
	    switch ( c )
		{
		case CHR_LF:
		/* Two newlines in a row - end of request. */
		hc->checked_idx++;
		return GR_GOT_REQUEST;
		case CHR_CR:
		hc->checked_state = CHST_CRLFCR;
		continue;
		default:
		hc->checked_state = CHST_LINE;
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_CRLFCR:
	    switch ( c )
		{
		case CHR_LF: case CHR_CR:
		/* Two CRLFs or two CRs in a row - end of request. */
		hc->checked_idx++;
		return GR_GOT_REQUEST;
		default:
		hc->checked_state = CHST_LINE;
		continue;
		}
	    /* NOTREACHED */
	    break;
	    case CHST_BOGUS:
	    return GR_BAD_REQUEST;
	    }
	}
    return GR_NO_REQUEST;
    }


/*
** Verify whether there is a pipelined request (1)
** or not (0).
*/
int
httpd_is_next_request( httpd_conn* hc )
    {
    /* Skip CRLF */
#if defined(MAX_KEEPALIVE_EXTRA_CRLFs) && (MAX_KEEPALIVE_EXTRA_CRLFs > 0)
    while( hc->checked_idx < hc->read_idx &&
	( hc->read_buf[hc->checked_idx] == CHR_LF ||
	  hc->read_buf[hc->checked_idx] == CHR_CR ) )
	  hc->checked_idx++;
    return ( hc->checked_idx + 16 < hc->read_idx &&
	isalpha( hc->read_buf[hc->checked_idx] ) );
#else
    return ( hc->checked_idx + 16 < hc->read_idx );
#endif
    }


int
httpd_parse_request( httpd_conn* hc )
    {
    char* buf        = (char*) 0;
    char* method_str = (char*) 0;
    char* url        = (char*) 0;
    char* protocol   = (char*) 0;
    char* reqhost    = (char*) 0;
    char* cp         = (char*) 0;

    /* Get first line */
    hc->checked_idx = 0;	/* (reset) */

    /* Skip CRLF (already checked by httpd_got_request() */
#if defined(MAX_KEEPALIVE_EXTRA_CRLFs) && (MAX_KEEPALIVE_EXTRA_CRLFs > 0)
    while( hc->checked_idx < hc->read_idx &&
	( hc->read_buf[hc->checked_idx] == CHR_LF ||
	  hc->read_buf[hc->checked_idx] == CHR_CR ) )
	  hc->checked_idx++;
#endif
    method_str = bufgets( hc );
    if ( method_str == (char*) 0 )
	{
	httpd_send_err( hc, 400, err400title, err400titlelen, "", err400form,
		"" );
	return -1;
	}

    /* Parse request. Take note that we have already set "should_linger",
    ** in order to handle also bad requests or strange conditions
    ** that lead to errors.
    */
    url = strpbrk( method_str, HTTP_BTLFCR_STR );
    if ( url == (char*) 0 || url == method_str )
	{
	httpd_send_err( hc, 400, err400title, err400titlelen, "", err400form,
		"" );
	return -1;
	}
    *url++ = '\0';
    url += strspn( url, HTTP_BTLFCR_STR );
    protocol = strpbrk( url, HTTP_BTLFCR_STR );
    if ( protocol == (char*) 0 )
	{
	protocol = "HTTP/0.9";
	hc->mime_flag = 0;
	hc->should_linger = 0;
	}
    else
	{
	*protocol++ = '\0';
	protocol += strspn( protocol, HTTP_BTLFCR_STR );
	if ( *protocol == '\0' )
	    {
	    /* trailing spaces, ignore them */
	    /* NOTE: httpd_got_request() should prevent this to happen */
	    protocol = "HTTP/0.9";
	    hc->mime_flag = 0;
	    hc->should_linger = 0;
	    }
	else
	    {
	    int httpMajorVersion = 1;
	    int httpMinorVersion = 0;
	    int protocol_len;

	    protocol_len = (int) strcspn( protocol, HTTP_BTLFCR_STR );
	    protocol[protocol_len] = '\0';

	    /* pattern: HTTP/[0-9]*\.[0-9][0-9]* */
	    if ( protocol_len < 8 ||
		 protocol_len > 12 ||
		 strncasecmp( protocol, "HTTP/", 5 ) != 0 ||
		 !isdigit( protocol[5] ) )
		{
		/* Unknown or bad protocol pattern, reply,
		** default is to linger HTTP/1.1.
		** Leave default protocol and protocol_len.
		*/
		hc->one_one = 1;
		httpd_send_err( hc, 400, err400title, err400titlelen,
			"", err400form, "" );
		return -1;
		}

	    if ( protocol[6] == '.' &&
		 isdigit( protocol[7] ) &&
		 protocol[8] == '\0' )
		{ /* "HTTP/n.n" common case, fast conversion */
		httpMajorVersion = ( protocol[5] - '0' );
		httpMinorVersion = ( protocol[7] - '0' );
		}
	    else
		{ /* some new protocol version with more than 1 digit */
		char *pszTmp = &protocol[5];

		/* check pattern and deformat Major and Minor version */
		httpMajorVersion = ( *pszTmp - '0' );
		for ( ++pszTmp; *pszTmp && isdigit( *pszTmp ); ++pszTmp )
		    {
		    httpMajorVersion *= 10;
		    httpMajorVersion += ( *pszTmp - '0' );
		    }
		if ( *pszTmp != '.' || !isdigit( pszTmp[1] ) )
		    {
		    httpMinorVersion = -1;
		    }
		else
		    {
		    ++pszTmp;
		    httpMinorVersion = ( *pszTmp - '0' );
		    for ( ++pszTmp; *pszTmp && isdigit( *pszTmp ); ++pszTmp )
			{
			httpMinorVersion *= 10;
			httpMinorVersion += ( *pszTmp - '0' );
			}
		    if ( *pszTmp != '\0' )
			httpMinorVersion = -1;
		    }
		}

	    if (  httpMajorVersion  < 0   ||
		  httpMajorVersion  > 1   ||
		( httpMajorVersion == 0 &&
		  httpMinorVersion != 9 ) ||
		  httpMinorVersion  < 0   ||
		  httpMinorVersion  > 999 )
		{   /* HTTP version not supported */
		    /* we use the highest we can support */
		hc->one_one = 1;
		httpd_send_err( hc, 505, err505title, err505titlelen,
			"", err505form, protocol );
		return -1;
		}

	    if ( httpMajorVersion == 1 && httpMinorVersion >= 1 )
		{   /* force HTTP version to what is supported */
		protocol = hc->protocol;
		hc->one_one = 1;
		/* Use persistent connection and linger mode
		** by default.
		*/
		hc->do_keep_alive = hc->hs->do_keepalive_conns;
		}
	    else
		{
		hc->should_linger = 0;
		if ( httpMajorVersion == 1 )
		    /* Downgrade HTTP version to requested HTTP/1.0 */
		    protocol = "HTTP/1.0";
		else
		    {
		    /* Downgrade HTTP version to requested HTTP/0.9,
		    ** OK, this should not happen here, but we are smart :-P
		    */
		    protocol = "HTTP/0.9";
		    hc->mime_flag = 0;
		    }
		}
	    }
	}

    /* protocol length is constant, thus we don't change hc->protocol_len */
    hc->protocol = protocol;

    /* Check for HTTP/1.1 absolute URL. */
    if ( strncasecmp( url, "http://", 7 ) == 0 )
	{
	if ( ! hc->one_one )
	    {
	    httpd_send_err( hc, 400, err400title, err400titlelen,
		"", err400form, "" );
	    return -1;
	    }
	reqhost = url + 7;
	url = strchr( reqhost, '/' );
	if ( url == (char*) 0 || reqhost[0] == '/' || reqhost[0] == '.' )
	    {
	    httpd_send_err( hc, 400, err400title, err400titlelen,
		"", err400form, "" );
	    return -1;
	    }
	*url = '\0';
	httpd_realloc_str( &hc->reqhost, &hc->maxreqhost, strlen( reqhost ) );
	(void) strcpy( hc->reqhost, reqhost );
	*url = '/';
	}

    /* encoded url is first decoded,
    ** then it is checked for bad characters (*)
    */

    /* Search for HTTP method */
    hc->method = get_method_id( method_str );
    if ( hc->method <  METHOD_GET ||
#ifdef EXECUTE_CGI
	 hc->method >  METHOD_POST
#else
	 hc->method >= METHOD_POST
#endif
	)
	{
	httpd_send_err501( hc, method_str );
	return -1;
	}

    hc->encodedurl = url;
    hc->encodedurl_len = (int) strlen( url );
    httpd_realloc_str(
	&hc->decodedurl, &hc->maxdecodedurl, hc->encodedurl_len );

    /* decode URL (it is equal to or smaller than encoded URL) */
    strdecode( hc->decodedurl, hc->encodedurl );

    /* remove dangerous dots (to prevent "out of tree" attacks) */
    hc->decodedurl_len = de_dotdot( hc->decodedurl );

    /* (*) check for bad characters */
    if ( hc->decodedurl[0] != '/' || hc->decodedurl[1] == '/' ||
	 ( hc->decodedurl[1] == '.' && hc->decodedurl[2] == '.' &&
	   ( hc->decodedurl[3] == '\0' || hc->decodedurl[3] == '/' ) ) )
	{
	httpd_send_err( hc, 400, err400title, err400titlelen,
		"", err400form, "" );
	return -1;
	}

    hc->origfn_len = hc->decodedurl_len - 1;
    httpd_realloc_str(
	&hc->origfilename, &hc->maxorigfilename, hc->decodedurl_len );
    (void) strcpy( hc->origfilename, &hc->decodedurl[1] );

    /* Extract query string from encoded URL. */
    cp = strchr( hc->encodedurl, '?' );
    if ( cp != (char*) 0 )
	{
	++cp;
	httpd_realloc_str( &hc->query, &hc->maxquery, strlen( cp ) );
	(void) strcpy( hc->query, cp );
	/* 07-JAN-2002 Cameron Gregory */
	/* And remove query from (decoded) origfilename. */
	cp = strchr( hc->origfilename, '?' );
	if ( cp != (char*) 0 )
	    {
	    *cp = '\0';
	    hc->origfn_len = (int) ( cp - hc->origfilename );
	    }
	}

    /* Special case for top-level URL. */
    if ( hc->origfilename[0] == '\0' )
	{
	hc->origfilename[0] = '.';
	hc->origfilename[1] = '\0';
	hc->origfn_len = 1;
	}

    if ( hc->origfn_len >= ( MAXPATHLEN - 1 ) )
	{
	httpd_send_err( hc, 414, err414title, err414titlelen,
		"", err414form, "" );
	return -1;
	}

    if ( hc->mime_flag )
	{
	/* Read the MIME headers. */
	while ( ( buf = bufgets( hc ) ) != (char*) 0 )
	    {
	    if ( buf[0] == '\0' )
		break;

	    switch( buf[0] )
		{
		case 'A':
		case 'a':
#if defined(EXECUTE_CGI) || defined(LOG_UNKNOWN_HEADERS)
		    if ( strncasecmp( buf, "Accept:", 7 ) == 0 )
			{
#ifdef EXECUTE_CGI
			int accept_len = 0;

			cp = &buf[7];
			cp += strspn( cp, HTTP_BTAB_STR );
			if ( hc->accept[0] != '\0' )
			    {
			    accept_len = (int) strlen( hc->accept );
			    if ( accept_len > 2048 )
				{
				syslog( LOG_ERR,
				    "%.80s way too much Accept: data (%d)",
				    httpd_ntoa( &hc->client_addr ),
				    accept_len );
				continue;
				}
			    httpd_realloc_str(
				&hc->accept, &hc->maxaccept,
				accept_len + 2 + strlen( cp ) );
			    (void) strcat( &hc->accept[accept_len], ", " );
			    accept_len += 2;
			    }
			else
			    httpd_realloc_str(
				&hc->accept, &hc->maxaccept, strlen( cp ) );
			(void) strcat( &hc->accept[accept_len], cp );
#endif /* EXECUTE_CGI */
			continue;
			}

		    if ( strncasecmp( buf, "Accept-Encoding:", 16 ) == 0 )
			{
#ifdef EXECUTE_CGI
			int accepte_len = 0;

			cp = &buf[16];
			cp += strspn( cp, HTTP_BTAB_STR );
			if ( hc->accepte[0] != '\0' )
			    {
			    accepte_len = (int) strlen( hc->accepte );
			    if ( accepte_len > 1024 )
				{
				syslog( LOG_ERR,
				"%.80s way too much Accept-Encoding: data (%d)",
				httpd_ntoa( &hc->client_addr ), accepte_len );
				continue;
				}
			    httpd_realloc_str(
				&hc->accepte, &hc->maxaccepte,
				accepte_len + 2 + strlen( cp ) );
			    (void) strcat( &hc->accepte[accepte_len], ", " );
			    accepte_len += 2;
			    }
			else
			    httpd_realloc_str(
				&hc->accepte, &hc->maxaccepte, strlen( cp ) );
			/* (void) strcat( &hc->accepte[accepte_len], cp ); */
			(void) strcpy( hc->accepte, cp );
#endif /* EXECUTE_CGI */
			continue;
			}

		    if ( strncasecmp( buf, "Accept-Language:", 16 ) == 0 )
			{
#ifdef EXECUTE_CGI
			cp = &buf[16];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->acceptl = cp;
#endif /* EXECUTE_CGI */
			continue;
			}
#endif /* EXECUTE_CGI || LOG_UNKNOWN_HEADERS */

#if defined(AUTH_FILE) || defined(LOG_UNKNOWN_HEADERS)
		    if ( strncasecmp( buf, "Authorization:", 14 ) == 0 )
			{
#ifdef AUTH_FILE
			cp = &buf[14];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->authorization = cp;
#endif /* AUTH_FILE */
			continue;
			}
#endif /* AUTH_FILE || LOG_UNKNOWN_HEADERS */

#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif

		case 'C':
		case 'c':
		    if ( strncasecmp( buf, "Content-Type:", 13 ) == 0 )
			{
			cp = &buf[13];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->contenttype = cp;
			continue;
			}

		    if ( strncasecmp( buf, "Content-Length:", 15 ) == 0 )
			{
			cp = &buf[15];
			hc->contentlength = atol( cp );
			continue;
			}

		    if ( strncasecmp( buf, "Cookie:", 7 ) == 0 )
			{
			cp = &buf[7];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->cookie = cp;
			continue;
			}

		    if ( strncasecmp( buf, "Connection:", 11 ) == 0 )
			{
			size_t nc = 0;
			cp = &buf[11];
			hc->should_linger = hc->one_one;
			/*
			** Connection: Keep-Alive, Pipeline, etc.
			** There can be 1 or more tokens,
			** we close the connection ONLY
			** if there is the "close" token.
			** NOTE: other listed tokens should be removed
			**       from the HTTP headers (RFC-2616),
			**       but this is a job for proxies.
			** NOTE: in the near future,
			**       some new token could be added
			**       to HTTP/1.1 specifications
			**       to indicate a "pipeline" connection,
			**       in that case we should re-add that keyword
			**       to the sent headers.
			*/
			do
			    {
			    /* skip spaces, tabs and commas */
			    cp += strspn( cp, HTTP_BTC_STR );
			    if ( *cp == '\0' )
				break;

			    /* find the end of the token */
			    nc = strcspn( cp, HTTP_BTC_STR );

			    /* figure what kind of token is */
			    if ( nc == 5 &&
				strncasecmp( cp, "close", nc ) == 0 )
				{
				/* Close connection */
				hc->do_keep_alive = 0;
				}
			    else
				{  /* some other token */
				/*
				** We have already set hc->do_keep_alive
				** only for HTTP/1.1
				** with persistent connection and
				** if hc->do_keep_alive
				**    has already been disabled
				** then it has not to be reenabled here
				** (in any case).
				*/
				hc->should_linger = 1;
				}

			    cp += nc;
			    }
			while( *cp != '\0' );
			continue;
			}
#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif

		case 'H':
		case 'h':
		    if ( strncasecmp( buf, "Host:", 5 ) == 0 )
			{
			cp = &buf[5];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->hdrhost = cp;
			cp = strrchr( hc->hdrhost, ':' );
			if ( cp != (char*) 0 )
			    *cp = '\0';
			/*
			** chars not allowed: 0-32, "<>#%/\\", 127-255
			** minimum rejected, i.e. "/\\<>#\x08\x7F"
			** chars deprecated: "{|}^[]"
			*/
			if ( hc->hdrhost[0] == '.' ||
			    strpbrk( hc->hdrhost, "/\\<>#\x08\x7F" ) != 0 )
			    {
			    httpd_send_err( hc, 400,
				err400title, err400titlelen,
				"", err400form, "" );
			    return -1;
			    }
			continue;
			}
#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif

		case 'I':
		case 'i':
		    if ( strncasecmp( buf, "If-Modified-Since:", 18 ) == 0 )
			{
			cp = &buf[18];
			hc->if_modified_since = tdate_parse( cp );
			if ( hc->if_modified_since == (time_t) -1 )
			    syslog( LOG_DEBUG, "unparsable time: %.80s", cp );
			continue;
			}

		    if ( strncasecmp( buf, "If-Range:", 9 ) == 0 )
			{
			cp = &buf[9];
			hc->range_if = tdate_parse( cp );
			if ( hc->range_if == (time_t) -1 )
			    syslog( LOG_DEBUG, "unparsable time: %.80s", cp );
			continue;
			}
#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif

		case 'R':
		case 'r':
		    if ( strncasecmp( buf, "Referer:", 8 ) == 0 )
			{
			cp = &buf[8];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->referer = cp;
			continue;
			}

		    if ( strncasecmp( buf, "Range-If:", 9 ) == 0 )
			{
			cp = &buf[9];
			hc->range_if = tdate_parse( cp );
			if ( hc->range_if == (time_t) -1 )
			    syslog( LOG_DEBUG, "unparsable time: %.80s", cp );
			continue;
			}

		    if ( strncasecmp( buf, "Range:", 6 ) == 0 )
			{
			/*
			** Only support %d- and %d-%d,
			** NOT %d-%d,%d-%d or -%d.
			*/
			if ( strchr( buf, ',' ) == (char*) 0 )
			    {
			    char* cp_dash;
			    cp = strpbrk( buf, "=" );
			    if ( cp != (char*) 0 )
				{
				cp_dash = strchr( cp + 1, '-' );
				if ( cp_dash != (char*) 0 &&
				     cp_dash != cp + 1 )
				    {
				    *cp_dash = '\0';
				    hc->init_byte_loc = atol( cp + 1 );
				    if ( isdigit( (int) cp_dash[1] ) )
					hc->end_byte_loc = atol( cp_dash + 1 );
				    else
					hc->end_byte_loc = -1L;
				    /* Well, range request
				    ** should be allowed only for HTTP/1.1
				    ** (and above) requests, but we are
				    ** tolerant because many HTTP/1.0 clients
				    ** implement this feature.
				    */
				    if ( hc->init_byte_loc <  0L ||
					 hc->end_byte_loc  < -1L ||
					(hc->end_byte_loc  >  0L &&
					 hc->end_byte_loc  < hc->init_byte_loc))
					hc->got_range = 0;
				    else
					hc->got_range = 1;
				    }
				}
			    }
			continue;
			}
#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif

		case 'U':
		case 'u':
		    if ( strncasecmp( buf, "User-Agent:", 11 ) == 0 )
			{
			cp = &buf[11];
			cp += strspn( cp, HTTP_BTAB_STR );
			hc->useragent = cp;
			continue;
			}
#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif

		default:
#ifdef LOG_UNKNOWN_HEADERS
		    break;
#else
		    continue;
#endif
		}

#ifdef LOG_UNKNOWN_HEADERS
	    if ( strncasecmp( buf, "Accept-Charset:", 15 ) == 0 ||
		strncasecmp( buf, "Accept-Language:", 16 ) == 0 ||
		strncasecmp( buf, "Agent:", 6 ) == 0 ||
		strncasecmp( buf, "Cache-Control:", 14 ) == 0 ||
		strncasecmp( buf, "Cache-Info:", 11 ) == 0 ||
		strncasecmp( buf, "Charge-To:", 10 ) == 0 ||
		strncasecmp( buf, "Client-IP:", 10 ) == 0 ||
		strncasecmp( buf, "Date:", 5 ) == 0 ||
		strncasecmp( buf, "Extension:", 10 ) == 0 ||
		strncasecmp( buf, "Forwarded:", 10 ) == 0 ||
		strncasecmp( buf, "From:", 5 ) == 0 ||
		strncasecmp( buf, "HTTP-Version:", 13 ) == 0 ||
		strncasecmp( buf, "Max-Forwards:", 13 ) == 0 ||
		strncasecmp( buf, "Message-Id:", 11 ) == 0 ||
		strncasecmp( buf, "MIME-Version:", 13 ) == 0 ||
		strncasecmp( buf, "Negotiate:", 10 ) == 0 ||
		strncasecmp( buf, "Pragma:", 7 ) == 0 ||
		strncasecmp( buf, "Proxy-Agent:", 12 ) == 0 ||
		strncasecmp( buf, "Proxy-Connection:", 17 ) == 0 ||
		strncasecmp( buf, "Security-Scheme:", 16 ) == 0 ||
		strncasecmp( buf, "Session-Id:", 11 ) == 0 ||
		strncasecmp( buf, "UA-Color:", 9 ) == 0 ||
		strncasecmp( buf, "UA-CPU:", 7 ) == 0 ||
		strncasecmp( buf, "UA-Disp:", 8 ) == 0 ||
		strncasecmp( buf, "UA-OS:", 6 ) == 0 ||
		strncasecmp( buf, "UA-Pixels:", 10 ) == 0 ||
		strncasecmp( buf, "User:", 5 ) == 0 ||
		strncasecmp( buf, "Via:", 4 ) == 0 ||
		strncasecmp( buf, "X-", 2 ) == 0 )
		continue;	/* ignore */

	    /* else log */
	    syslog( LOG_DEBUG, "unknown request header: %.80s", buf );

#endif /* LOG_UNKNOWN_HEADERS */

	    }
	}

    if ( hc->one_one )
	{
	/* NOTE: we have already set keep_alive, do_keep_alive and
	**       should_linger as soon as possible with proper values.
	*/

	/* Check that HTTP/1.1 requests specify a host, as required. */
	if ( hc->reqhost[0] == '\0' && hc->hdrhost[0] == '\0' )
	    {
	    httpd_send_err( hc, 400, err400title, err400titlelen,
		"", err400form, "" );
	    return -1;
	    }

#ifdef BAD_KEEPALIVE_UA_LIST
	/*
	**  Disable keep alive support for bad browsers (user agents).
	*/
	if ( hc->do_keep_alive )
	    {
	    static const char *vKABadUa[] = { BAD_KEEPALIVE_UA_LIST };
	    int	i = 0;
	    /* search bad list, we assume there is at least one name */
	    do
		{
		if ( strstr( hc->useragent, vKABadUa[i] ) != (char*) 0 )
		    {	/* bad client, go away ASAP */
		    hc->do_keep_alive = 0;
		    break;
		    }
		}
	    while ( ++i < sizeof(vKABadUa)/sizeof(vKABadUa[0]) );
	    }
#endif /* BAD_KEEPALIVE_UA_LIST */
	}

    /* Ok, the request has been parsed.  Now we resolve stuff that
    ** may require the entire request.
    */

    /* Copy original filename to expanded filename. */
    hc->expnfn_len = hc->origfn_len;
    httpd_realloc_str(
	&hc->expnfilename, &hc->maxexpnfilename, hc->expnfn_len );
    (void) strcpy( hc->expnfilename, hc->origfilename );

    /* Tilde mapping. */
#if defined( TILDE_MAP_1 ) || defined( TILDE_MAP_2 )
    if ( hc->expnfilename[0] == '~' )
	{
#ifdef TILDE_MAP_1
	if ( ! tilde_map_1( hc ) )
	    {
	    httpd_send_err( hc, 404, err404title, err404titlelen,
		"", err404form, hc->encodedurl );
	    return -1;
	    }
#endif /* TILDE_MAP_1 */
#ifdef TILDE_MAP_2
	if ( ! tilde_map_2( hc ) )
	    {
	    httpd_send_err( hc, 404, err404title, err404titlelen,
		"", err404form, hc->encodedurl );
	    return -1;
	    }
#endif /* TILDE_MAP_2 */
	}
#endif	/* TILDE_MAP_1 || TILDE_MAP_2 */

    /* Virtual host mapping. */
    if ( hc->hs->vhost )
	{
	if ( ! vhost_map( hc ) )
	    {
	    httpd_send_err( hc, 500, err500title, err500titlelen,
		"", err500form, hc->encodedurl );
	    return -1;
	    }
	}

    {
    char *pi = (char*) 0;
    int  pi_len = 0;
    int  cp_len = 0;

    /* Expand all symbolic links in the filename.  This also gives us
    ** any trailing non-existing components, for pathinfo.
    */
    cp = expand_symlinks( hc->expnfilename, hc->expnfn_len, &cp_len,
			&pi, hc->hs->no_symlink, hc->tildemapped, &hc->sb );
    if ( cp == (char*) 0 )
	{
	httpd_send_err( hc, 500, err500title, err500titlelen,
		"", err500form, hc->encodedurl );
	return -1;
	}
    httpd_realloc_str( &hc->expnfilename, &hc->maxexpnfilename, cp_len );
    (void) strcpy( hc->expnfilename, cp );
    hc->expnfn_len = cp_len;

    pi_len = (int) strlen( pi );

    httpd_realloc_str( &hc->pathinfo, &hc->maxpathinfo, pi_len + 2 );
    (void) strcpy( hc->pathinfo, pi );

    /* Remove pathinfo stuff from the original filename too. */
    if ( hc->pathinfo[0] != '\0' )
	{
	int i;
	i = hc->origfn_len - pi_len;
	if ( i > 0 && strcmp( &hc->origfilename[i], hc->pathinfo ) == 0 )
	    {
	    hc->origfilename[--i] = '\0';
	    hc->origfn_len = i;
	    }
	}
    }

    /* If the expanded filename is an absolute path, check that it's still
    ** within the current directory or the alternate directory.
    */
    if ( hc->expnfilename[0] == '/' )
	{
	if ( strncmp(
		 hc->expnfilename, hc->hs->cwd, hc->hs->cwd_len ) == 0 )
	    {
	    /* Elide the current directory. */
	    (void) ovl_strcpy(
		hc->expnfilename, &hc->expnfilename[hc->hs->cwd_len] );
	    hc->expnfn_len -= hc->hs->cwd_len;
	    }
#ifdef TILDE_MAP_2
	else if ( hc->altdir[0] != '\0' &&
		  ( strncmp(
		       hc->expnfilename, hc->altdir,
		       strlen( hc->altdir ) ) == 0 &&
		    ( hc->expnfilename[strlen( hc->altdir )] == '\0' ||
		      hc->expnfilename[strlen( hc->altdir )] == '/' ) ) )
	    {
		;
	    }
#endif /* TILDE_MAP_2 */
	else
	    {
	    syslog(
		LOG_NOTICE, "%.80s URL \"%.80s\" goes outside the web tree",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	    httpd_send_err(
		hc, 403, err403title, err403titlelen, "",
		ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a file outside the permitted web server directory tree.\n" ),
		hc->encodedurl );
	    return -1;
	    }
	}

    return 0;
    }


static char*
bufgets( httpd_conn* hc )
    {
    int checked_idx0;
    char c;

    for ( checked_idx0 = hc->checked_idx;
	hc->checked_idx < hc->read_idx;
	hc->checked_idx++ )
	{
	c = hc->read_buf[hc->checked_idx];
	if ( c == CHR_LF || c == CHR_CR )
	    {
	    hc->read_buf[hc->checked_idx++] = '\0';
	    if ( c == CHR_CR && hc->checked_idx < hc->read_idx &&
		 hc->read_buf[hc->checked_idx] == CHR_LF )
		{
		hc->read_buf[hc->checked_idx++] = '\0';
		}
	    return &(hc->read_buf[checked_idx0]);
	    }
	}
    return (char*) 0;
    }


static int
de_dotdot( char* file )
    {
    char* cp;
    char* cp2;
    int l;

    /* Collapse any multiple / sequences. */
    while ( ( cp = strstr( file, "//") ) != (char*) 0 )
	{
	for ( cp2 = cp + 2; *cp2 == '/'; ++cp2 )
	    continue;
	(void) ovl_strcpy( cp + 1, cp2 );
	}

    /* Remove leading ./ and any /./ sequences. */
    while ( strncmp( file, "./", 2 ) == 0 )
	(void) ovl_strcpy( file, file + 2 );
    while ( ( cp = strstr( file, "/./") ) != (char*) 0 )
	(void) ovl_strcpy( cp, cp + 2 );

    /* Alternate between removing leading ../ and removing xxx/../ */
    for (;;)
	{
	while ( strncmp( file, "../", 3 ) == 0 )
	    (void) ovl_strcpy( file, file + 3 );
	cp = strstr( file, "/../" );
	if ( cp == (char*) 0 )
	    break;
	for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    continue;
	(void) ovl_strcpy( cp2 + 1, cp + 4 );
	}

    /* Also elide any xxx/.. at the end. */
    while ( ( l = (int) strlen( file ) ) > 3 &&
	    strcmp( ( cp = file + l - 3 ), "/.." ) == 0 )
	{
	for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    continue;
	if ( cp2 < file )
	    break;
	*cp2 = '\0';
	}
    return l;
    }


void
httpd_complete_request( httpd_conn* hc, struct timeval* nowP, int logit )
    {
    if (logit == CR_DO_LOGIT)
	make_log_entry( hc, nowP );

    if ( hc->file_fd != EOF || hc->file_address != (char*) 0 )
	{
	mmc_unmap( hc->file_fd, hc->file_address, &(hc->sb), nowP );
	hc->file_fd = EOF;
	hc->file_address = (char*) 0;
	}
    }


void
httpd_close_conn_wr( httpd_conn* hc )
    {
    if ( hc->conn_fd >= 0 )
	{
	/* half close output stream of this connection;
        ** NOTE: this is a non blocking call,
	** thus there is no need to test for EINTR.
	*/
	(void) shutdown( hc->conn_fd, SHUT_WR );
	}
    }


void
httpd_close_conn( httpd_conn* hc, struct timeval* nowP )
    {

    if ( hc->conn_fd >= 0 )
	{
	/* Traditional *NIX behaviour is to always close file descriptor,
	** regardless pending signals or other conditions.
	*/
	(void) close( hc->conn_fd );
	hc->conn_fd = -1;
	}
    }


void
httpd_destroy_conn( httpd_conn* hc )
    {
    if ( hc->initialized == 0 )
	return;

    hc->initialized = 0;

    free( (void*) hc->read_buf );
                  hc->read_buf = (char*) 0;
    free( (void*) hc->decodedurl );
                  hc->decodedurl = (char*) 0;
    free( (void*) hc->origfilename );
                  hc->origfilename = (char*) 0;
    free( (void*) hc->expnfilename );
                  hc->expnfilename = (char*) 0;
    free( (void*) hc->encodings );
                  hc->encodings = (char*) 0;
    free( (void*) hc->pathinfo );
                  hc->pathinfo = (char*) 0;
    free( (void*) hc->query );
                  hc->query = (char*) 0;
#ifdef EXECUTE_CGI
    free( (void*) hc->accept );
                  hc->accept = (char*) 0;
    free( (void*) hc->accepte );
                  hc->accepte = (char*) 0;
#endif /* EXECUTE_CGI */
    free( (void*) hc->reqhost );
                  hc->reqhost = (char*) 0;
    free( (void*) hc->hostdir );
                  hc->hostdir = (char*) 0;
#ifdef AUTH_FILE
    free( (void*) hc->remoteuser );
                  hc->remoteuser = (char*) 0;
#endif /* AUTH_FILE */
    free( (void*) hc->response );
                  hc->response = (char*) 0;
#ifdef TILDE_MAP_2
    free( (void*) hc->altdir );
                  hc->altdir = (char*) 0;
#endif /* TILDE_MAP_2 */
    }


struct mime_entry {
    char* ext;
    size_t ext_len;
    char* val;
    size_t val_len;
    };
static struct mime_entry enc_tab[] = {
#include "mime_encodings.h"
    };
static const int n_enc_tab = sizeof(enc_tab) / sizeof(*enc_tab);
static struct mime_entry typ_tab[] = {
#include "mime_types.h"
    };
static const int n_typ_tab = sizeof(typ_tab) / sizeof(*typ_tab);

struct mime_hash {
    struct mime_entry *pmime;
    struct mime_hash  *pnext;
    };

#define TYP_HASH_BITS	9	/* 8 = 256 entries, 9 = 512 entries, ecc. */
#define	TYP_HASH_SIZE	( 1 << TYP_HASH_BITS )
#define	TYP_HASH_MASK	( TYP_HASH_SIZE - 1 )

static size_t max_enc_ext_len;
static size_t max_typ_ext_len;
static struct mime_hash *free_mime_hash;
static struct mime_hash	*typ_hash_tab[TYP_HASH_SIZE];

/* if default mime type is defined to be zero length */
/* then header "Content-Type:" is omitted to allow client */
/* to guess the proper mime-type */

#ifndef DEFAULT_MIME_TYPE
#define DEFAULT_MIME_TYPE	""
#endif
#ifndef DEFAULT_MIME_TYPE_BIN
#define DEFAULT_MIME_TYPE_BIN	""
#endif

/* Case-insensitive HASH.
** NOTE: only ASCII characters give meaningful results.
*/
static unsigned int
hash_mime( char *buf, size_t len )
    {
    unsigned int h;

    for ( h = 5381; len > 0; --len, ++buf )
	{
	h += h << 5;
#if defined(tolower)
	h ^= tolower( *buf );
#else
	if ( !isupper( *buf ) )
	    /* fast case */
	    h ^= (int) *buf;
	else
	    h ^= tolower( *buf );
#endif
	}

    return( h & TYP_HASH_MASK );
    }


/*
** Initializes mime structures and insert optional charset into mime types.
*/
static int
init_mime( httpd_server *hs )
    {
    int i;
    unsigned int h = 0;
    struct mime_hash *pmh1, *pmh2;
    char mimebuf[256];

    if ( hs->charset == (char *) 0 )
	hs->charset = "";

    mimebuf[0] = '\0';
    (void) my_snprintf( mimebuf, sizeof( mimebuf ),
	DEFAULT_MIME_TYPE, hs->charset );
    mimebuf[ sizeof( mimebuf ) - 1 ] = '\0';
    hs->def_mime_type = strdup( mimebuf );
    if ( hs->def_mime_type == (char*) 0 )
	{
	syslog( LOG_CRIT, "init_mime: strdup def_mime_type failed - %m" );
	return -1;
	}
    hs->def_mime_type_len = (int) strlen( hs->def_mime_type );

    mimebuf[0] = '\0';
    (void) my_snprintf( mimebuf, sizeof( mimebuf ),
	DEFAULT_MIME_TYPE_BIN, hs->charset );
    mimebuf[ sizeof( mimebuf ) - 1 ] = '\0';
    hs->def_mime_typeb = strdup( mimebuf );
    if ( hs->def_mime_typeb == (char*) 0 )
	{
	syslog( LOG_CRIT, "init_mime: strdup def_mime_typeb failed - %m" );
	return -1;
	}
    hs->def_mime_typeb_len = (int) strlen( hs->def_mime_typeb );

    /* Fill in the lengths. */
    for ( i = 0; i < n_enc_tab; ++i )
	{
	enc_tab[i].ext_len = strlen( enc_tab[i].ext );
	enc_tab[i].val_len = strlen( enc_tab[i].val );
	if ( enc_tab[i].ext_len > max_enc_ext_len )
	     max_enc_ext_len = enc_tab[i].ext_len;
	}
    for ( i = 0; i < n_typ_tab; ++i )
	{
	int  fmtlen = 0;
	char *psz;

	psz = strstr( typ_tab[i].val, "%s" );
	if ( psz != (char *) 0 )
	    {
	    if ( psz[2] == '\0' && hs->charset[0] == '\0' )
		{
		/*
		** No need to format and to allocate a new string.
		** NOTE: we can set a lower value in val_len
		**       only because we always use val_len
		**       to format strings.
		*/
		fmtlen = 2;
		}
	    else
		{
		/* Format string */
		mimebuf[0] = '\0';
		(void) my_snprintf( mimebuf, sizeof(mimebuf),
			typ_tab[i].val, hs->charset );
		mimebuf[sizeof(mimebuf)-1] = '\0';
		/* Allocate new string */
		typ_tab[i].val = strdup( mimebuf );
		if ( typ_tab[i].val == (char*) 0 )
		    {
		    syslog( LOG_CRIT, "init_mime: strdup failed - %m" );
		    return -1;
		    }
		}
	    }
	typ_tab[i].ext_len = strlen( typ_tab[i].ext );
	typ_tab[i].val_len = strlen( typ_tab[i].val ) - fmtlen;
	if ( typ_tab[i].ext_len > max_typ_ext_len )
	     max_typ_ext_len = typ_tab[i].ext_len;
	}

    if ( ( free_mime_hash = calloc( n_typ_tab, sizeof(struct mime_hash) ) )
	== (struct mime_hash*) 0 )
	{
	    syslog( LOG_CRIT, "init_mime: calloc failed - %m" );
	    return -1;
	}
    for ( i = 0; i < n_typ_tab; ++i)
	{
	h = hash_mime( typ_tab[i].ext, typ_tab[i].ext_len );

	pmh1 = &free_mime_hash[i];
	pmh1->pmime = &typ_tab[i];

	if( typ_hash_tab[h] == (struct mime_hash*) 0 )
	    {
	    typ_hash_tab[h] = pmh1;
	    }
	else
	    {
	    pmh2 = typ_hash_tab[h];
	    typ_hash_tab[h] = pmh1;
	    pmh1->pnext = pmh2;
	    }
	}

    return 0;
    }


static void
figure_mime( httpd_conn* hc )
    {
    char* prev_dot;
    char* dot;
    char* ext = "";
    size_t ext_len = 0;
    int i;
    int	num_encodings = 0;
    int idx_encodings[MAX_MIME_ENCODINGS_LIMIT];

    hc->encodings[0] = '\0';
    hc->encodings_len = 0;

    /* Peel off encoding extensions until there aren't any more. */
    for ( prev_dot = &hc->expnfilename[strlen(hc->expnfilename)]; ;
	  prev_dot = dot )
	{
	for ( dot = prev_dot - 1;
	      dot >= hc->expnfilename && *dot != '.';
	    --dot )
	    ;
	if ( dot < hc->expnfilename )
	    {
	    /* No dot found.  No more encoding extensions, and no type
	    ** extension either.
	    */
	    hc->type     = hc->hs->def_mime_type;
	    hc->type_len = hc->hs->def_mime_type_len;
	    return;
	    }
	ext = dot + 1;
	ext_len = prev_dot - ext;

	if ( ext_len < 1 || ext_len > max_enc_ext_len )
	    /* No encoding extension can be found. */
	    /* Break and look for a type extension. */
	    break;

	/* Search the encodings table.  Linear search is fine here,
	** because there are only a few entries.
	*/

	for ( i = 0; i < n_enc_tab; ++i )
	    {
	    if ( ext_len == enc_tab[i].ext_len &&
		strncasecmp( ext, enc_tab[i].ext, ext_len ) == 0 )
		{
		/* (1) update encodings length, see also below */
		hc->encodings_len += (int) enc_tab[i].val_len + 1;

		/* If there are too many encodings then give up;
		** this file name looks suspicious, too bad.
		*/
		if ( num_encodings >= MAX_MIME_ENCODINGS_LIMIT )
		    {	/* binary mime type */
		    hc->type     = hc->hs->def_mime_typeb;
		    hc->type_len = hc->hs->def_mime_typeb_len;
		    return;
		    }
		idx_encodings[num_encodings++] = i;
		break;
		}
	    }
	if ( i >= n_enc_tab )
	    /* No encoding extension found. */
	    /* Break and look for a type extension. */
	    break;
	}

    /* Make the encoding list; encodings must be in the same order
    ** (left to right) they were applied to file content.
    */
    if ( num_encodings > 0 )
	{
	int	i2;
	httpd_realloc_str(
		    &hc->encodings, &hc->maxencodings,
		    hc->encodings_len + 2 );
	hc->encodings_len = 0;
	for ( i = num_encodings - 1, i2 = 0; i >= 0; --i )
	    {
		if ( hc->encodings[0] != '\0' )
		    {	/* (1) look above before changing this literal char */
		    hc->encodings[hc->encodings_len++] = ',';
		    }
		i2 = idx_encodings[i];
		(void) strcpy( &hc->encodings[hc->encodings_len],
				enc_tab[i2].val );
		hc->encodings_len += (int) enc_tab[i2].val_len;
	    }
	}

    /* Figure about extension */
    if ( ext_len > 0 && ext_len <= max_typ_ext_len )
	{
	unsigned int h;
	struct mime_hash *pmh1;

	h = hash_mime( ext, ext_len );

	for ( pmh1 = typ_hash_tab[h];
	     pmh1 != (struct mime_hash*) 0;
	     pmh1 = pmh1->pnext )
	    {
	    if ( pmh1->pmime->ext_len == ext_len &&
		strncasecmp( ext, pmh1->pmime->ext, ext_len ) == 0 )
		{   /* found ! */
		hc->type     = pmh1->pmime->val;
		hc->type_len = pmh1->pmime->val_len;
		return;
		}
	    }
	}

    /* unknown extension */
    hc->type     = hc->hs->def_mime_type;
    hc->type_len = hc->hs->def_mime_type_len;
    return;
    }


#if defined(EXECUTE_CHILD) && defined(CGI_TIMELIMIT)
static void
cgi_kill2( ClientData client_data, struct timeval* nowP )
    {
    pid_t pid;

    /* Before trying to kill the CGI process, reap any zombie processes.
    ** That may get rid of the CGI process.
    */
    (void) do_reap();

    pid = (pid_t) client_data.i;
    if ( kill( pid, SIGKILL ) == 0 )
	syslog( LOG_ERR, "hard-killed CGI process %d", pid );
    }


static void
cgi_kill( ClientData client_data, struct timeval* nowP )
    {
    pid_t pid;

    /* Before trying to kill the CGI process, reap any zombie processes.
    ** That may get rid of the CGI process.
    */
    (void) do_reap();

    pid = (pid_t) client_data.i;
    if ( kill( pid, SIGINT ) == 0 )
	{
	syslog( LOG_ERR, "killed CGI process %d", pid );
	/* In case this isn't enough, schedule an uncatchable kill. */
	if ( tmr_create( nowP, cgi_kill2, client_data, 5 * 1000L,
		TMR_ONE_SHOT ) == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(cgi_kill2) failed" );
	    exit( 103 );
	    }
	}
    }
#endif /* EXECUTE_CHILD && CGI_TIMELIMIT */


#ifdef GENERATE_INDEXES

struct ls_entry {
    char*  name;
    size_t namelen;
    };

/* qsort comparison routine - declared old-style on purpose, for portability. */
static int
name_compare( a, b )
    struct ls_entry* a;
    struct ls_entry* b;
    {
    return strcmp( a->name, b->name );
    }


static int
ls( httpd_conn* hc )
    {
    DIR* dirp;
    struct dirent* de;
    int namlen;
    size_t expnlen =  strlen( hc->expnfilename );
    size_t origlen =  strlen( hc->origfilename );
    static int maxnames = 0;
    int nnames;
    static struct ls_entry* nametab;
    static char* name;
    static int maxname = 0;
    static char* rname;
    static int maxrname = 0;
    static char* encrname;
    static int maxencrname = 0;
    FILE* fp;
    int i, r;
    struct stat sb;
    struct stat lsb;
    char modestr[20];
    char* linkprefix;
    char link[MAXPATHLEN+1];
    int linklen;
    char* filename;
    char* fileclass;
    time_t now = 0;
    char* timestr;
    ClientData client_data;

    /* Dynamic request, disable range */
    if ( hc->got_range )
	hc->got_range = 0;

    /*  We are not going to leave the socket open after a dirlist. */
    if ( hc->do_keep_alive )
	hc->do_keep_alive = 0;

    hc->encodings[0]  = '\0';
    hc->encodings_len = 0;
    hc->type     =       MIME_TYPE_TEXT_HTML;
    hc->type_len = SZLEN(MIME_TYPE_TEXT_HTML);

    dirp = opendir( hc->expnfilename );
    if ( dirp == (DIR*) 0 )
	{
	syslog( LOG_ERR, "opendir %.80s - %m", hc->expnfilename );
	httpd_send_err( hc, 404, err404title, err404titlelen,
		"", err404form, hc->encodedurl );
	return -1;
	}

    if ( hc->method == METHOD_HEAD )
	{
	send_mime(
	    hc, 200, ok200title, ok200titlelen, "", -1, hc->sb.st_mtime );
	closedir( dirp );
	}
    else if ( hc->method == METHOD_GET )
	{
	r = fork( );
	if ( r < 0 )
	    {
	    syslog( LOG_ERR, "fork - %m" );
	    httpd_send_err( hc, 500, err500title, err500titlelen,
		"", err500form, hc->encodedurl );
	    closedir( dirp );
	    return -1;
	    }
	if ( r == 0 )
	    {
	    char defangedname[512];

	    /* Child process. */
	    httpd_unlisten( hc->hs );

	    /* Set blocking mode */
	    (void) httpd_set_nonblock( hc->conn_fd, SOPT_OFF );

	    /* Clear response (this should not be required) */
	    httpd_clear_response( hc );

	    /* Fill response buffer */
	    send_mime( hc, 200, ok200title, ok200titlelen, "",
			-1, hc->sb.st_mtime );

	    /* Write response */
	    hc->response[hc->responselen] = '\0';
	    dprintf( hc->conn_fd, "%s", hc->response );

	    /* Clear sent response */
	    httpd_clear_response( hc );

	    {
	    char *decodedurl = hc->decodedurl;

	    defangedname[0] = '\0';
	    if ( need_defang( decodedurl ) )
		{
		defang( decodedurl, defangedname, sizeof(defangedname) );
		decodedurl = defangedname;
		}

	    (void) dprintf( hc->conn_fd, "\
<HTML>\n\
<HEAD><TITLE>Index of %.512s</TITLE></HEAD>\n\
<BODY BGCOLOR=\"#99cc99\" TEXT=\"#000000\" LINK=\"#2020ff\" VLINK=\"#4040cc\">\n\
<H2>Index of %.512s</H2>\n\
<PRE>\n\
Mode  Links  Bytes  Last-Changed  Name\n\
<HR>\n",
		decodedurl, decodedurl );
	    }

	    //fflush( fp );

#ifdef CGI_NICE
	    /* Set priority. */
	    (void) nice( CGI_NICE );
#endif /* CGI_NICE */

	    /* Read in names. */
	    nnames = 0;
	    while ( ( de = readdir( dirp ) ) != 0 )     /* dirent or direct */
		{
		if ( nnames >= maxnames )
		    {
		    if ( maxnames == 0 )
			{
			maxnames = 100;
			nametab = NEW( struct ls_entry, maxnames );
			}
		    else
			{
			maxnames *= 2;
			nametab = RENEW( nametab, struct ls_entry, maxnames );
			}
		    if ( nametab == (struct ls_entry*) 0 )
			{
			syslog( LOG_ERR,
			"out of memory reallocating directory array" );
			exit( 105 );
			}
		    }
		namlen = NAMLEN(de);
#ifdef INDEXES_SKIP_DOTFILES

		/* eventually skip files starting with dots */
		if ( de->d_name[0] == '.' )
		    {
#ifdef INDEXES_SKIP_DOTCURDIR
		    if ( de->d_name[1] == '\0' )
			continue;
#endif
		    if ( namlen != 2 )
			continue;
		    if ( de->d_name[1] != '.' )
			continue;
		    /* ".." is allowed only if we are not at web root */
		    if ( hc->decodedurl[0] == '/' &&
			 hc->decodedurl[1] == '\0' )
			continue;
		   }

#else  /* INDEXES_SKIP_DOTFILES */

		/* skip anyway .. if we are at web root */
		if ( namlen <= 2 &&
		     de->d_name[0] == '.' &&
		    (
#ifdef INDEXES_SKIP_DOTCURDIR
		     de->d_name[1] == '\0' ||
#endif
		    ( de->d_name[1] == '.' &&
		      hc->decodedurl[0] == '/' &&
		      hc->decodedurl[1] == '\0'
		    )
		    ) )
		    continue;
#endif /* !INDEXES_SKIP_DOTFILES */

		/* Alloc space for file name */
		nametab[nnames].name = NEW( char, (namlen+1) );
		if ( nametab[nnames].name == (char*) 0 )
		    {
		    syslog( LOG_ERR,
			"out of memory allocating a directory name" );
		    exit( 105 );
		    }
		/* Copy file name */
		(void) memcpy( nametab[nnames].name, de->d_name, namlen );
		nametab[nnames].name[namlen] = '\0';
		nametab[nnames].namelen = namlen;
		++nnames;
		}
	    closedir( dirp );

	    /* Sort the names. */
	    qsort( nametab, nnames, sizeof(*nametab), name_compare );

	    /* Get time string. */
	    now = time( (time_t*) 0 );

	    /* Generate output. */
	    for ( i = 0; i < nnames; ++i )
		{
		size_t rnamelen = nametab[i].namelen;
		char *dircomment = "";

		httpd_realloc_str(
		    &name, &maxname,
		    expnlen + 1 + nametab[i].namelen );
		httpd_realloc_str(
		    &rname, &maxrname,
		    origlen + 1 + nametab[i].namelen );

		if ( hc->expnfilename[0] == '\0' ||
		      ( hc->expnfilename[0] == '.' &&
			hc->expnfilename[1] == '\0' ) )
		    {
		    (void) strcpy( name,  nametab[i].name );
		    (void) strcpy( rname, nametab[i].name );
		    }
		else
		    {
		    (void) memcpy( name, hc->expnfilename, expnlen );
		    name[expnlen] = '/';
		    (void) strcpy( &name[expnlen+1], nametab[i].name );

		    if ( hc->origfilename[0] == '.' &&
			 hc->origfilename[1] == '\0' )
			{
			(void) strcpy( rname, nametab[i].name );
			}
		    else
			{
			(void) memcpy( rname, hc->origfilename, origlen );
			(void) strcpy( &rname[origlen], nametab[i].name );
			rnamelen += origlen;
			}
		    }
		httpd_realloc_str(
		    &encrname, &maxencrname, 3 * rnamelen + 1 );
		strencode( encrname, maxencrname, rname );

		if ( stat( name, &sb ) < 0 || lstat( name, &lsb ) < 0 )
		    continue;

		linkprefix = "";
		link[0] = '\0';
		/* Break down mode word.  First the file type. */
		switch ( lsb.st_mode & S_IFMT )
		    {
		    case S_IFIFO:  modestr[0] = 'p'; break;
		    case S_IFCHR:  modestr[0] = 'c'; break;
		    case S_IFDIR:  modestr[0] = 'd'; break;
		    case S_IFBLK:  modestr[0] = 'b'; break;
		    case S_IFREG:  modestr[0] = '-'; break;
		    case S_IFSOCK: modestr[0] = 's'; break;
		    case S_IFLNK:  modestr[0] = 'l';
		    linklen = readlink( name, link, ( sizeof(link) - 1 ) );
		    if ( linklen != -1 )
			{
			link[linklen] = '\0';
			linkprefix = " -&gt; ";
			}
		    break;
		    default:       modestr[0] = '?'; break;
		    }
		/* Now the world permissions.  Owner and group permissions
		** are not of interest to web clients.
		*/
		modestr[1] = ( lsb.st_mode & S_IRACC ) ? 'r' : '-';
		modestr[2] = ( lsb.st_mode & S_IWACC ) ? 'w' : '-';
		modestr[3] = ( lsb.st_mode & S_IXACC ) ? 'x' : '-';
		modestr[4] = '\0';

		/* We also leave out the owner and group name, they are
		** also not of interest to web clients.  Plus if we're
		** running under chroot(), they would require a copy
		** of /etc/passwd and /etc/group, which we want to avoid.
		*/

		timestr = ctime( &lsb.st_mtime );
		timestr[ 0] = timestr[ 4];
		timestr[ 1] = timestr[ 5];
		timestr[ 2] = timestr[ 6];
		timestr[ 3] = ' ';
		timestr[ 4] = timestr[ 8];
		timestr[ 5] = timestr[ 9];
		timestr[ 6] = ' ';
		if ( now - lsb.st_mtime > 60*60*24*182 )        /* 1/2 year */
		    {
		    timestr[ 7] = ' ';
		    timestr[ 8] = timestr[20];
		    timestr[ 9] = timestr[21];
		    timestr[10] = timestr[22];
		    timestr[11] = timestr[23];
		    }
		else
		    {
		    timestr[ 7] = timestr[11];
		    timestr[ 8] = timestr[12];
		    timestr[ 9] = ':';
		    timestr[10] = timestr[14];
		    timestr[11] = timestr[15];
		    }
		timestr[12] = '\0';

		/* The ls -F file class. */
		switch ( sb.st_mode & S_IFMT )
		    {
		    case S_IFDIR:  fileclass = "/"; break;
		    case S_IFSOCK: fileclass = "="; break;
		    case S_IFLNK:  fileclass = "@"; break;
		    default:
		    fileclass = ( sb.st_mode & S_IXACC ) ? "*" : "";
		    break;
		    }
		filename = nametab[i].name;
#ifdef INDEXES_REMARK_DOTDIRS
		if (link[0] == '\0' &&
		    filename[0] == '.')
		{
		    if (filename[1] == '.' &&
			filename[2] == '\0')
			{
			filename = "Parent directory";
			dircomment = "  (../ go up one level)";
			}
		    else
		    if (filename[1] == '\0')
			{
			filename = "Reload directory";
			dircomment = "  (./  reload current directory)";
			}
		}
#endif /* INDEXES_REMARK_DOTDIRS */

		/* Eventually escape HTML entities in filename */
		/* well we don't bother about binary characters, etc. */
		if ( need_defang( filename ) )
		    {
		    defang( filename, defangedname, sizeof(defangedname) );
		    filename = defangedname;
		    }

		/* And print. */
		(void)  dprintf( hc->conn_fd,
		"%s %3ld  %8ld  %s  <A HREF=\"/%.500s%s\">%.512s</A>%s%s%s%s\n",
		    modestr, (long) lsb.st_nlink, (long) lsb.st_size, timestr,
		    encrname, S_ISDIR(sb.st_mode) ? "/" : "",
		    filename, linkprefix, link, fileclass, dircomment );
		}

#ifdef USE_SCTP
	    if ( hc->is_sctp )
		{
		const char *trailer = "    </pre>\n  </body>\n</html>\n";
		(void) httpd_write_sctp( hc->conn_fd, trailer, strlen(trailer), hc->use_eeor, 1, 0, hc->sid );
		}
	    else
		(void) dprintf( hc->conn_fd, "    </pre>\n  </body>\n</html>\n" );
#else
	    (void) dprintf( hc->conn_fd, "    </pre>\n  </body>\n</html>\n" );
#endif


	    //(void) fprintf( fp, "\n<HR>\n</PRE>\n</BODY>\n</HTML>\n" );
	    //(void) fclose( fp );
	    exit( 0 );
	    }

	/* Parent process. */

	httpd_clear_response( hc );
	closedir( dirp );
	syslog( LOG_INFO,
		"spawned indexing process %d for directory '%.200s'",
		r, hc->expnfilename );
	do_cond_reap();
#ifdef CGI_TIMELIMIT
	/* Schedule a kill for the child process, in case it runs too long */
	client_data.i = r;
	if ( tmr_create( (struct timeval*) 0, cgi_kill, client_data, CGI_TIMELIMIT * 1000L, TMR_ONE_SHOT ) == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(cgi_kill ls) failed" );
	    exit( 106 );
	    }
#endif /* CGI_TIMELIMIT */
	hc->status = 200;
	hc->bytes_sent = CGI_BYTECOUNT;
	hc->should_linger = 0;
	}
    else
	{   /* method not allowed for this URL (POST, etc.) */
	closedir( dirp );
	/* eventually eat unused input */
	if ( hc->method == METHOD_POST )
	    hc->should_linger = 1;
	httpd_send_err405( hc,
		METHOD_ID2BIT(METHOD_GET) |
		METHOD_ID2BIT(METHOD_HEAD),
		HTTPD_METHOD_STR( hc->method ) );
	return -1;
	}

    return 0;
    }

#endif /* GENERATE_INDEXES */


#ifdef SERVER_NAME_LIST
static char*
hostname_map( char* hostname )
    {
    int len, n;
    static char* list[] = { SERVER_NAME_LIST };

    len = strlen( hostname );
    for ( n = sizeof(list) / sizeof(*list) - 1; n >= 0; --n )
	if ( strncasecmp( hostname, list[n], len ) == 0 )
	    if ( list[n][len] == '/' )  /* check in case of a substring match */
		return &list[n][len + 1];
    return (char*) 0;
    }
#endif /* SERVER_NAME_LIST */


#ifdef EXECUTE_CGI

static char*
build_env( const char* fmt, const char* arg )
    {
    char* cp;
    int size;
    static char* buf;
    static int maxbuf = 0;

    size = strlen( fmt ) + strlen( arg );
    if ( size > maxbuf )
	httpd_realloc_str( &buf, &maxbuf, size );
    (void) my_snprintf( buf, maxbuf,
	fmt, arg );
    cp = strdup( buf );
    if ( cp == (char*) 0 )
	{
	syslog( LOG_ERR, "out of memory copying environment variable" );
	exit( 107 );
	}
    return cp;
    }


/* Set up environment variables. Be real careful here to avoid
** letting malicious clients overrun a buffer.  We don't have
** to worry about freeing stuff since we're a sub-process.
*/
static char**
make_envp( httpd_conn* hc, char* cgipattern )
    {
    static char* envp[50];
    int envn;
    int len = 0;
    char* cp;
    char *script = "";
    char buf[256];

    /* Build environment */
    envn = 0;
    envp[envn++] = build_env( "PATH=%s", CGI_PATH );
#ifdef CGI_LD_LIBRARY_PATH
    envp[envn++] = build_env( "LD_LIBRARY_PATH=%s", CGI_LD_LIBRARY_PATH );
#endif /* CGI_LD_LIBRARY_PATH */
    envp[envn++] = build_env( "SERVER_SOFTWARE=%s", SERVER_SOFTWARE );
    /* If vhosting, use that server-name here. */
    if ( hc->hs->vhost && hc->hostname != (char*) 0 )
	cp = hc->hostname;
    else
	cp = hc->hs->server_hostname;
    if ( cp != (char*) 0 )
	envp[envn++] = build_env( "SERVER_NAME=%s", cp );
    envp[envn++] = "GATEWAY_INTERFACE=CGI/1.1";
    envp[envn++] = build_env("SERVER_PROTOCOL=%s", hc->protocol);
    (void) my_snprintf( buf, sizeof(buf), "%d", hc->hs->port );
    envp[envn++] = build_env( "SERVER_PORT=%s", buf );
    envp[envn++] = build_env(
	"REQUEST_METHOD=%s", HTTPD_METHOD_STR( hc->method ) );
    envp[envn++] = build_env( "REQUEST_URI=%s", hc->decodedurl );

    /* Construct script filename. */
    if ( hc->expnfilename[0] == '/' )
	script = hc->expnfilename;
    else
	{
	len = hc->hs->cwd_len + strlen( hc->expnfilename ) + 1;
	script = NEW( char, len + 1 );
	if ( script == (char*) 0 )
	    script = hc->expnfilename;	/* ignore error */
	else
	    (void) my_snprintf( script, len,
		"%s%s", hc->hs->cwd, hc->expnfilename );
	}

    /* Pathinfo stuff */
    if ( hc->pathinfo[0] != '\0' )
	{
	char* cp2;
	envp[envn++] = build_env( "PATH_INFO=/%s", hc->pathinfo );
	len = hc->hs->cwd_len + strlen( hc->pathinfo ) + 1;
	cp2 = NEW( char, len + 1 );
	if ( cp2 != (char*) 0 )
	    {
	    (void) my_snprintf( cp2, len,
		"%s%s", hc->hs->cwd, hc->pathinfo );
	    envp[envn++] = build_env( "PATH_TRANSLATED=%s", cp2 );
	    }
	}
    else
	envp[envn++] = build_env( "PATH_TRANSLATED=%s", script );
    envp[envn++] = build_env( "SCRIPT_FILENAME=%s", script );
    envp[envn++] = build_env(
	"SCRIPT_NAME=/%s", strcmp( hc->origfilename, "." ) == 0 ?
	"" : hc->origfilename );
    if ( hc->query[0] != '\0')
	envp[envn++] = build_env( "QUERY_STRING=%s", hc->query );
    envp[envn++] = build_env(
	"REMOTE_ADDR=%s", httpd_ntoa( &hc->client_addr ) );
	if ( hc->client_addr.sa.sa_family == AF_INET )
	(void) my_snprintf( buf, sizeof(buf), "%d", (int) ntohs( hc->client_addr.sa_in.sin_port ) );
	else
	(void) my_snprintf( buf, sizeof(buf), "%d", (int) ntohs( hc->client_addr.sa_in6.sin6_port ) );
	envp[envn++] = build_env( "REMOTE_PORT=%s", buf );
	#ifdef USE_SCTP
	if ( hc->is_sctp )
	{
	uint16_t remote_encaps_port;
	#ifdef SCTP_REMOTE_UDP_ENCAPS_PORT
	socklen_t optlen;
	struct sctp_udpencaps udpencaps;

	memset( &udpencaps, 0, sizeof(struct sctp_udpencaps) );
	memcpy( &udpencaps.sue_address, &hc->client_addr, sizeof( hc->client_addr ) );
	optlen = (socklen_t)sizeof( struct sctp_udpencaps );
	if ( getsockopt( hc->conn_fd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &udpencaps, &optlen ) < 0 )
		remote_encaps_port = 0;
	else
		remote_encaps_port = ntohs( udpencaps.sue_port );
	#else
	remote_encaps_port = 0;
	#endif
	if ( remote_encaps_port > 0 )
		{
	#ifdef __FreeBSD__
		uint32_t local_encaps_port;
		size_t len;

		len = sizeof( uint32_t );
		if ( sysctlbyname( "net.inet.sctp.udp_tunneling_port", &local_encaps_port, &len, NULL, 0 ) < 0 )
		local_encaps_port = 0;
		(void) my_snprintf( buf, sizeof(buf), "%d", (int) local_encaps_port );
		envp[envn++] = build_env( "SERVER_UDP_ENCAPS_PORT=%s", buf );
	#endif
		(void) my_snprintf( buf, sizeof(buf), "%d", (int) remote_encaps_port );
		envp[envn++] = build_env( "REMOTE_UDP_ENCAPS_PORT=%s", buf );
		envp[envn++] = build_env( "TRANSPORT_PROTOCOL=%s", "SCTP/UDP" );
		}
	else
		envp[envn++] = build_env( "TRANSPORT_PROTOCOL=%s", "SCTP" );
	}
	else
	envp[envn++] = build_env( "TRANSPORT_PROTOCOL=%s", "TCP" );
	#else
	envp[envn++] = build_env( "TRANSPORT_PROTOCOL=%s", "TCP" );
	#endif

    if ( hc->referer[0] != '\0' )
	envp[envn++] = build_env( "HTTP_REFERER=%s", hc->referer );
    if ( hc->useragent[0] != '\0' )
	envp[envn++] = build_env( "HTTP_USER_AGENT=%s", hc->useragent );
    if ( hc->accept[0] != '\0' )
	envp[envn++] = build_env( "HTTP_ACCEPT=%s", hc->accept );
    if ( hc->accepte[0] != '\0' )
	envp[envn++] = build_env( "HTTP_ACCEPT_ENCODING=%s", hc->accepte );
    if ( hc->acceptl[0] != '\0' )
	envp[envn++] = build_env( "HTTP_ACCEPT_LANGUAGE=%s", hc->acceptl );
    if ( hc->cookie[0] != '\0' )
	envp[envn++] = build_env( "HTTP_COOKIE=%s", hc->cookie );
    if ( hc->contenttype[0] != '\0' )
	envp[envn++] = build_env( "CONTENT_TYPE=%s", hc->contenttype );
    if ( hc->hdrhost[0] != '\0' )
	envp[envn++] = build_env( "HTTP_HOST=%s", hc->hdrhost );
    if ( hc->contentlength != -1 )
	{
	(void) my_snprintf( buf, sizeof(buf),
	    "%ld", (long) hc->contentlength );
	envp[envn++] = build_env( "CONTENT_LENGTH=%s", buf );
	}
#ifdef AUTH_FILE
    if ( hc->remoteuser[0] != '\0' )
	envp[envn++] = build_env( "REMOTE_USER=%s", hc->remoteuser );
    /* We only support Basic auth at the moment. */
    if ( hc->authorization[0] != '\0' )
	envp[envn++] = build_env( "AUTH_TYPE=%s", "Basic" );
#endif /* AUTH_FILE */
    if ( getenv( "TZ" ) != (char*) 0 )
	envp[envn++] = build_env( "TZ=%s", getenv( "TZ" ) );
    if ( cgipattern != (char*) 0 )
	envp[envn++] = build_env( "CGI_PATTERN=%s", cgipattern );

    envp[envn] = (char*) 0;
    return envp;
    }


/* Set up argument vector.  Again, we don't have to worry about freeing stuff
** since we're a sub-process.  This gets done after make_envp() because we
** scribble on hc->query.
*/
static char**
make_argp( httpd_conn* hc, char* cliprogram )
    {
    int argn;
    char** argp;
    char* cp1;
    char* cp2;

    argn = 0;
    /* By allocating an arg slot for every character in the query, plus
    ** one for the filename and one for the NULL, we are guaranteed to
    ** have enough.  We could actually use strlen/2.
    */
    argp = NEW( char*, strlen( hc->query ) + 3 );
    if ( argp == (char**) 0 )
	return (char**) 0;

    if ( cliprogram != (char*) 0 )
	argp[argn++] = cliprogram;

    argp[argn] = strrchr( hc->expnfilename, '/' );
    if ( argp[argn] != (char*) 0 )
	++argp[argn];
    else
	argp[argn] = hc->expnfilename;

    ++argn;
    /* According to the CGI spec at http://hoohoo.ncsa.uiuc.edu/cgi/cl.html,
    ** "The server should search the query information for a non-encoded =
    ** character to determine if the command line is to be used, if it finds
    ** one, the command line is not to be used."
    */
    if ( strchr( hc->query, '=' ) == (char*) 0 )
	{
	for ( cp1 = cp2 = hc->query; *cp2 != '\0'; ++cp2 )
	    {
	    if ( *cp2 == '+' )
		{
		*cp2 = '\0';
		strdecode( cp1, cp1 );
		argp[argn++] = cp1;
		cp1 = cp2 + 1;
		}
	    }
	if ( cp2 != cp1 )
	    {
	    strdecode( cp1, cp1 );
	    argp[argn++] = cp1;
	    }
	}

    argp[argn] = (char*) 0;
    return argp;
    }


/* This routine is used only for POST requests.  It reads the data
** from the request and sends it to the child process.  The only reason
** we need to do it this way instead of just letting the child read
** directly is that we have already read part of the data into our
** buffer or because not all data has been read by the previous read(s).
*/

#define BUFSIZE 1024

static void
cgi_interpose_input( httpd_conn* hc, int wfd )
    {
    int c = 0;
	ssize_t r;
#ifdef USE_SCTP
    ssize_t r1, r2;
    char buf1[BUFSIZE];
    char buf2[BUFSIZE];
    char *buf;
#else
    char buf[BUFSIZE];
#endif


    /* restore blocking mode (if it was lost) */
    (void) httpd_set_nonblock( hc->conn_fd, SOPT_OFF );

    if ( hc->read_idx > hc->checked_idx )
	c = hc->read_idx - hc->checked_idx;

    if ( c > 0 )
	{
	int idx = hc->checked_idx;
	int cnt = c;
	int nw;
	do
	    {
	    nw = write( wfd, &(hc->read_buf[idx]), cnt );
	    if ( nw == -1 )
		{
		if ( errno == EINTR )
		    continue;
		if ( errno == EAGAIN )
		    {
		    sleep( 1 );
		    continue;
		    }
		}
	    if ( nw <= 0 )
		return;
	    idx += nw;
	    cnt = hc->read_idx - idx;
	    }
	while( cnt > 0 );
	}
    while ( c < hc->contentlength )
	{
	r = read( hc->conn_fd, buf, MIN( sizeof(buf), hc->contentlength - c ) );
	if ( r < 0 )
	    {
	    if ( errno == EINTR )
		continue;
	    if ( errno == EAGAIN )
		{
		sleep( 1 );
		continue;
		}
	    }
	if ( r <= 0 )
	    return;
	else
	    {
	    int w = 0, nw = 0;
	    do
		{
		w = write( wfd, &buf[nw], ( r - nw ) );
		if ( w == -1 )
		    {
		    if ( errno == EINTR )
			continue;
		    if ( errno == EAGAIN )
			{
			sleep( 1 );
			continue;
			}
		    }
		if ( w <= 0 )
		    break;
		nw += w;
		}
	    while ( nw < r );
	    c += nw;
	    if ( nw < r )
		break;
	    }
	}
    post_post_garbage_hack( hc );
    }


/* Special hack to deal with broken browsers that send a LF or CRLF
** after POST data, causing TCP resets - we should just try
** to read and discard up to 2 bytes but we try to read some more
** (after all the connection is going to be closed).
** NOTE: creating an interposer process for all POST CGIs
** even for those whose POST data is very short is (in theory)
** unacceptably expensive.  The eventual fix will come when interposing
** gets integrated into the main loop as a tasklet instead of a process.
*/
static void
post_post_garbage_hack( httpd_conn* hc )
    {
    int r;
    char buf[16];

    /* Set non-blocking mode */
    (void) httpd_set_nonblock( hc->conn_fd, SOPT_ON );
    do
	{
	r = read( hc->conn_fd, buf, sizeof(buf) );
	}
    while( r == -1 && errno == EINTR );
    }


/* This routine is used for parsed-header CGIs.  The idea here is that the
** CGI can return special headers such as "Status:" and "Location:" which
** change the return status of the response.  Since the return status has to
** be the very first line written out, we have to accumulate all the headers
** and check for the special ones before writing the status.  Then we write
** out the saved headers and proceed to echo the rest of the response.
*/
static void
cgi_interpose_output( httpd_conn* hc, int rfd )
    {
    int status;
    int eoh = 0;	/* end of HTTP headers */
    int r = 0, w = 0, nw = 0;
    char buf[1024];
    int headers_size, headers_len;
    char* headers;
    char* br;
    char* cp;

    /* restore block-mode (if it was lost) */
    (void) httpd_set_nonblock( hc->conn_fd, SOPT_OFF );

    /* we start with a normal condition */
    status = 200;

    /* Slurp in all headers. */
    headers_size = 0;
    headers = (char *) 0;
    httpd_realloc_str( &headers, &headers_size, 512 );
    headers_len = 0;
#ifdef USE_SCTP
    buf = buf1;
#endif

    for (;;)
	{
	do
	    {
		r = read( rfd, buf, BUFSIZE );

	    }
	while( r == -1 && errno == EINTR );

	if ( r <= 0 )
	    {
	    br = &(headers[headers_len]);
	    break;
	    }
	httpd_realloc_str( &headers, &headers_size, headers_len + r );
	(void) memcpy( &(headers[headers_len]), buf, r );
	headers_len += r;
	headers[headers_len] = '\0';
	if ( ( br = strstr( headers, HTTP_CRLF_STR HTTP_CRLF_STR ) )
		!= (char*) 0 ||
	     ( br = strstr( headers, HTTP_LF_STR HTTP_LF_STR ) ) != (char*) 0 )
	    /* OK, headers have just been read */
	    {
	    eoh = 1;
	    break;
	    }
#if	defined(CGI_MAX_HEADERS_LENGTH) && (CGI_MAX_HEADERS_LENGTH > 0)
	/* no, check for headers too long */
	if (headers_len > CGI_MAX_HEADERS_LENGTH)
	    /* yeah, we don't want to go out of memory because of */
	    /* a buggy CGI which is writing huge amounts of crappy data */
	    /* instead of HTTP headers */
	    /* NOTE: we let a small CGI response without HTTP headers */
	    break;
#endif
	}

    /* if there were no headers, bail */
    if ( headers_len < 1 )
	return;

#if	defined(CGI_MAX_HEADERS_LENGTH) && (CGI_MAX_HEADERS_LENGTH > 0)
    if ( headers_len > CGI_MAX_HEADERS_LENGTH )
	{
	/* HTTP headers too long, write an error response and stop */
	/* so buggy CGI is hit by a signal (SIGPIPE) */
	httpd_clear_response( hc );
	httpd_send_err( hc, 500, err500title, err500titlelen, "",
	ERROR_FORM( err500form, "HTTP headers too long or not correctly ended by this CGI '%.80s'.\n" ),
		hc->encodedurl );
	do
	    {
	    w = write( hc->conn_fd, hc->response, hc->responselen );
	    }
	while( w == -1 && errno == EINTR );
	httpd_close_conn_wr( hc );
	syslog( LOG_ERR,
	"CGI '%.80s': HTTP headers too long %d > %d (missing empty line)",
		hc->expnfilename, headers_len, CGI_MAX_HEADERS_LENGTH );
	return;
	}
#endif

    /* Figure out the status.  Look for a Status: or Location: header; */
    /* else if there's and HTTP header line, get it from there; else */
    /* use default status (200 or 500) */
    if ( strncmp( headers, "HTTP/", 5 ) == 0)
	{
	cp = headers;
	cp += strcspn( cp, HTTP_BTAB_STR );
	status = atoi( cp );
	eoh = 2;
	}
    if ( ( cp = strstr( headers, "Status:" ) ) != (char*) 0 &&
	   cp < br &&
	 ( cp == headers || *(cp-1) == CHR_LF ) )
	{
	cp += 7;
	cp += strspn( cp, HTTP_BTAB_STR );
	status = atoi( cp );
	eoh = 3;
	}
    if ( ( cp = strstr( headers, "Location:" ) ) != (char*) 0 &&
	   cp < br &&
	 ( cp == headers || *(cp-1) == CHR_LF ) )
	{
	status = 302;
	eoh = 4;
	}

    /* Write the status line. */
    (void) my_snprintf( buf, sizeof(buf), "HTTP/1.0 %d %s%s",
		status, httpd_err_title( status ),
		( eoh ? HTTP_CRLF_STR : HTTP_CRLF_STR HTTP_CRLF_STR ) );

#ifdef USE_SCTP
    if ( hc->is_sctp )
	{
	int headers_written, buffer_cached;

	headers_written = 0;
	buffer_cached = 0;
	for (;;)
	    {
	    r = read( rfd, buf, BUFSIZE );
	    if ( r < 0 && ( errno == EINTR || errno == EAGAIN ) )
		{
		sleep( 1 );
		continue;
		}
	    if (headers_written == 0)
		{
		int eor;

		if ( (headers_len == 0) && (r == 0) )
		    eor = 1;
		else
		    eor = 0;
		(void) my_snprintf( buf2, BUFSIZE, "HTTP/1.0 %d %s\015\012", status, title );
		(void) httpd_write_fully_sctp( hc, buf2, strlen( buf2 ),
		                               hc->use_eeor, eor, hc->send_at_once_limit );
		if ( r == 0 )
		    eor = 1;
		else
		    eor = 0;
		(void) httpd_write_fully_sctp( hc, headers, headers_len,
		                               hc->use_eeor, eor, hc->send_at_once_limit );
		headers_written = 1;
		}
	    if ( r <= 0 )
		break;
	    if ( buffer_cached == 1 )
		{
		if (buf == buf1)
		    {
		    if ( httpd_write_fully_sctp( hc, buf2, r2,
		                                 hc->use_eeor, 0,
		                                 hc->send_at_once_limit ) != r2 )
			break;
		    }
		else
		    {
		    if ( httpd_write_fully_sctp( hc, buf1, r1,
		                                 hc->use_eeor, 0,
		                                 hc->send_at_once_limit ) != r1 )
			break;
		    }
		buffer_cached = 0;
		}
	    if ( buf == buf1 )
		{
		r1 = r;
		buf = buf2;
		}
	    else
		{
		r2 = r;
		buf = buf1;
		}
	    buffer_cached = 1;
	    }
	if ( buffer_cached == 1 )
	    {
	    if ( buf == buf1 )
		(void)httpd_write_fully_sctp( hc, buf2, r2,
		                              hc->use_eeor, 1,
		                              hc->send_at_once_limit );
	    else
		(void)httpd_write_fully_sctp( hc, buf1, r1,
		                              hc->use_eeor, 1,
		                              hc->send_at_once_limit );
	    }
	}
    else
	{
	(void) my_snprintf( buf, BUFSIZE, "HTTP/1.0 %d %s\015\012", status, title );
	(void) httpd_write_fully( hc->conn_fd, buf, strlen( buf ) );

	/* Write the saved headers. */
	(void) httpd_write_fully( hc->conn_fd, headers, headers_len );

	/* Echo the rest of the output. */
	for (;;)
	    {
	    r = read( rfd, buf, BUFSIZE );
	    if ( r < 0 && ( errno == EINTR || errno == EAGAIN ) )
		{
		sleep( 1 );
		continue;
		}
	    if ( r <= 0 )
		break;
	    if ( httpd_write_fully( hc->conn_fd, buf, r ) != r )
		break;
	    }
	}
#else
    (void) my_snprintf( buf, BUFSIZE, "HTTP/1.0 %d %s\015\012", status, title );
	(void) httpd_write_fully( hc->conn_fd, buf, strlen( buf ) );


    /* Write the saved headers. */
    do
	{
	w = write( hc->conn_fd, headers, headers_len );
	}
    while( w == -1 && errno == EINTR );

    /* we don't care about freeing headers because this is a subprocess */
    /* and allocated memory is automatically fred after exit() */

    /* Echo the rest of the output. */
    for (;;)
	{
	r = read( rfd, buf, BUFSIZE );
	if ( r == -1 )
	    {
	    if ( errno == EINTR )
		continue;
	    if ( errno == EAGAIN )
		{
		sleep( 1 );
		continue;
		}
	    }
	if ( r <= 0 )
	    break;
	nw = 0;
	do
	    {
	    w = write( hc->conn_fd, &buf[nw], ( r - nw ) );
	    if ( w == -1 )
		{
		if ( errno == EINTR )
		    continue;
		if ( errno == EAGAIN )
		    {
		    sleep( 1 );
		    continue;
		    }
		}
	    if ( w <= 0 )
		break;
	    nw += w;
	    }
	while( nw < r );
	if ( nw < r )
	    break;
	}
#endif

    httpd_close_conn_wr( hc );
    }


/* CGI child process.
** If this child forks then, when it dies, its children become orphans and
** thus they should be adopted by init(8); if this does not happen
** because executing a process listing (ps cax) you see lots of
** thttpd <defunct> (zombies) that NEVER go away, then your OS is BUGGY;
** in this case try to use nph-* CGIs with GET method only.
*/
static void
cgi_child( httpd_conn* hc, char* cliprogram, char* cgipattern )
    {
    int r;
    char** argp;
    char** envp;
    char* binary;
    char* directory;

    /* Unset close-on-exec flag for this socket.  This actually shouldn't
    ** be necessary, according to POSIX a dup()'d file descriptor does
    ** *not* inherit the close-on-exec flag, its flag is always clear.
    ** However, Linux messes this up and does copy the flag to the
    ** dup()'d descriptor, so we have to clear it.  This could be
    ** ifdeffed for Linux only.
    */
    (void) fcntl( hc->conn_fd, F_SETFD, 0 );

    /* Close the syslog descriptor so that the CGI program can't
    ** mess with it.  All other open descriptors should be either
    ** the listen socket(s), sockets from accept(), or the file-logging
    ** fd, and all of those are set to close-on-exec, so we don't
    ** have to close anything else.
    */
    closelog();

    /* If the socket happens to be using one of the stdin/stdout/stderr
    ** descriptors, move it to another descriptor so that the dup2 calls
    ** below don't screw things up.  We arbitrarily pick fd 3 - if there
    ** was already something on it, we clobber it, but that doesn't matter
    ** since at this point the only fd of interest is the connection.
    ** All others will be closed on exec.
    */
    if ( hc->conn_fd == STDIN_FILENO ||
         hc->conn_fd == STDOUT_FILENO ||
         hc->conn_fd == STDERR_FILENO )
	{
	int newfd = dup2( hc->conn_fd, STDERR_FILENO + 1 );
	if ( newfd >= 0 )
	    hc->conn_fd = newfd;
	/* If the dup2 fails, shrug.  We'll just take our chances.
	** Shouldn't happen though.
	*/
	}

    /* Split the program into directory and binary, so we can chdir()
    ** to the program's own directory.  This isn't in the CGI 1.1
    ** spec, but it's what other HTTP servers do.
    */
    directory = strdup( hc->expnfilename );
    if ( directory == (char*) 0 )
	binary = hc->expnfilename;      /* ignore errors */
    else
	{
	binary = strrchr( directory, '/' );
	if ( binary == (char*) 0 )
	    binary = hc->expnfilename;
	else
	    {
	    *binary++ = '\0';
	    (void) chdir( directory );  /* ignore errors */
	    }
	}

    /* If we run an interpreter then use its pathname */
    if ( cliprogram != (char*) 0 )
	binary = cliprogram;

    /* Make the environment vector. */
    envp = make_envp( hc, cgipattern );

    /* Make the argument vector. */
    argp = make_argp( hc, cliprogram );

    /* Set up stdin.  For POSTs we have to set up a pipe from an
    ** interposer process, because we may have read some data
    ** into our buffer and because browser can send more data after
    ** an initial delay.
    */
    if ( hc->method == METHOD_POST )
	{
	int p[2];

	if ( pipe( p ) < 0 )
	    {
	    syslog( LOG_ERR, "pipe - %m" );
	    httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	    httpd_write_blk_response( hc );
	    exit( 108 );
	    }
	r = fork( );
	if ( r < 0 )
	    {
	    syslog( LOG_ERR, "fork - %m" );
	    httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	    httpd_write_blk_response( hc );
	    exit( 109 );
	    }
	if ( r == 0 )
	    {
	    /* Interposer process. */
	    (void) close( p[0] );
	    cgi_interpose_input( hc, p[1] );
	    exit( 0 );
	    }
	/* Need to schedule a kill for process r; but in the main process! */
	(void) close( p[1] );
	if ( p[0] != STDIN_FILENO )
	    {
	    (void) dup2( p[0], STDIN_FILENO );
	    (void) close( p[0] );
	    }
	}
    else
	{
	/* Otherwise, the request socket is stdin. */
	if ( hc->conn_fd != STDIN_FILENO )
	    (void) dup2( hc->conn_fd, STDIN_FILENO );
	}

    /* Set up stdout/stderr.  If we're doing CGI header parsing,
    ** we need an output interposer too.
    */
    if ( strncmp( argp[0], "nph-", 4 ) != 0 && hc->mime_flag )
	{
	int p[2];

	if ( pipe( p ) < 0 )
	    {
	    syslog( LOG_ERR, "pipe - %m" );
	    httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	    httpd_write_blk_response( hc );
	    exit( 110 );
	    }
	r = fork( );
	if ( r < 0 )
	    {
	    syslog( LOG_ERR, "fork - %m" );
	    httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	    httpd_write_blk_response( hc );
	    exit( 111 );
	    }
	if ( r == 0 )
	    {
	    /* Interposer process. */
	    (void) close( p[1] );
	    cgi_interpose_output( hc, p[0] );
	    exit( 0 );
	    }
	/* Need to schedule a kill for process r; but in the main process! */
	(void) close( p[0] );
	if ( p[1] != STDOUT_FILENO )
	    (void) dup2( p[1], STDOUT_FILENO );
	if ( p[1] != STDERR_FILENO )
	    (void) dup2( p[1], STDERR_FILENO );
	if ( p[1] != STDOUT_FILENO && p[1] != STDERR_FILENO )
	    (void) close( p[1] );
	}
    else
	{
	/* Otherwise, the request socket is stdout/stderr. */
	if ( hc->conn_fd != STDOUT_FILENO )
	    (void) dup2( hc->conn_fd, STDOUT_FILENO );
	if ( hc->conn_fd != STDERR_FILENO )
	    (void) dup2( hc->conn_fd, STDERR_FILENO );
	}

    /* At this point we would like to set close-on-exec again for hc->conn_fd
    ** (see previous comments on Linux's broken behavior re: close-on-exec
    ** and dup.)  Unfortunately there seems to be another Linux problem, or
    ** perhaps a different aspect of the same problem - if we do this
    ** close-on-exec in Linux, the socket stays open but stderr gets
    ** closed - the last fd duped from the socket.  What a mess.  So we'll
    ** just leave the socket as is, which under other OSs means an extra
    ** file descriptor gets passed to the child process.  Since the child
    ** probably already has that file open via stdin stdout and/or stderr,
    ** this is not a problem.
    */
    /* (void) fcntl( hc->conn_fd, F_SETFD, FD_CLOEXEC ); */

#ifdef CGI_NICE
    /* Set priority. */
    (void) nice( CGI_NICE );
#endif /* CGI_NICE */

    /* Default behavior for SIGPIPE. */
#ifdef HAVE_SIGSET
    (void) sigset( SIGPIPE, SIG_DFL );
#else
    (void) signal( SIGPIPE, SIG_DFL );
#endif

    /* Run the program. */
    (void) execve( binary, argp, envp );

    /* Something went wrong. */
    syslog( LOG_ERR, "execve '%.80s' - %m", hc->expnfilename );
    httpd_send_err( hc, 500, err500title, err500titlelen,
		"", err500form, hc->encodedurl );
    httpd_write_blk_response( hc );
    exit( 112 );
    }


static int
cgi( httpd_conn* hc, char* cliprogram, char* cgipattern )
    {
    int r;
    ClientData client_data;

    /* Dynamic request, disable range */
    if ( hc->got_range )
	hc->got_range = 0;

    /*  We are not going to leave the socket open after a CGI ... too hard. */
    if ( hc->do_keep_alive )
	hc->do_keep_alive = 0;

    if ( hc->method == METHOD_GET || hc->method == METHOD_POST )
	{
	r = fork( );
	if ( r < 0 )
	    {
	    /* parent should eventually eat unused input */
	    if ( hc->method == METHOD_POST )
		hc->should_linger = 1;
	    syslog( LOG_ERR, "fork - %m" );
	    httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	    return -1;
	    }
	if ( r == 0 )
	    {
	    /* child started, OK, it handles all I/O */
	    httpd_unlisten( hc->hs );
	    /* set blocking I/O mode */
	    (void) httpd_set_nonblock( hc->conn_fd, SOPT_OFF );
	    cgi_child( hc, cliprogram, cgipattern );
	    /* NOTREACHED */
	    }

	/* Parent process should NOT eat unused input */
	/* because child process is supposed to do this */
	httpd_clear_response( hc );
	syslog( LOG_INFO,
		"spawned %s process %d for file '%.200s'",
		( cliprogram == (char*) 0 ? "CGI" : "CLI" ),
		r, hc->expnfilename );
	do_cond_reap();
#ifdef CGI_TIMELIMIT
	/* Schedule a kill for the child process, in case it runs too long */
	client_data.i = r;
	if ( tmr_create( (struct timeval*) 0, cgi_kill, client_data, CGI_TIMELIMIT * 1000L, TMR_ONE_SHOT ) == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(cgi_kill child) failed" );
	    exit( 113 );
	    }
#endif /* CGI_TIMELIMIT */
	hc->status = 200;
	hc->bytes_sent = CGI_BYTECOUNT;
	hc->should_linger = 0;
	}
    else
	{
	/* no need to eat input */
	httpd_send_err405( hc,
		METHOD_ID2BIT(METHOD_GET) |
		METHOD_ID2BIT(METHOD_POST),
		HTTPD_METHOD_STR( hc->method ) );
	return -1;
	}

    return 0;
    }

#endif /* EXECUTE_CGI */


static int
really_start_request( httpd_conn* hc, struct timeval* nowP,
			int numconn, int maxconn, int MaxKeepAliveFileSize )
    {
    static char* indexname;
    static int maxindexname = 0;
    static const char* index_names[] = { INDEX_NAMES };
    int i;
    int isRegOrigFile = 0;
#ifdef AUTH_FILE
    static char* dirname;
    static int maxdirname = 0;
#endif /* AUTH_FILE */

    switch ( hc->method )
	{
	case METHOD_GET:
	case METHOD_HEAD:
#ifdef EXECUTE_CGI
	case METHOD_POST:
#endif /* EXECUTE_CGI */
	    break;
	default:
	    httpd_send_err501( hc, HTTPD_METHOD_STR( hc->method ) );
	    return -1;
	}

    /* Stat the file only if it has not already done before */
    if ( hc->sb.st_mtime == 0 && stat( hc->expnfilename, &hc->sb ) < 0 )
	{
	httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	return -1;
	}

    /* Is it world-readable or world-executable?  We check explicitly instead
    ** of just trying to open it, so that no one ever gets surprised by
    ** a file that's not set world-readable and yet somehow is
    ** readable by the HTTP server and therefore the *whole* world.
    */
    if ( ! ( hc->sb.st_mode & ( S_IRACC | S_IXACC ) ) )
	{
	syslog(
	    LOG_INFO,
	    "%.80s URL \"%.80s\" resolves to a non world-readable file",
	    httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a file that is not world-readable.\n" ),
	    hc->encodedurl );
	return -1;
	}

    /* Is it a directory? */
    if ( S_ISDIR(hc->sb.st_mode) )
	{
	char* cp;
	char* pi;
	int indxlen = 0;
	int indxlen0 = 0;
	int cp_len = 0;

	/* If there's pathinfo, it's just a non-existent file. */
	if ( hc->pathinfo[0] != '\0' )
	    {
	    httpd_send_err( hc, 404, err404title, err404titlelen,
			"", err404form, hc->encodedurl );
	    return -1;
	    }

	/* Special handling for directory URLs that don't end in a slash.
	** We send back an explicit redirect with the slash, because
	** otherwise many clients can't build relative URLs properly.
	*/
	if ( hc->origfn_len > 0 &&
	   ( hc->origfilename[0] != '.' || hc->origfilename[1] != '\0' ) &&
	     hc->origfilename[hc->origfn_len - 1] != '/' )
	    {
      httpd_send_err( hc, 404, err404title, err404titlelen,
			"", err404form, hc->encodedurl );
	    return -1;
	    //send_dirredirect( hc );
	    //return -1;
	    }

	/* Look for an index file. */
	for ( i = 0; i < sizeof(index_names) / sizeof(index_names[0]); ++i )
	    {
	    indxlen0 = strlen( index_names[i] );
	    httpd_realloc_str(
		&indexname, &maxindexname,
		hc->expnfn_len + 1 + indxlen0 );

	    (void) strcpy( indexname, hc->expnfilename );
	    indxlen = hc->expnfn_len;
	    if ( indxlen == 0 || indexname[indxlen - 1] != '/' )
		{
		indexname[indxlen++] = '/';
		indexname[indxlen] = '\0';
		}
	    if ( indxlen == 2 && strcmp( indexname, "./" ) == 0 )
		indxlen = 0;
	    (void) strcpy( &indexname[indxlen], index_names[i] );
	    indxlen += indxlen0;
	    if ( stat( indexname, &hc->sb ) >= 0 )
		break;
	    }

	/* Nope, no index file, so it's an actual directory request. */
	if ( i >= sizeof(index_names) / sizeof(index_names[0]) )
	    {
#ifdef GENERATE_INDEXES

	    /* Directories must be readable for indexing. */
	    if ( ! ( hc->sb.st_mode & S_IRACC ) ||
		 ! hc->hs->do_generate_indexes )
		{
#ifdef SYSLOG_INDEXING_DISABLED
		syslog(
		LOG_INFO,
		"%.80s URL \"%.80s\" tried to index a directory but indexing is disabled",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
#endif /* SYSLOG_INDEXING_DISABLED */
		httpd_send_err(
		hc, 403, err403title, err403titlelen, "",
		ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a directory that has indexing disabled.\n" ),
		hc->encodedurl );
		return -1;
		}
#ifdef AUTH_FILE
	    /* Check authorization for this directory. */
	    if ( auth_check( hc, hc->expnfilename ) == -1 )
		return -1;
#endif /* AUTH_FILE */
	    /* Referer check. */
	    if ( ! check_referer( hc ) )
		return -1;
	    /* Check for forbidden query string in directory listing */
	    if ( hc->query[0] != '\0' )
		{
		syslog( LOG_INFO,
		    "%.80s URL \"%.80s\" resolves to a directory listing plus query string (forbidden)",
		    httpd_ntoa( &hc->client_addr ), hc->encodedurl );
		httpd_send_err( hc, 403, err403title, err403titlelen, "",
		    ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a directory listing plus CGI-style query string. Remove query string (from this URL) and retry.\n" ),
		    hc->encodedurl );
		return -1;
		}
	    /* Ok, generate an index. */
	    return ls( hc );

#else /* GENERATE_INDEXES */

#ifdef SYSLOG_INDEXING_DISABLED
	    syslog(
		LOG_INFO,
		"%.80s URL \"%.80s\" tried to index a directory (NO_GENERATE_INDEXES)",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
#endif /* SYSLOG_INDEXING_DISABLED */
	    httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' is a directory, and directory indexing is disabled on this server.\n" ),
	    hc->encodedurl );
	    return -1;

#endif /* GENERATE_INDEXES */
	    }
	/* Got an index file.  Expand symlinks again.  More pathinfo means
	** something went wrong.
	*/
	cp_len = 0;
	cp = expand_symlinks( indexname, indxlen, &cp_len,
				&pi, hc->hs->no_symlink, hc->tildemapped,
				(struct stat*) 0 );
	if ( cp == (char*) 0 || pi[0] != '\0' )
	    {
	    httpd_send_err( hc, 500, err500title, err500titlelen,
			"", err500form, hc->encodedurl );
	    return -1;
	    }
	hc->expnfn_len = cp_len;
	httpd_realloc_str( &hc->expnfilename, &hc->maxexpnfilename, cp_len );
	(void) strcpy( hc->expnfilename, cp );

	/* Now, is the index version a regular file ? */
	if ( ! S_ISREG( hc->sb.st_mode ) )
	    {
	    syslog(
		LOG_INFO,
		"%.80s URL \"%.80s\" resolves to a non-regular index file",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	    httpd_send_err(
		hc, 403, err403title, err403titlelen, "",
		ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a non-regular index file.\n" ),
		hc->encodedurl );
	    return -1;
	    }

	/* Now, is the index version world-readable or world-executable? */
	if ( ! ( hc->sb.st_mode & ( S_IRACC | S_IXACC ) ) )
	    {
	    syslog(
		LOG_INFO,
		"%.80s URL \"%.80s\" resolves to a non-world-readable index file",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	    httpd_send_err(
		hc, 403, err403title, err403titlelen, "",
		ERROR_FORM( err403form, "The requested URL '%.80s' resolves to an index file that is not world-readable.\n" ),
		hc->encodedurl );
	    return -1;
	    }
	}
    else
    if ( ! S_ISREG( hc->sb.st_mode ) )
	{
	syslog(
		LOG_INFO,
		"%.80s URL \"%.80s\" does not resolve to a directory or a regular file",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	httpd_send_err(
		hc, 403, err403title, err403titlelen, "",
		ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a non-regular file.\n" ),
		hc->encodedurl );
	return -1;
	}
    else
	isRegOrigFile = 1;

#ifdef AUTH_FILE
    /* Check authorization for this directory. */
    httpd_realloc_str( &dirname, &maxdirname, hc->expnfn_len );
    (void) strcpy( dirname, hc->expnfilename );
    cp = strrchr( dirname, '/' );
    if ( cp == (char*) 0 )
	(void) strcpy( dirname, "." );
    else
	*cp = '\0';
    if ( auth_check( hc, dirname ) == -1 )
	return -1;

    /* Check if the filename is the AUTH_FILE itself - that's verboten. */
    if ( hc->expnfn_len == SZLEN(AUTH_FILE) )
	{
	if ( strcmp( hc->expnfilename, AUTH_FILE ) == 0 )
	    {
	    syslog(
		LOG_NOTICE,
		"%.80s URL \"%.80s\" tried to retrieve an auth file",
		httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	    httpd_send_err(
		hc, 403, err403title, err403titlelen, "",
		ERROR_FORM( err403form, "The requested URL '%.80s' is an authorization file, retrieving it is not permitted.\n" ),
		hc->encodedurl );
	    return -1;
	    }
	}
    else if ( hc->expnfn_len >= sizeof(AUTH_FILE) &&
	      strcmp( &(hc->expnfilename[hc->expnfn_len - sizeof(AUTH_FILE) + 1]), AUTH_FILE ) == 0 &&
	      hc->expnfilename[hc->expnfn_len - sizeof(AUTH_FILE)] == '/' )
	{
	syslog(
	    LOG_NOTICE,
	    "%.80s URL \"%.80s\" tried to retrieve an auth file",
	    httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' is an authorization file, retrieving it is not permitted.\n" ),
	    hc->encodedurl );
	return -1;
	}
#endif /* AUTH_FILE */

    /* Referer check. */
    if ( ! check_referer( hc ) )
	return -1;

#ifdef EXECUTE_CGI
    /* Is it world-executable and in the CGI area? */
    if ( hc->hs->cgi_pattern != (char*) 0 &&
	 ( hc->sb.st_mode & S_IXACC ) &&
	 match( hc->hs->cgi_pattern, hc->expnfilename ) )
	return cgi( hc, (char*) 0, hc->hs->cgi_pattern );

#ifdef EXECUTE_CGICLI
     if ( hc->hs->cgicli_vrec != (httpd_cgicli_vrec*) 0
#ifdef CGICLI_WANTS_EXEC_BIT
	&& ( hc->sb.st_mode & S_IXACC )
#endif
	)
	{
	int	i2 = hc->hs->cgicli_vrec->cnt_cgicli;
	httpd_cgicli_entry *pcli;

	for ( i = 0; i < i2; ++i )
	    {
	    pcli = &( hc->hs->cgicli_vrec->cgicli_tab[i] );
	    if ( match( pcli->cli_pattern, hc->expnfilename ) )
		{
		return cgi( hc, pcli->cli_path, pcli->cli_pattern );
		}
	    }
	}
#endif /* EXECUTE_CGICLI */

#endif /* EXECUTE_CGI */

    /* It's not CGI or CGI-CLI. If it's executable or there's pathinfo,
    ** someone's trying to either serve or run a non-CGI file as CGI.
    ** Either case is prohibited.
    */
    if ( hc->sb.st_mode & S_IXACC )
	{
	syslog(
	    LOG_NOTICE, "%.80s URL \"%.80s\" is executable but isn't CGI",
	    httpd_ntoa( &hc->client_addr ), hc->encodedurl );
	httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a file which is marked executable but is not a CGI file; retrieving it is forbidden.\n" ),
	    hc->encodedurl );
	return -1;
	}

#ifdef DISALLOW_QRYSTR_IN_STFILES
    if ( hc->pathinfo[0] != '\0' || hc->query[0] != '\0' )
	{
	char	tmpstr[64];
	(void) my_snprintf( tmpstr, sizeof( tmpstr ), "%s%s%s",
		  ( hc->pathinfo[0] ? "pathinfo" : "" ),
		( ( hc->pathinfo[0] && hc->query[0] ) ? " and " : "" ),
		  ( hc->query[0] ? "query string" : "" ) );
	syslog(
	    LOG_INFO, "%.80s URL \"%.80s\" has %s but isn't CGI",
	    httpd_ntoa( &hc->client_addr ), hc->encodedurl, tmpstr );
	httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a file plus CGI-style pathinfo / query string, but the file is not a valid CGI file.\n" ),
	    hc->encodedurl );
	return -1;
	}
#endif	/* DISALLOW_QRYSTR_IN_STFILES */

    if ( isRegOrigFile )
	{
	/* check for trailing '/', if we find slashes, we may try to remove
	** them and then to redirect resulting URL;  if encodedurl does not end
	** with slashes then we return an error as Apache does.
	*/
	if ( hc->origfn_len > 1 &&
	    hc->origfilename[hc->origfn_len - 1] == '/' )
	    {
	    if ( hc->encodedurl_len > 1 )
		{
#ifdef FNREG_FIX_TRAILING_SLASHES
		if ( hc->encodedurl[hc->encodedurl_len - 1] == '/' )
		    {	/* trim trailing slashes */
		    do
			{
			hc->encodedurl[--hc->encodedurl_len] = '\0';
			}
		    while ( hc->encodedurl_len > 1 &&
			hc->encodedurl[hc->encodedurl_len - 1] == '/' );

		    send_redirect( hc, hc->encodedurl, hc->encodedurl_len );
		    return -1;
		    }
		else
#endif /* FNREG_FIX_TRAILING_SLASHES */
		    {
		    httpd_send_err( hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "The requested URL '%.80s' resolves to a file plus a trailing slash '/'. Remove trailing slash '/' (from the end of URL) and retry.\n" ),

	    hc->encodedurl );
		    return -1;
		    }
		}
	    }
	}

    figure_mime( hc );

    if ( hc->got_range )
	{
	/* Check if range request is satisfiable */
	if ( hc->init_byte_loc >= hc->sb.st_size )
	    {
	    hc->got_range = 0;
	    if ( hc->range_if == (time_t) -1 ||
		hc->range_if == hc->sb.st_mtime )
		{
		httpd_send_err( hc, 416, err416title, err416titlelen,
			"", err416form, hc->encodedurl );
		return -1;
		}
	    }

	/* Fill in end_byte_loc, if necessary. */
	if ( hc->end_byte_loc == -1L ||
	     hc->end_byte_loc >= hc->sb.st_size )
	     hc->end_byte_loc  = hc->sb.st_size - 1;
	}

    /* Common case / fast path */
    if ( hc->method == METHOD_GET )
	{
	void* file_address = (void*) 0;

	/* conditional or normal GET */
	if ( hc->if_modified_since != (time_t) -1 &&
	     hc->if_modified_since >= hc->sb.st_mtime )
	    {	/* NOTE: length -1, response without Content-Length */
	    send_mime(
		hc, 304, err304title, err304titlelen,
		"", -1, hc->sb.st_mtime );
	    return 0;
	    }

	/* normal GET maybe with range, etc. */

	hc->file_fd = EOF;
	hc->file_address = (char*) 0;

	/* open/map file content */
	if ( mmc_map( &(hc->file_fd), &file_address,
	     hc->expnfilename, &(hc->sb), nowP ) != MMC_NORMAL )
	    {
	    httpd_send_err( hc, 500, err500title, err500titlelen,
		"", err500form, hc->encodedurl );
	    return -1;
	    }
	hc->file_address = file_address;

	/* Test if connection can be kept alive */
	if ( hc->do_keep_alive &&
	    MaxKeepAliveFileSize > 0 &&
	    hc->sb.st_size > (off_t) MaxKeepAliveFileSize )
	    hc->do_keep_alive = 0;

	/* Send HTTP headers */
	send_mime(
		hc, 200, ok200title, ok200titlelen, "",
		hc->sb.st_size, hc->sb.st_mtime );
	return 0;
	}

    /* Rare (nowadays) second case */
    if ( hc->method == METHOD_HEAD )
	{
	/* we don't have to care about if_modified_since, etc. */
	send_mime(
	    hc, 200, ok200title, ok200titlelen, "",
	    hc->sb.st_size, hc->sb.st_mtime );
	return 0;
	}

    /* METHOD_POST, etc.:
    ** method not allowed for this resource (static file).
    */
    httpd_send_err405( hc,
	METHOD_ID2BIT(METHOD_GET) |
	METHOD_ID2BIT(METHOD_HEAD),
	HTTPD_METHOD_STR( hc->method ) );
    return -1;

    }


int
httpd_start_request( httpd_conn* hc, struct timeval* nowP,
			int numconn, int maxconn, int MaxKeepAliveFileSize )
    {
    int r;

    /* Really start the request. */
    r = really_start_request( hc, nowP,
			numconn, maxconn, MaxKeepAliveFileSize );

    /* And return the status. */
    return r;
    }


static void
make_log_entry( httpd_conn* hc, struct timeval* nowP )
    {
    char* ru = "-";
    char* vhostsep  = "";
    char* vhostname = "";
    char bytes[40] = "-";

    if ( hc->hs->no_log )
	return;

    /* This is straight CERN Combined Log Format - the only tweak
    ** being that if we're using syslog() we leave out the date, because
    ** syslogd puts it in.  The included syslogtocern script turns the
    ** results into true CERN format.
    */

    /* Format remote user. */
#ifdef AUTH_FILE
    if ( hc->remoteuser[0] != '\0' )
	ru = hc->remoteuser;
#endif	/* AUTH_FILE */

    /* If we're vhosting, prepend the hostname to the url.  This is
    ** a little weird, perhaps writing separate log files for
    ** each vhost would make more sense.  An alternative solution
    ** is to prepend it to all other fields (LOG_PREPEND_VHOSTNAME).
    */
    if ( hc->hs->vhost && !hc->tildemapped )
	{
#ifdef LOG_PREPEND_VHOSTNAME
	vhostsep = " ";
#else
	vhostsep = "/";
#endif
	vhostname = ( hc->hostname == (char*) 0 ?
			hc->hs->server_hostname : hc->hostname );
	}

    /* Format the bytes (fast conversion, NO LARGE FILE support). */
    if ( hc->bytes_sent >= 0L )
	(void) fmt_ulong10( bytes, (unsigned long) hc->bytes_sent );

    /* Logfile or syslog? */
    if ( hc->hs->logfp != (FILE*) 0 )
	{
	time_t now;
	static time_t prev_now;
	static char date[100];

	/* Get the current time, if necessary. */
	if ( nowP != (struct timeval*) 0 )
	    now = nowP->tv_sec;
	else
	    now = time( (time_t*) 0 );

	/* Make the datetime string (only if needed) */
	if ( now != prev_now )
	    {
	    prev_now = now;
	    (void) fmt_cern_time( date, sizeof( date ), now );
	    }

	/* And write the log entry. */
#ifdef LOG_PREPEND_VHOSTNAME
	(void) fprintf( hc->hs->logfp,
#ifdef USE_SCTP
	    "%.80s:%d %.4s - %.80s [%s] \"%.80s %.300s %.80s\" %d %s \"%.200s\" \"%.200s\"\n",
	    httpd_ntoa( &hc->client_addr ),
	    hc->client_addr.sa.sa_family == AF_INET ?
	      ntohs( hc->client_addr.sa_in.sin_port ) :
	      ntohs( hc->client_addr.sa_in6.sin6_port ),
	    hc->is_sctp ? "SCTP" : " TCP",
#else
	    "%.80s - %.80s [%s] \"%.80s %.300s %.80s\" %d %s \"%.200s\" \"%.200s\"\n",
	    httpd_ntoa( &hc->client_addr ),
#endif
	    ru, date,

	    HTTPD_METHOD_STR( hc->method ),
	    hc->encodedurl, hc->protocol,
	    hc->status, bytes, hc->referer, hc->useragent );
#else
	(void) fprintf( hc->hs->logfp,
	    "%.80s - %.80s [%s] \"%.80s %s%.100s%.200s %.80s\" %d %s \"%.200s\" \"%.200s\"\n",
	    httpd_ntoa( &hc->client_addr ), ru, date,
	    HTTPD_METHOD_STR( hc->method ),
	    vhostsep, vhostname,
	    hc->encodedurl, hc->protocol,
	    hc->status, bytes, hc->referer, hc->useragent );
#endif /* LOG_PREPEND_VHOSTNAME */

#if defined(LOG_FLUSH_TIME) && (LOG_FLUSH_TIME < 1)
	    fflush( hc->hs->logfp );
#else
	    /* don't need to flush every time */
#endif /* LOG_FLUSH_TIME */
	}
    else
	{
#ifdef LOG_PREPEND_VHOSTNAME
	syslog( LOG_INFO,
	    "%.100s%s%.80s - %.80s \"%.80s %.200s %.80s\" %d %s \"%.200s\" \"%.200s\"",
	    vhostname, vhostsep,
	    httpd_ntoa( &hc->client_addr ), ru,
	    HTTPD_METHOD_STR( hc->method ),
	    hc->encodedurl, hc->protocol,
	    hc->status, bytes, hc->referer, hc->useragent );
#else
	syslog( LOG_INFO,
	    "%.80s - %.80s \"%.80s %s%.100s%.200s %.80s\" %d %s \"%.200s\" \"%.200s\"",
	    httpd_ntoa( &hc->client_addr ), ru,
	    HTTPD_METHOD_STR( hc->method ),
	    vhostsep, vhostname,
	    hc->encodedurl, hc->protocol,
	    hc->status, bytes, hc->referer, hc->useragent );
#endif /* LOG_PREPEND_VHOSTNAME */
	}
    }


/* Format a CERN time (log record).
** Putting this stuff into a function is useful to reduce cache pollution
** after a mispredicted jump.
*/
static int
fmt_cern_time( char* buftime, size_t bufsize, time_t tnow )
    {
    struct tm* t;
    const char* cernfmt_nozone = "%d/%b/%Y:%H:%M:%S";
    int zone;
    char sign;
    char dtm_nozone[100];

    /* Format the time, forcing a numeric timezone (some log analyzers
    ** are stoooopid about this).
    */
    t = localtime( &tnow );
    (void) strftime( dtm_nozone, sizeof(dtm_nozone),
			cernfmt_nozone, t );
#ifdef HAVE_TM_GMTOFF
    zone = t->tm_gmtoff / 60L;
#else
    zone = -timezone / 60L;
    /* Probably have to add something about daylight time here. */
#endif
    if ( zone >= 0 )
	sign = '+';
    else
	{
	sign = '-';
	zone = -zone;
	}
    zone = ( zone / 60 ) * 100 + zone % 60;
    (void) my_snprintf( buftime, bufsize,
		"%s %c%04d", dtm_nozone, sign, zone );
    buftime[bufsize - 1] = '\0';
    return strlen( buftime );
    }


static const char *wday_name_tab[7] =
    {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };

static const char *month_name_tab[12] =
    {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

static const int month_days_tab[12] =
    {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };


#ifndef NO_TMF

/* Convert a GMT time value into a struct tm record.
*/
static struct tm
time_to_tm( time_t t1 )
    {
    struct tm	tm1;
    int		hpy;	/* hours per year */
    unsigned int  yy;
    unsigned int cumdays;

    /* Time in minutes */
    tm1.tm_sec = (int)(t1 % 60L);
    t1 /= 60L;

    /* Time in hours */
    tm1.tm_min = (int)(t1 % 60L);
    t1 /= 60L;

    /* Number of 4 year blocks */
    yy = (unsigned int)(t1 / (1461L * 24L));
    tm1.tm_year = (int) (yy << 2);
    tm1.tm_year += 70;
    cumdays = 1461 * yy;
    /* Hours since end of last 4 year block */
    t1 %= 1461L * 24L;

    for (;;)
    {
	hpy = 365 * 24;

	if ((tm1.tm_year & 3) == 0)
		hpy += 24;

	if( t1 < (time_t) hpy )
		break;

	cumdays += (unsigned int ) hpy / 24;
	tm1.tm_year++;
	t1 -= hpy;
    }

    /* Now, time t1 is the number of hours elapsed since
    ** the begginning of current year.
    */

    /* Time in days */
    tm1.tm_hour = (int)(t1 % 24);
    t1 /= 24;
    tm1.tm_yday = (int) t1;
    cumdays += (unsigned int) t1 + 4;
    tm1.tm_wday = (int) (cumdays % 7);
    ++t1;

    if ((tm1.tm_year & 3) == 0)
	{
	if (t1 > 60)
            t1--;
	else
	if (t1 == 60)
	    {
	    tm1.tm_mon = 1;
	    tm1.tm_mday = 29;
	    return tm1;
	    }
	}

    for( tm1.tm_mon = 0; month_days_tab[tm1.tm_mon] < t1; ++tm1.tm_mon )
	t1 -= month_days_tab[tm1.tm_mon];

    tm1.tm_mday = (int)(t1);

    return tm1;
    }

#endif /* NO_TMF */


/* Format a RFC1123 time.
** NOTE: in HTTP headers, week day and month names MUST be in English !
*/
static int
fmt_rfc1123_time( char *buftime, size_t bufsize, time_t tnow )
    {
#ifdef NO_TMF
    struct tm *ptm;
#else
    struct tm rectm;
    struct tm *ptm = &rectm;
#endif
    unsigned int uYear;

#ifdef NO_TMF
    ptm = gmtime( &tnow );
#else
    *ptm = time_to_tm( tnow );
#endif /* NO_TMF */

    uYear = (unsigned int) ptm->tm_year + 1900;

    if ( bufsize < 30 )
	{
	buftime[0] = '\0';
	return 0;
	}
    buftime[ 0] = wday_name_tab[ ptm->tm_wday ][0];
    buftime[ 1] = wday_name_tab[ ptm->tm_wday ][1];
    buftime[ 2] = wday_name_tab[ ptm->tm_wday ][2];
    buftime[ 3] = ',';
    buftime[ 4] = ' ';
    buftime[ 5] = (char) ('0' + (ptm->tm_mday / 10) );
    buftime[ 6] = (char) ('0' + (ptm->tm_mday % 10) );
    buftime[ 7] = ' ';
    buftime[ 8] = month_name_tab[ ptm->tm_mon ][0];
    buftime[ 9] = month_name_tab[ ptm->tm_mon ][1];
    buftime[10] = month_name_tab[ ptm->tm_mon ][2];
    buftime[11] = ' ';
    buftime[12] = (char) ( '0' + ( uYear / 1000 ) % 10 );
    buftime[13] = (char) ( '0' + ( uYear /  100 ) % 10 );
    buftime[14] = (char) ( '0' + ( uYear /   10 ) % 10 );
    buftime[15] = (char) ( '0' + ( uYear %   10 ) );
    buftime[16] = ' ';
    buftime[17] = (char) ( '0' + ( ptm->tm_hour / 10 ) );
    buftime[18] = (char) ( '0' + ( ptm->tm_hour % 10 ) );
    buftime[19] = ':';
    buftime[20] = (char) ( '0' + ( ptm->tm_min  / 10 ) );
    buftime[21] = (char) ( '0' + ( ptm->tm_min  % 10 ) );
    buftime[22] = ':';
    buftime[23] = (char) ( '0' + ( ptm->tm_sec  / 10 ) );
    buftime[24] = (char) ( '0' + ( ptm->tm_sec  % 10 ) );
    buftime[25] = ' ';
    buftime[26] = 'G';
    buftime[27] = 'M';
    buftime[28] = 'T';
    buftime[29] = '\0';

    /* Return constant length */
    return 29;
    }


/* Returns 1 if ok to serve the url, 0 if not. */
static int
check_referer( httpd_conn* hc )
    {
    int r;

    /* Are we doing referer checking at all? */
    if ( hc->hs->url_pattern == (char*) 0 )
	return 1;

    r = really_check_referer( hc );

    if ( r != 0 )
	return r;

    syslog(
	    LOG_INFO, "%.80s non-local referer \"%.80s\" \"%.80s\"",
	    httpd_ntoa( &hc->client_addr ), hc->encodedurl, hc->referer );
    httpd_send_err(
	    hc, 403, err403title, err403titlelen, "",
	    ERROR_FORM( err403form, "You must supply a local referer to get URL '%.80s' from this server.\n" ),
	    hc->encodedurl );

    return r;
    }


/* Returns 1 if ok to serve the url, 0 if not. */
static int
really_check_referer( httpd_conn* hc )
    {
    httpd_server* hs;
    char* cp1;
    char* cp2;
    char* cp3;
    static char* refhost = (char*) 0;
    static int refhost_size = 0;
    char *lp;

    hs = hc->hs;

    /* Check for an empty referer. */
    if ( hc->referer == (char*) 0 || hc->referer[0] == '\0' ||
	 ( cp1 = strstr( hc->referer, "//" ) ) == (char*) 0 )
	{
	/* Disallow if we require a referer and the url matches. */
	if ( hs->no_empty_referers && match( hs->url_pattern, hc->decodedurl ) )
	    return 0;
	/* Otherwise ok. */
	return 1;
	}

    /* Extract referer host. */
    cp1 += 2;
    for ( cp2 = cp1; *cp2 != '/' && *cp2 != ':' && *cp2 != '\0'; ++cp2 )
	continue;
    httpd_realloc_str( &refhost, &refhost_size, cp2 - cp1 );
    for ( cp3 = refhost; cp1 < cp2; ++cp1, ++cp3 )
	if ( isupper(*cp1) )
	    *cp3 = tolower(*cp1);
	else
	    *cp3 = *cp1;
    *cp3 = '\0';

    /* Local pattern? */
    if ( hs->local_pattern != (char*) 0 )
	lp = hs->local_pattern;
    else
	{
	/* No local pattern.  What's our hostname? */
	if ( ! hs->vhost )
	    {
	    /* Not vhosting, use the server name. */
	    lp = hs->server_hostname;
	    if ( lp == (char*) 0 )
		/* Couldn't figure out local hostname - give up. */
		return 1;
	    }
	else
	    {
	    /* We are vhosting, use the hostname on this connection. */
	    lp = hc->hostname;
	    if ( lp == (char*) 0 )
		/* Oops, no hostname.  Maybe it's an old browser that
		** doesn't send a Host: header.  We could figure out
		** the default hostname for this IP address, but it's
		** not worth it for the few requests like this.
		*/
		return 1;
	    }
	}

    /* If the referer host doesn't match the local host pattern, and
    ** the URL does match the url pattern, it's an illegal reference.
    */
    if ( ! match( lp, refhost ) && match( hs->url_pattern, hc->decodedurl ) )
	return 0;
    /* Otherwise ok. */
    return 1;
    }


char*
httpd_ntoa( httpd_sockaddr* saP )
    {
#ifdef HAVE_GETNAMEINFO
    static char str[200];

    if ( getnameinfo( &saP->sa, sockaddr_len( saP ), str, sizeof(str), 0, 0, NI_NUMERICHOST ) != 0 )
	{
	str[0] = '?';
	str[1] = '\0';
	}
    return str;

#else /* HAVE_GETNAMEINFO */

    return inet_ntoa( saP->sa_in.sin_addr );

#endif /* HAVE_GETNAMEINFO */
    }


static int
sockaddr_check( httpd_sockaddr* saP )
    {
    switch ( saP->sa.sa_family )
	{
	case AF_INET: return 1;
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
	case AF_INET6: return 1;
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
	default:
	return 0;
	}
    }


static size_t
sockaddr_len( httpd_sockaddr* saP )
    {
    switch ( saP->sa.sa_family )
	{
	case AF_INET: return sizeof(struct sockaddr_in);
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
	case AF_INET6: return sizeof(struct sockaddr_in6);
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
	default:
	return 0;	/* shouldn't happen */
	}
    }


#ifndef NO_MYSNP

/* Some systems don't have snprintf(), so we make our own that uses
** either vsnprintf() or vsprintf().  If your system doesn't have
** vsnprintf(), it is probably vulnerable to buffer overruns.
** Upgrade!
*/
static int
my_snprintf( char* str, size_t size, const char* format, ... )
    {
    va_list ap;
    int r;

    va_start( ap, format );
#ifdef HAVE_VSNPRINTF
    r = vsnprintf( str, size, format, ap );
#else /* HAVE_VSNPRINTF */
    r = vsprintf( str, format, ap );
#endif /* HAVE_VSNPRINTF */
    va_end( ap );
    return r;
    }

#endif /* NO_MYSNP */


/* Utility functions */

#define IOS_NUMBUF	64

#ifdef DO_FMT_LONG
/*
** Convert a long to a string of characters.
*/
static size_t
fmt_long10(char *psz, const long lNum)
    {
    uint	flgNeg = 0;
    size_t	i = (IOS_NUMBUF - 1);
    size_t	uLen = 0;
    unsigned long	ulNum = (unsigned long) lNum;
    char	szOutBuf[IOS_NUMBUF];

    if (lNum < 0L)
	{
	flgNeg = 1;
	ulNum = -ulNum;
	}

    szOutBuf[i] = '\0';

    /* convert number to string */
    do
	{
	szOutBuf[--i] = (char) ((ulNum % 10) + '0');
	}
    while ((ulNum /= 10) != 0);

    /* set sign in any case */
    szOutBuf[--i] = '-';
    i += (flgNeg ^ 1);

    /* copy the result into output */
    uLen = ((IOS_NUMBUF - 1) - i);
    memcpy(psz, &szOutBuf[i], uLen + 1);

    /* return n. characters written to output (excluding '\0') */
    return uLen;
}
#endif /* DO_FMT_LONG */

/*
** Convert an unsigned long number to a string of characters
** (it should be much faster than a single my_snprintf()).
*/
static size_t
fmt_ulong10(char *psz, const unsigned long culNum)
    {
    unsigned long	ulNum = culNum;
    size_t	i = (IOS_NUMBUF - 1);
    size_t	uLen = 0;
    char	szOutBuf[IOS_NUMBUF];

    szOutBuf[i] = '\0';

    /* convert number to string */
    do
	{
	szOutBuf[--i] = (char) ((ulNum % 10) + '0');
	}
    while ((ulNum /= 10) != 0);

    /* copy the result into output */
    uLen = ((IOS_NUMBUF - 1) - i);
    memcpy(psz, &szOutBuf[i], uLen + 1);

    /* return n. characters written to output (excluding '\0') */
    return uLen;
    }


/* Generate debugging statistics syslog message. */
void
httpd_logstats( long secs )
    {
#ifdef DO_ALLOC_STATS
    if (str_alloc_count == 0)
	str_alloc_count++;

    syslog( LOG_INFO,
	"  libhttpd - %d strings allocated, %ld bytes (%g bytes/str)",
	str_alloc_count, str_alloc_size,
	( (float) str_alloc_size ) / str_alloc_count );
#else
    secs |= 1;
#endif
    }
