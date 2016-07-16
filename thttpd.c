/* thttpd.c - tiny/turbo/throttling HTTP server
**
** Copyright © 1995,1998,1999,2000,2001 by Jef Poskanzer <jef@acme.com>.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <pwd.h>
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#include <unistd.h>

#include "fdwatch.h"
#include "libhttpd.h"
#include "mmc.h"
#include "timers.h"
#include "match.h"

#ifndef FD_CLOEXEC
#define FD_CLOEXEC	1
#endif /* FD_CLOEXEC */

static char* argv0;
static int debug;
static int port;
static char* dir;
static char* data_dir;
static int do_chroot, no_log, no_symlink, do_vhost, do_global_passwd;
static int do_generate_indexes;
static int do_keepalive_conns;
static char* cgi_pattern;
static httpd_cgicli_vrec* cgicli_vrec;
static char* url_pattern;
static int no_empty_referers;
static char* local_pattern;
static char* logfile;
static char* urithrottlefile;
#ifdef USE_IPTHROTTLE
static char* ipthrottlefile;
static char* subnetsfile;
#endif /* USE_IPTHROTTLE */
#ifdef EXECUTE_CGICLI
static char* cgiclifile;
#endif /* EXECUTE_CGICLI */
static char* hostname;
static char* pidfile;
static char* user;
static char* charset;
static int max_age;
static int   OccasionalMmcTime = OCCASIONAL_MMC_TIME;
static long  SecIdleSendRespTimeLimit  = IDLE_SEND_RESP_TIMELIMIT;
static long  SecIdleKeepAliveTimeLimit = IDLE_KEEPALIVE_TIMELIMIT;

typedef struct {
    char* pattern;
    long limit;
    long rate;
    off_t bytes_since_avg;
    int num_sending;
    } throttletab;
static throttletab* throttles;
static int numthrottles, maxthrottles;
static int numurithrottles;

#ifdef USE_IPTHROTTLE
static int numipthrottles;
static int outiprule;

typedef struct {
    struct in_addr net;
    int mask;
    int rule;
    } subnet_t;

static subnet_t* subnets;
static int subnets_uselen, subnets_maxlen, subnets_reload ;
#endif /* USE_IPTHROTTLE */

#define THROTTLE_NOLIMIT	( 1024 * 1048576L )  /* no limit */

#if     MIN_THROTTLE_LIMIT < 100L
#error  MIN_THROTTLE_LIMIT < 100
#endif
#if     MAX_THROTTLE_LIMIT > ( 64 * 1048576L )
#error  MAX_THROTTLE_LIMIT > ( 64 * 1048576L )
#endif
#if     MAX_THROTTLE_LIMIT < ( MIN_THROTTLE_LIMIT * 4 )
#error  MAX_THROTTLE_LIMIT < ( MIN_THROTTLE_LIMIT * 4 )
#endif
#ifndef MIN_MAX_CONN_BYTES_LIMIT
#define MIN_MAX_CONN_BYTES_LIMIT 512L	/* min. value for MaxConnBytesLimit */
#endif

static long  MaxConnBytesLimit;
static int   ConnSoRcvBuf;		/* default 0 = don't set it */
static int   ConnSoSndBuf;		/* default 0 = don't set it */

#ifdef USE_LAYOUT
/* Layout Vars, global for now */
char *lheaderfile, *lfooterfile;
int   lheaderfile_len, lfooterfile_len;
char *lheaderfile_map, *lfooterfile_map;
#endif /* USE_LAYOUT */

typedef struct {
    int conn_state;		/* connection state */
    httpd_conn* hc;		/* http stuff */
    int tnums[MAXTHROTTLENUMS];	/* throttle indexes */
    int numtnums;		/* number of throttles */
    int keep_alive;		/* keep alive connection */
    int pipelining;		/* at least one pipelined request connection */
    long limit;			/* upper bandwidth limit */
    time_t throttled_at;	/* last throttle time */
    time_t iotimeout_at;	/* scheduled timeout time */
    Timer* wakeup_timer;	/* wakeup timer (I/O pausing / throttling) */
    Timer* linger_timer;	/* linger timer */
    long wouldblock_delay;	/* delay after an unexpected EWOULDBLOCK */
    off_t bytes_throttled;	/* bytes sent since last throttle update */
    off_t bytes_to_send;	/* bytes to send (end location) */
    off_t bytes_sent;		/* bytes virtually sent (current location) */
    } connecttab;
static connecttab*  connects;		/* connection array */
static connecttab** freeconnects;	/* free connections array */
static int numfreeconnects;
static int numconnects, maxconnects;	/* max. connections */
#ifndef SYSLOG_EACH_TOOMCONNS
static unsigned int ovfconnects;	/* overflow connections */
#endif /* SYSLOG_EACH_TOOMCONNS */
static unsigned long stats_ovfconnects;	/* overflow connections */
static int hiwmconnects1;		/* high water mark 1 (60%) */
static int hiwmconnects2;		/* high water mark 2 (80%) */
static int hiwmconnects3;		/* high water mark 3 (90%) */
static int hiwmconnects4;		/* high water mark 4 (95%) */
static int httpd_conn_count;		/* max. connection slots used */
static int LoWmKeepAliveRqsLimit = LOWM_KEEPALIVE_RQSLIMIT;
static int HiWmKeepAliveRqsLimit = HIWM_KEEPALIVE_RQSLIMIT;
static int MaxKeepAliveFileSize;	/* 0 per default (0 - 2 ^ 30) */

/* The connection states. */
#define CNST_FREE		0
#define CNST_READING		1
#define CNST_SENDING		2
#define CNST_SENDING_RESP	3
#define CNST_PAUSING		4
#define CNST_LINGERING		5
#define CNST_TOT_NUM		6

/* boolean values for do keep alive in clear_connection() */
#define NO_KEEP_ALIVE	0	/* FALSE */
#define DO_KEEP_ALIVE	1	/* TRUE */

#ifdef	HAVE_SIGSET
#define my_signal	sigset
#else
#define my_signal	signal
#endif

/* flags for gotSigMask */

#define GOT_O_SIGHUP	0x0001
#define GOT_O_SIGUSR1	0x0002
#define GOT_O_SIGUSR2	0x0004
#define GOT_M_SIGMASK	(GOT_O_SIGHUP|GOT_O_SIGUSR1|GOT_O_SIGUSR2)

static httpd_server* hs = (httpd_server*) 0;
static time_t start_time, stats_time;
static unsigned long stats_requests;
static unsigned long stats_connections;
static unsigned long stats_connaborted;
static int stats_simultaneous;
#ifdef HAVE_INT64T
static int64_t stats_resp_bytes;	/* HTTP headers + error responses */
static int64_t stats_body_bytes;	/* file contents really sent */
#else
static unsigned long stats_resp_bytes;	/* HTTP headers + error responses */
static unsigned long stats_body_bytes;	/* file contents really sent */
#endif /* HAVE_INT64T */

static volatile sig_atomic_t in_shut_down;
static volatile sig_atomic_t gotSigMask;


/* Forwards. */
static void thttpd_log_reopen( void );
static void handle_rsig( int sig );
static void handle_term( int sig );
static void handle_hup( int sig );
static void handle_usr1( int sig );
static void handle_usr2( int sig );
static void setup_signals( void );

int main( int argc, char** argv );

#if !defined(GENERATE_INDEXES) || !defined(EXECUTE_CGI) || !defined(EXECUTE_CGICLI) || !defined(USE_IPTHROTTLE)
static void print_arg_msg( const int msg_type, const char *optname );
#endif
static void parse_args( int argc, char** argv );
static void usage( void );
#ifdef USE_LAYOUT
static void* map_layoutfile( char* filename, int* pfilesize );
#endif
static void read_config( char* filename );
static void value_required( char* name, char* value );
static void no_value_required( char* name, char* value );
static char* e_strdup( char* oldstr );
static void lookup_hostname( httpd_sockaddr* sa4P, size_t sa4_len, int* gotv4P, httpd_sockaddr* sa6P, size_t sa6_len, int* gotv6P );
#ifdef EXECUTE_CGICLI
static void read_cgiclifile( char* cgiclifile );
#endif /* EXECUTE_CGICLI */
static void read_throttlefile( char* throttlefile, int* numthrottlesP );
static void shut_down( void );
static int handle_newconnect( struct timeval* tvP, int listen_fd );
static void handle_buf_read( connecttab* c, struct timeval* tvP );
static void handle_read( connecttab* c, struct timeval* tvP );
static void handle_send( connecttab* c, struct timeval* tvP );
static void handle_send_resp( connecttab* c, struct timeval* tvP );
static void handle_linger( connecttab* c, struct timeval* tvP );
static int  read_linger( connecttab* c, struct timeval* tvP );
static int in_check_throttles( connecttab* c, int tnum );
static int check_throttles( connecttab* c );
static void clear_throttles( connecttab* c, struct timeval* tvP );
static void update_throttles( ClientData client_data, struct timeval* nowP );
#ifdef USE_IPTHROTTLE
static int subnetcmp( const void *p1, const void *p2 );
static void initmatchsubnet( char* filename );
static int searchinsubnets( struct in_addr ip );
#endif /* USE_IPTHROTTLE */
static void resp_clear_connection( connecttab* c, struct timeval* tvP,
					int do_keep_alive );
static void clear_connection( connecttab* c, struct timeval* tvP,
					int do_keep_alive );
static void really_clear_connection( connecttab* c, struct timeval* tvP );
static void wakeup_connection( ClientData client_data, struct timeval* nowP );
static void wakeup_resp_connection( ClientData client_data, struct timeval* nowP );
static void linger_clear_connection( ClientData client_data, struct timeval* nowP );
static void occasional_idle( ClientData client_data, struct timeval* nowP );
#if defined(LOG_FLUSH_TIME) && (LOG_FLUSH_TIME > 0)
static void occasional_log( ClientData client_data, struct timeval* nowP );
#endif /* LOG_FLUSH_TIME */
static void occasional_mmc( ClientData client_data, struct timeval* nowP );
static void occasional_tmr( ClientData client_data, struct timeval* nowP );
#ifdef STATS_TIME
static void show_stats( ClientData client_data, struct timeval* nowP );
#endif /* STATS_TIME */
static void logstats( struct timeval* nowP );
static void thttpd_logstats( long secs );


static void
thttpd_log_reopen( void )
    {
    FILE* logfp;

    if ( no_log || hs == (httpd_server*) 0 )
	return;

    /* Re-open the log file. */
    if ( logfile != (char*) 0 )
	{
	httpd_flush_logfp( hs );
	logfp = fopen( logfile, "a" );
	if ( logfp == (FILE*) 0 )
	    {
	    syslog( LOG_CRIT, "reopening %.80s - %m", logfile );
	    return;
	    }
	(void) fcntl( fileno( logfp ), F_SETFD, FD_CLOEXEC );
	httpd_set_logfp( hs, logfp );
	}
    }


static void
handle_rsig( int sig )
    {
    syslog( LOG_WARNING, "handle_rsig: signal %d, shutdown interrupted", sig );
    /* no closelog() (we are inside a signal handler) */
    exit( sig );
    }


/* SIGTERM, SIGINT, etc. say to exit immediately.
** Here there is code to handle recursive signal calls.
*/
static void
handle_term( int sig )
    {
    syslog( LOG_NOTICE, "handle_term: signal %d, shutting down ...", sig );
    /* If the same signal occurs in shut_down() then exit directly
    ** in order to avoid recursive calls to this function.
    */
    (void) my_signal( sig, handle_rsig );
    if ( in_shut_down )
	handle_rsig( sig );
    shut_down();
    syslog( LOG_NOTICE, "handle_term: shutdown completed, exit( %d )", sig );
    /* no closelog() (we are inside a signal handler) */
    exit( sig );
    }


/* SIGHUP says to re-open the log file.  If log file name has a pathname
** that starts outside chroot tree, then this doesn't work.
** What you have to do instead is: A) cd to the root of chroot tree
** (before starting thttpd) and specify a relative path (under chroot tree)
** for log file, or B) (better) send a SIGUSR1 to shut down cleanly,
** and then restart thttpd.
*/
static void
handle_hup( int sig )
    {
    gotSigMask |= GOT_O_SIGHUP;
#ifndef	HAVE_SIGSET
    (void) my_signal( sig, handle_hup );
#endif
    }


static void
handle_usr1( int sig )
    {
    gotSigMask |= GOT_O_SIGUSR1;
#ifndef	HAVE_SIGSET
    (void) my_signal( sig, handle_usr1 );
#endif
    }


static void
handle_usr2( int sig )
    {
    gotSigMask |= GOT_O_SIGUSR2;
#ifndef	HAVE_SIGSET
    (void) my_signal( sig, handle_usr2 );
#endif
    }


static void
setup_signals( void )
    {
    void (*p_handle_term)(int) = handle_term;

    /* Set up to catch signals. */
#ifdef	SIGHUP
    (void) my_signal( SIGHUP,	handle_hup );
#ifdef notdef
    (void) my_signal( SIGHUP,	SIG_IGN );
#endif
#endif
#ifdef	SIGINT
    (void) my_signal( SIGINT,	p_handle_term );
#endif
#ifdef	SIGILL
    (void) my_signal( SIGILL,	p_handle_term );
#endif
#ifdef	SIGQUIT
    (void) my_signal( SIGQUIT,	p_handle_term );
#endif
#ifdef	SIGABRT
    (void) my_signal( SIGABRT,	p_handle_term );
#endif
#ifdef	SIGIOT
    (void) my_signal( SIGIOT,	p_handle_term );
#endif
#ifdef	SIGBUS
    (void) my_signal( SIGBUS,	p_handle_term );
#endif
#ifdef	SIGFPE
    (void) my_signal( SIGFPE,	p_handle_term );
#endif
#ifdef	SIGSEGV
    (void) my_signal( SIGSEGV,	p_handle_term );
#endif
#ifdef	SIGUSR1
    (void) my_signal( SIGUSR1,	handle_usr1 );
#endif
#ifdef	SIGUSR2
    (void) my_signal( SIGUSR2,	handle_usr2 );
#endif
#ifdef	SIGPIPE
    (void) my_signal( SIGPIPE,	SIG_IGN );	/* get EPIPE instead */
#endif
#ifdef	SIGALRM
    (void) my_signal( SIGALRM,	p_handle_term );
#endif
#ifdef	SIGTERM
    (void) my_signal( SIGTERM,	p_handle_term );
#endif
#ifdef	SIGTSTP
    (void) my_signal( SIGTSTP,	p_handle_term );
#endif
#ifdef	SIGTTIN
    (void) my_signal( SIGTTIN,	p_handle_term );
#endif
#ifdef	SIGTTOU
    (void) my_signal( SIGTTOU,	p_handle_term );
#endif
#ifdef	SIGURG
    (void) my_signal( SIGURG,	p_handle_term );
#endif
#ifdef	SIGXCPU
    (void) my_signal( SIGXCPU,	p_handle_term );
#endif
#ifdef	SIGXFSZ
    (void) my_signal( SIGXFSZ,	p_handle_term );
#endif
#ifdef	SIGVTALRM
    (void) my_signal( SIGVTALRM,p_handle_term );
#endif
#ifdef	SIGWINCH
    (void) my_signal( SIGWINCH,	SIG_IGN );
#endif
#ifdef	SIGPWR
    (void) my_signal( SIGPWR,	p_handle_term );
#endif
    /* zero flag to show start value */
    gotSigMask = 0;
    }


int
main( int argc, char** argv )
    {
    char* cp;
    struct passwd* pwd;
    uid_t uid = 32767;
    gid_t gid = 32767;
    char* cwd;
    FILE* logfp;
    int num_ready;
    int cnum, ridx;
    connecttab* c;
    httpd_sockaddr sa4;
    httpd_sockaddr sa6;
    int gotv4 = 0, gotv6 = 0;
    struct timeval tv = { 0, 0 };
    int terminate = 0;

    argv0 = argv[0];

    cp = strrchr( argv0, '/' );
    if ( cp != (char*) 0 )
	++cp;
    else
	cp = argv0;
    openlog( cp, LOG_NDELAY|LOG_PID, LOG_FACILITY );

    syslog( LOG_NOTICE, "%.80s starting . . .", SERVER_SOFTWARE );

    /* Handle command-line arguments. */
    parse_args( argc, argv );

    /* Check port number (upper limit is for future extensions). */
    if ( port < 1 || port > 65535 )
	{
	syslog( LOG_CRIT, "illegal port number %d", port );
	(void) fprintf( stderr, "%s: illegal port number %d\n", argv0, port );
	exit( 40 );
	}

    /* Read zone info now, in case we chroot(). */
    tzset();

    /* Look up hostname now, in case we chroot(). */
    lookup_hostname( &sa4, sizeof(sa4), &gotv4, &sa6, sizeof(sa6), &gotv6 );
    if ( ! ( gotv4 || gotv6 ) )
	{
	syslog( LOG_ERR, "can't find any valid address" );
	(void) fprintf( stderr, "%s: can't find any valid address\n", argv0 );
	exit( 41 );
	}
#ifdef EXECUTE_CGICLI
    /* CGIcli file. */
    if ( cgiclifile != (char*) 0 )
	read_cgiclifile( cgiclifile );
#endif /* EXECUTE_CGICLI */
    /* Throttle file. */
    maxthrottles = 0;
    numthrottles = 0;
    numurithrottles = 0;
#ifdef USE_IPTHROTTLE
    numipthrottles = 0;
    outiprule = -1;
#endif /* USE_IPTHROTTLE */

    throttles = (throttletab*) 0;
    if ( urithrottlefile != (char*) 0 )
	read_throttlefile( urithrottlefile, &numurithrottles );

#ifdef USE_IPTHROTTLE
    if ( ipthrottlefile != (char*) 0 )
	read_throttlefile( ipthrottlefile, &numipthrottles );

    subnets_uselen = 0;
    subnets_maxlen = 0;
    subnets_reload = 0;
    if ( subnetsfile != (char*) 0 )
	{
	initmatchsubnet( subnetsfile );
	subnets_reload = 1;
	}
#endif /* USE_IPTHROTTLE */

    /* Figure out uid/gid from user, getting it now is useful for root */
    pwd = getpwnam( user );
    if ( pwd == (struct passwd*) 0 )
	{
	syslog( LOG_CRIT, "unknown user - '%.80s'", user );
	(void) fprintf( stderr, "%s: unknown user - '%s'\n", argv0, user );
	exit( 42 );
	}
    uid = pwd->pw_uid;
    gid = pwd->pw_gid;

    /* Log file. */
    if ( logfile != (char*) 0 )
	{
	if ( strcmp( logfile, "/dev/null" ) == 0 )
	    {
	    no_log = 1;
	    logfp = (FILE*) 0;
	    }
	else
	    {
	    logfp = fopen( logfile, "a" );
	    if ( logfp == (FILE*) 0 )
		{
		syslog( LOG_CRIT, "%.80s - %m", logfile );
		perror( logfile );
		exit( 43 );
		}
	    (void) fcntl( fileno( logfp ), F_SETFD, FD_CLOEXEC );
	    if ( getuid() == 0 )
		{
		/* If we are root then we chown the log file to the user we'll
		** be switching to.
		*/
		if ( fchown( fileno( logfp ), uid, gid ) < 0 )
		    {
		    syslog( LOG_WARNING, "fchown logfile - %m" );
		    perror( "fchown logfile" );
		    }
		}
	    }
	}
    else
	logfp = (FILE*) 0;

    /* Switch directories if requested. */
    if ( dir != (char*) 0 )
	{
	if ( chdir( dir ) < 0 )
	    {
	    syslog( LOG_CRIT, "chdir - %m" );
	    perror( "chdir" );
	    exit( 44 );
	    }
	}
#ifdef USE_USER_DIR
    else if ( getuid() == 0 )
	{
	/* No explicit directory was specified, we're root, and the
	** USE_USER_DIR option is set - switch to the specified user's
	** home dir.
	*/
	if ( chdir( pwd->pw_dir ) < 0 )
	    {
	    syslog( LOG_CRIT, "chdir - %m" );
	    perror( "chdir" );
	    exit( 45 );
	    }
	}
#endif /* USE_USER_DIR */

    /* Get current directory. */
    {
    char mycwd[MAXPATHLEN+1];
    mycwd[0] = '\0';
    if ( getcwd( mycwd, sizeof(mycwd) - 1 ) == (char*) 0 )
	{
	syslog( LOG_CRIT, "getcwd - %m" );
	perror( "getcwd" );
	exit( 45 );
	}
    else
	{
	size_t	len = strlen( mycwd );
	if ( len == 0 || mycwd[len - 1] != '/' )
	    {
	    mycwd[len++] = '/';
	    mycwd[len]   = '\0';
	    }
	}
    cwd = e_strdup( mycwd );
    }

    if ( ! debug )
	{
	/* We're not going to use stdin stdout or stderr from here on, so close
	** them to save file descriptors.
	*/
	(void) fclose( stdin );
	(void) fclose( stdout );
	(void) fclose( stderr );

	/* Daemonize - make ourselves a subprocess. */
#ifdef HAVE_DAEMON
	if ( daemon( 1, 1 ) < 0 )
	    {
	    syslog( LOG_CRIT, "daemon - %m" );
	    exit( 46 );
	    }
#else /* HAVE_DAEMON */
	switch ( fork() )
	    {
	    case 0:
	    break;
	    case -1:
	    syslog( LOG_CRIT, "fork - %m" );
	    exit( 47 );
	    default:
	    exit( 0 );
	    }
#ifdef HAVE_SETSID
        (void) setsid();
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON */
	}
    else
	{
	/* Even if we don't daemonize, we still want to disown our parent
	** process.
	*/
#ifdef HAVE_SETSID
        (void) setsid();
#endif /* HAVE_SETSID */
	}

    if ( pidfile != (char*) 0 )
	{
	/* Write the PID file. */
	FILE* pidfp = fopen( pidfile, "w" );
	if ( pidfp == (FILE*) 0 )
	    {
	    syslog( LOG_CRIT, "%.80s - %m", pidfile );
	    exit( 48 );
	    }
	(void) fprintf( pidfp, "%d\n", (int) getpid() );
	(void) fclose( pidfp );
	}

    /* Set up to catch signals. */
    setup_signals();

    /* Initialize the timer package. */
    tmr_init();

    /* Initialize fdwatch package.  This has to be done before chroot
    ** if /dev/poll is used.
    */
    maxconnects = fdwatch_get_nfiles();

    if ( maxconnects < ( 16 + SPARE_FDS ) )
	{ /* also maxconnects < 0 */
	syslog( LOG_CRIT,
		"fdwatch initialization failure: maxconnects %d < %d too low",
		maxconnects, ( 16 + SPARE_FDS ) );
	exit( 58 );
	}
    maxconnects -= SPARE_FDS;

    /* if sendfile is enabled then the max. number of parallel connections
    ** is halved (so that the server does not run out of file descriptors).
    */
    if ( mmc_cfg_get_param( MMC_P_USE_SENDFILE ) != 0 )
	{
	if ( maxconnects < 32 )
	    {
	    syslog( LOG_CRIT,
		"sendfile enabled: real maxconnects %d < 32 too low",
		maxconnects );
	    exit( 58 );
	    }
	maxconnects /= 2;
	(void) mmc_cfg_set_param( MMC_P_UPLIMIT_MAX_OPENED_FILES,
				maxconnects );
	}

    /* Chroot if requested. */
    if ( do_chroot )
	{
	if ( chroot( cwd ) < 0 )
	    {
	    syslog( LOG_CRIT, "chroot - %m" );
	    perror( "chroot" );
	    exit( 49 );
	    }
	/* If we're logging and the logfile's pathname begins with the
	** chroot tree's pathname, then elide the chroot pathname so
	** that the logfile pathname still works from inside the chroot
	** tree.
	*/
	if ( logfp != (FILE*) 0 &&
	     logfile != (char*) 0 &&
	     strcmp( logfile, "-" ) != 0 &&
	     strcmp( cwd, "/" ) != 0 )
	    {
	    size_t cwd_len = strlen( cwd );
	    if ( cwd_len > 1 && strncmp( logfile, cwd, cwd_len ) == 0 )
		{
		char *cp2;
		cp2 = &logfile[ cwd_len - 1 ];
		(void) memmove( logfile, cp2, strlen( cp2 ) + 1 );
		/* (We already guaranteed that cwd ends with a slash, so leaving
		** that slash in logfile makes it an absolute pathname within
		** the chroot tree.)
		*/
		}
	    /*
	    **  else we may or may not be able to reopen log file,
	    **	see stat test below.
	    */
	    }
	/* reset cwd path, cwd always points to a non zero allocated string */
	(void) strcpy( cwd, "/" );
	/* Always chdir to / after a chroot. */
	if ( chdir( cwd ) < 0 )
	    {
	    syslog( LOG_CRIT, "chroot chdir - %m" );
	    perror( "chroot chdir" );
	    exit( 50 );
	    }
	}

    /* Switch directories again if requested. */
    if ( data_dir != (char*) 0 )
	{
	if ( chdir( data_dir ) < 0 )
	    {
	    syslog( LOG_CRIT, "data_dir chdir - %m" );
	    perror( "data_dir chdir" );
	    exit( 1 );
	    }
	}

    /* If we chrooted, then check if we will be able to reopen log file;
    ** in this case we probably are in a production testcase,
    ** thus we want to be reasonably sure to be able to reopen log file.
    */
    if ( logfp != (FILE*) 0 &&
	 logfile != (char*) 0 &&
	 strcmp( logfile, "-" ) != 0 &&
	 ( do_chroot != 0 || dir != (char*) 0 || data_dir != (char*) 0 )
       )
	{
	int flg_err = 1;
	struct stat sb1;
	struct stat sb2;
	if ( fstat( fileno( logfp ), &sb1 ) != 0 ||
	     stat( logfile, &sb2 ) != 0 ||
	     ( flg_err = 0,
		sb1.st_dev != sb2.st_dev ) ||
		sb1.st_ino != sb2.st_ino
	   )
	    {
	    int i = 0;
	    int i2 = 0;
	    char *vszWarn[2];

	    if ( flg_err != 0 )
		{
		syslog( LOG_WARNING, "(f)stat() logfile - %m" );
		perror( "(f)stat() logfile" );
		/* go on, path may not exist after chroot */
		}
	    if ( logfile[0] != '/' )
		{
		vszWarn[i++] = 
		"logfile is not an absolute path, you may not be able to re-open it";
		}
	    if ( do_chroot != 0 )
		{
		vszWarn[i++] =
		"logfile is not within the chroot tree, you will not be able to re-open it";
		}
	    else
		{
		vszWarn[i++] =
		"logfile path not found after -d, -dd chdir, you will not be able to re-open it";
		}
	    i2 = i;
	    for ( i = 0; i < i2; i++ )
		{
		syslog( LOG_WARNING, "%s", vszWarn[i] );
		if ( debug != 0 )
		    (void) fprintf( stderr, "%s: %s\n", argv0, vszWarn[i] );
		}
	    /* go on, this is not a fatal error */
	    }
	}

#ifdef EXECUTE_CGI
    if ( cgi_pattern != (char*) 0
#ifdef EXECUTE_CGICLI
	||  cgicli_vrec != (httpd_cgicli_vrec*) 0
#endif /* EXECUTE_CGICLI */
	)
	{
	if ( do_keepalive_conns != 0 )
	    {
	    do_keepalive_conns = 0;
	    syslog( LOG_NOTICE,
		"CGI enabled, Keep-Alive connections are not allowed !" );
	    }
	/* we enable close-on-exec only if we can spawn CGI subprocesses
	** and fd-map is enabled.
	*/
	if ( mmc_cfg_get_param( MMC_P_USE_SENDFILE ) )
	     mmc_cfg_set_param( MMC_P_CLOSE_ON_EXEC, 1 );
	/* NOTE: no else, close-on-exec is disabled by default */
	}
#endif /* EXECUTE_CGI */

    /* log information */
    syslog( LOG_NOTICE,
    "DefExpireAge %d OccMmcTime %d",
	mmc_cfg_get_param( MMC_P_DEFAULT_EXPIRE_AGE ),
	OccasionalMmcTime
	);
    syslog( LOG_NOTICE,
    "DesMaxMallocBytes %d DesMaxMallocFiles %d DesMaxMappedFiles %d DesMaxMappedBytes %d DesMaxOpenedFiles %d",
	mmc_cfg_get_param( MMC_P_DESIRED_MAX_MALLOC_BYTES ),
	mmc_cfg_get_param( MMC_P_DESIRED_MAX_MALLOC_FILES ),
	mmc_cfg_get_param( MMC_P_DESIRED_MAX_MAPPED_FILES ),
	mmc_cfg_get_param( MMC_P_DESIRED_MAX_MAPPED_BYTES ),
	mmc_cfg_get_param( MMC_P_DESIRED_MAX_OPENED_FILES )
	);
    syslog( LOG_NOTICE,
    "MaxFileSizeL0 %d MaxFileSizeL1 %d MaxFileSizeL2 %d MaxFileSizeL3 %d MaxFileSizeL4 %d",
	mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L0 ),
	mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L1 ),
	mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L2 ),
	mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L3 ),
	mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L4 )
	);
    syslog( LOG_NOTICE,
    "%s  %s (%s)  %s  %s",
	mmc_cfg_get_param( MMC_P_USE_MMAP ) > 0 ?
		"USE_MMAP" :
		" NO_mmap",
	mmc_cfg_get_param( MMC_P_USE_SENDFILE ) > 0 ?
		"USE_SENDFILE" :
		" NO_sendfile",
	httpd_typeof_sendfile(),
	mmc_cfg_get_param( MMC_P_USE_O_NOATIME ) > 0 ?
		"USE_O_NOATIME" :
		" NO_o_noatime",
	mmc_cfg_get_param( MMC_P_CLOSE_ON_EXEC ) > 0 ?
		"(close-on-exec)" :
		""
	);
    if ( mmc_cfg_get_param( MMC_P_USE_SENDFILE ) > 0 )
	{
	syslog( LOG_NOTICE,
	"MAX_SENDFILE_BLK_SIZE: %d bytes",
	(int) httpd_get_sf_blksize() );
	}
    syslog( LOG_NOTICE,
    "IdleSendRespTmo %ld IdleKeepAliveTmo %ld",
	SecIdleSendRespTimeLimit,
	SecIdleKeepAliveTimeLimit
	);
    syslog( LOG_NOTICE,
    "LoWmKeepAliveRqs %d HiWmKeepAliveRqs %d MaxKeepAliveFileSize %d",
	LoWmKeepAliveRqsLimit,
	HiWmKeepAliveRqsLimit,
	MaxKeepAliveFileSize
	);
    syslog( LOG_NOTICE,
    "%s  %s  MAX_AGE %d",
	(do_generate_indexes ?
		"Do_GenerateIndexes" :
		"NO_GenerateIndexes"),
	(do_keepalive_conns ?
		"Do_KeepAliveConns" :
		"NO_KeepAliveConns"),
	max_age
	);
    syslog( LOG_NOTICE,
    "MaxConnBytesLimit %ld NumUriThrottles %d %s %d",
		MaxConnBytesLimit,
		numurithrottles,
#ifdef USE_IPTHROTTLE
		"NumIpThrottles",
		numipthrottles
#else
		"NO_IpThrottles",
		0
#endif /* USE_IPTHROTTLE */
	);

    /* Initialize the HTTP layer.  Got to do this before giving up root,
    ** so that we can bind to a privileged port.
    */
    hs = httpd_initialize(
	hostname,
	(gotv4 ? &sa4 : (httpd_sockaddr*) 0),
	(gotv6 ? &sa6 : (httpd_sockaddr*) 0),
	port, cgi_pattern, cgicli_vrec,
	charset, max_age, cwd, no_log, logfp, no_symlink, do_vhost,
	do_global_passwd, url_pattern, local_pattern, no_empty_referers,
	do_generate_indexes, do_keepalive_conns, ConnSoRcvBuf, ConnSoSndBuf );
    if ( hs == (httpd_server*) 0 )
	{
	exit( 51 );
	}

#ifdef EXECUTE_CGICLI
    httpd_free_cgicli_vrec( cgicli_vrec );
    cgicli_vrec = (httpd_cgicli_vrec*) 0;
#endif /* EXECUTE_CGICLI */

    /* Set up the occasional idle connection timer. */
    if ( tmr_create( (struct timeval*) 0, occasional_idle, JunkClientData,
	MIN( OCCASIONAL_IDLE_TIME * 1000L, SecIdleKeepAliveTimeLimit * 1000L ),
	TMR_PERIODIC ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(occasional_idle) failed" );
	exit( 52 );
	}

#if defined(LOG_FLUSH_TIME) && (LOG_FLUSH_TIME > 0)
    /* Set up the occasional log timer. */
    if ( logfp != (FILE*) 0 &&
	tmr_create( (struct timeval*) 0, occasional_log, JunkClientData,
		LOG_FLUSH_TIME * 1000L, TMR_PERIODIC ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(occasional_log) failed" );
	exit( 52 );
	}
#endif /* LOG_FLUSH_TIME */

    /* Set up the occasional mmc timer. */
    if ( tmr_create( (struct timeval*) 0, occasional_mmc, JunkClientData,
		OccasionalMmcTime * 1000L, TMR_PERIODIC ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(occasional_mmc) failed" );
	exit( 52 );
	}

    /* Set up the occasional tmr timer. */
    if ( tmr_create( (struct timeval*) 0, occasional_tmr, JunkClientData,
		OCCASIONAL_TMR_TIME * 1000L, TMR_PERIODIC ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(occasional_tmr) failed" );
	exit( 52 );
	}

    if ( numthrottles > 0 )
	{
	/* Set up the throttles timer. */
	if ( tmr_create( (struct timeval*) 0, update_throttles, JunkClientData,
		THROTTLE_TIME * 1000L, TMR_PERIODIC ) == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(update_throttles) failed" );
	    exit( 53 );
	    }
	}

#ifdef STATS_TIME
    /* Set up the stats timer. */
    if ( tmr_create( (struct timeval*) 0, show_stats, JunkClientData,
		STATS_TIME * 1000L, TMR_PERIODIC ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(show_stats) failed" );
	exit( 54 );
	}
#endif /* STATS_TIME */

    start_time = stats_time = time( (time_t*) 0 );
    stats_requests     = 0;
    stats_connections  = 0;
    stats_connaborted  = 0;
    stats_simultaneous = 0;
    stats_resp_bytes   = 0;
    stats_body_bytes   = 0;
    stats_ovfconnects  = 0;

    /* If we're root, try to become someone else. */
    if ( getuid() == 0 )
	{
	/* Set aux groups to null. */
	if ( setgroups( 0, (const gid_t*) 0 ) < 0 )
	    {
	    syslog( LOG_CRIT, "setgroups - %m" );
	    exit( 55 );
	    }
	/* Set primary group. */
	if ( setgid( gid ) < 0 )
	    {
	    syslog( LOG_CRIT, "setgid - %m" );
	    exit( 56 );
	    }
	/* Try setting aux groups correctly - not critical if this fails. */
	if ( initgroups( user, gid ) < 0 )
	    syslog( LOG_WARNING, "initgroups - %m" );
#ifdef HAVE_SETLOGIN
	/* Set login name. */
        (void) setlogin( user );
#endif /* HAVE_SETLOGIN */
	/* Set uid. */
	if ( setuid( uid ) < 0 )
	    {
	    syslog( LOG_CRIT, "setuid - %m" );
	    exit( 57 );
	    }
	/* Check for unnecessary security exposure. */
	if ( ! do_chroot )
	    syslog( LOG_WARNING, "started as root without requesting chroot" );
	}

    /* Initialize our connections table. */
    hiwmconnects1 = ( maxconnects / 5 ) * 3;		/* 60% */
    hiwmconnects2 = ( maxconnects / 5 ) * 4;		/* 80% */
							/* 90% */
    hiwmconnects3 = ( maxconnects - ( maxconnects - hiwmconnects2 ) / 2 );
    cnum = ( maxconnects - hiwmconnects3 ) / 2;		/* 95% - 99% */
    if ( cnum < 1 )
	 cnum = 1;
    else
    if ( cnum > 128 )
	 cnum = 128;
    hiwmconnects4 = ( maxconnects - cnum );

    connects = CNEW( connecttab, maxconnects + 2 );
    if ( connects == (connecttab*) 0 )
	{
	syslog( LOG_CRIT, "out of memory allocating a connecttab[%d]",
		maxconnects );
	exit( 59 );
	}
    freeconnects = CNEW( connecttab*, (maxconnects + 2) );
    if ( freeconnects == (connecttab**) 0 )
	{
	syslog( LOG_CRIT, "out of memory allocating a freeconnecttab[%d]",
		maxconnects );
	exit( 59 );
	}
    syslog( LOG_NOTICE, "allocated connecttab[], maxconnects %d",
		maxconnects );
    /* CNEW() allocated memory has been zeroed */

    numfreeconnects = maxconnects;
    for ( cnum = 0; cnum < maxconnects; ++cnum )
	{
	freeconnects[cnum] = &connects[--numfreeconnects];
	connects[cnum].conn_state = CNST_FREE;
	connects[cnum].hc = (httpd_conn*) 0;
	}
    numfreeconnects = maxconnects;
    numconnects = 0;
#ifndef SYSLOG_EACH_TOOMCONNS
    ovfconnects = 0;
#endif /* SYSLOG_EACH_TOOMCONNS */
    httpd_conn_count = 0;

    if ( hs != (httpd_server*) 0 )
	{
	if ( hs->listen4_fd != -1 )
	    fdwatch_add_fd( hs->listen4_fd, (void*) 0, FDW_READ );
	if ( hs->listen6_fd != -1 )
	    fdwatch_add_fd( hs->listen6_fd, (void*) 0, FDW_READ );
	}

    /* Main loop. */
    (void) gettimeofday( &tv, (struct timezone*) 0 );
    do
	{
	/* Main inner loop. */
	do
	    {

	    if ( gotSigMask )
		break;

	    /* Do the fd watch. */
	    num_ready = fdwatch( tmr_mstimeout( &tv ) );

	    if ( num_ready < 0 )
		{
		if ( errno == EINTR )
		    continue;       /* try again */
		syslog( LOG_ERR, "fdwatch(%d): neverrs %ld, nfderrs %ld - %m",
			num_ready,
			fdwatch_get_neverrs(),
			fdwatch_get_nfderrs() );
		exit( 60 );
		}

	    (void) gettimeofday( &tv, (struct timezone*) 0 );

	    hs->nowtime = tv.tv_sec;

	    if ( num_ready == 0 )
		{
		/* No fd's are ready - run the timers. */
		tmr_run( &tv );
		continue;
		}

	    /* Is it a new connection? */
	    if ( hs->listen6_fd != -1 && 
		fdwatch_check_fd( hs->listen6_fd ) )
		{
		if ( handle_newconnect( &tv, hs->listen6_fd ) )
		    /* Go around the loop and do another fdwatch, rather than
		    ** dropping through and processing existing connections.
		    ** New connections always get priority.
		    */
		    continue;
		}
	    if ( hs->listen4_fd != -1 && 
		fdwatch_check_fd( hs->listen4_fd ) )
		{
		if ( handle_newconnect( &tv, hs->listen4_fd ) )
		    /* Go around the loop and do another fdwatch, rather than
		    ** dropping through and processing existing connections.
		    ** New connections always get priority.
		    */
		    continue;
		}

	    /* Find the connections that need servicing. */
	    for ( ridx = 0; ridx < num_ready; ++ridx )
		{
		c = (connecttab*) fdwatch_get_client_data( ridx );
		/* Null client data == server socket (already handled) */
		if ( c == (connecttab*) 0 )
		    continue;

		switch( c->conn_state )
		    {
		    case CNST_READING:
			handle_read( c, &tv );
			continue;
		    case CNST_SENDING:
			handle_send( c, &tv );
			continue;
		    case CNST_SENDING_RESP:
			handle_send_resp( c, &tv );
			continue;
		    case CNST_LINGERING:
			handle_linger( c, &tv );
			continue;
		    default:
			continue;
		    }
		}
	    tmr_run( &tv );
	    }
	while ( terminate == 0 );

	if ( gotSigMask )
	    {   /* we got one or more signal */

	    if ( hs == (httpd_server*) 0 )
		break;

	    /* this should not be necessary but we want to be paranoid
	    ** and protected ourself from compiler bugs or
	    ** other strange things that might happen (once a year).
	    */
	    gotSigMask &= GOT_M_SIGMASK;

	    if ( gotSigMask & GOT_O_SIGHUP )
		{
		gotSigMask &= ~GOT_O_SIGHUP;
		thttpd_log_reopen();
		}

	    if ( gotSigMask & GOT_O_SIGUSR1 )
		{
		/* Graceful shutdown in order to continue to serve
		** active connections (without aborting them abruptively).
		*/
		gotSigMask &= ~GOT_O_SIGUSR1;
		if ( !terminate )
		    {
		    terminate = 1;

		    /* don't listen to wait for new connections anymore */
		    if ( hs->listen4_fd != -1 &&
			fdwatch_is_fd ( hs->listen4_fd ) )
			fdwatch_del_fd( hs->listen4_fd );
		    if ( hs->listen6_fd != -1 &&
			fdwatch_is_fd ( hs->listen6_fd ) )
			fdwatch_del_fd( hs->listen6_fd );

		    /* disable keep alive (to speed up shutdown) */
		    hs->do_keepalive_conns = 0;

		    /* synchronize fdwatch events */
		    fdwatch_sync();

		    /* Close listen descriptors.
		    ** NOTE: we cannot call httpd_terminate(), because
		    ** it frees server structures that we are going to use
		    ** until there are open connections.
		    */
		    httpd_unlisten( hs );
		    }
		/* log, so we know how many connections we have to wait for */
		syslog( LOG_NOTICE,
			"got signal SIGUSR1 (numconnects %d)", numconnects);

		/* if there are no connections we exit now from while loop,
		** see below condition.
		*/
		}

	    if ( gotSigMask & GOT_O_SIGUSR2 )
		{
		gotSigMask &= ~GOT_O_SIGUSR2;
		logstats( (struct timeval*) 0 );
#ifdef USE_IPTHROTTLE
		initmatchsubnet( subnetsfile );
#endif /* USE_IPTHROTTLE */
		}
	    }
	}
    while( terminate == 0 || numconnects > 0 );

    /* The main loop terminated. */
    shut_down();
    syslog( LOG_NOTICE, "exiting" );
    closelog();
    exit( 0 + SIGUSR1 * terminate );
    }


#if !defined(GENERATE_INDEXES) ||	\
    !defined(EXECUTE_CGI) ||		\
    !defined(EXECUTE_CGICLI) ||		\
    !defined(USE_IPTHROTTLE)

#define MSG_ARG_NOINDEXES	0
#define MSG_ARG_NOCGI		1
#define MSG_ARG_NOCGICLI	2
#define MSG_ARG_NOIPTHROTTLE	3

static void print_arg_msg( const int msg_type, const char *optname )
    {
    char *p;

    switch( msg_type )
	{
	case MSG_ARG_NOINDEXES:
	    p = "generate indexes";
	    break;
	case MSG_ARG_NOCGI:
	    p = "CGI execution";
	    break;
	case MSG_ARG_NOCGICLI:
	    p = "CGI-CLI execution";
	    break;
	case MSG_ARG_NOIPTHROTTLE:
	    p = "IP throttle";
	    break;
	default:
	    p = "unknown message";
	    break;
	}
    fprintf( stderr,
	"\n%s: NOTE: %s, %s %s !\n",
	argv0, optname, p, "has been disabled at compile time" );
    }
#endif	/* !defined(GENERATE_INDEXES) || !defined(EXECUTE_CGI) || !defined(EXECUTE_CGICLI) || !defined(USE_IPTHROTTLE) */


static void
parse_args( int argc, char** argv )
    {
    int argn;
    int flgCfg = 0;

    debug = 0;
    port = DEFAULT_PORT;
    dir = (char*) 0;
    data_dir = (char*) 0;
#ifdef ALWAYS_CHROOT
    do_chroot = 1;
#else /* ALWAYS_CHROOT */
    do_chroot = 0;
#endif /* ALWAYS_CHROOT */
    no_log = 0;
    no_symlink = do_chroot;
#ifdef ALWAYS_VHOST
    do_vhost = 1;
#else /* ALWAYS_VHOST */
    do_vhost = 0;
#endif /* ALWAYS_VHOST */
#ifdef ALWAYS_GLOBAL_PASSWD
    do_global_passwd = 1;
#else /* ALWAYS_GLOBAL_PASSWD */
    do_global_passwd = 0;
#endif /* ALWAYS_GLOBAL_PASSWD */
#if defined(EXECUTE_CGI) && defined(CGI_PATTERN)
    cgi_pattern = CGI_PATTERN;
#else /* EXECUTE_CGI && CGI_PATTERN */
    cgi_pattern = (char*) 0;
#endif /* !(EXECUTE_CGI && CGI_PATTERN) */
    cgicli_vrec = (httpd_cgicli_vrec*) 0;
#ifdef GENERATE_INDEXES
    do_generate_indexes = 1;
#else
    do_generate_indexes = 0;
#endif
    do_keepalive_conns = 1;
    url_pattern = (char*) 0;
    no_empty_referers = 0;
    local_pattern = (char*) 0;
#ifdef EXECUTE_CGICLI
    cgiclifile = (char*) 0;
#endif /* EXECUTE_CGICLI */
    urithrottlefile = (char*) 0;
#ifdef USE_THROTTLE
    ipthrottlefile = (char*) 0;
#endif /* USE_THROTTLE */
    hostname = (char*) 0;
    logfile = (char*) 0;
    pidfile = (char*) 0;
    user = DEFAULT_USER;
    charset = DEFAULT_CHARSET;
    max_age = DEFAULT_MAX_AGE;

    /* set values (ex config.h) */
#ifdef CONN_SO_RCVBUF
    ConnSoRcvBuf = CONN_SO_RCVBUF;
#else
    ConnSoRcvBuf = 0;
#endif
#ifdef CONN_SO_SNDBUF
    ConnSoSndBuf = CONN_SO_SNDBUF;
#else
    ConnSoSndBuf = 0;
#endif
#ifdef MAX_CONN_BYTES_LIMIT
    MaxConnBytesLimit = MAX_CONN_BYTES_LIMIT;
#else
    MaxConnBytesLimit = THROTTLE_NOLIMIT;
#endif
#ifdef	OCCASIONAL_MMC_TIME
    mmc_cfg_set_param( MMC_P_CLEANUP_TIME,
				OCCASIONAL_MMC_TIME );
#endif
#ifdef	DEFAULT_EXPIRE_AGE
    mmc_cfg_set_param( MMC_P_DEFAULT_EXPIRE_AGE,
				DEFAULT_EXPIRE_AGE );
#endif
#ifdef	DESIRED_MAX_MALLOC_BYTES
    mmc_cfg_set_param( MMC_P_DESIRED_MAX_MALLOC_BYTES,
				DESIRED_MAX_MALLOC_BYTES );
#endif
#ifdef	DESIRED_MAX_MALLOC_FILES
    mmc_cfg_set_param( MMC_P_DESIRED_MAX_MALLOC_FILES,
				DESIRED_MAX_MALLOC_FILES );
#endif
#ifdef	DESIRED_MAX_MAPPED_FILES
    mmc_cfg_set_param( MMC_P_DESIRED_MAX_MAPPED_FILES,
				DESIRED_MAX_MAPPED_FILES );
#endif
#ifdef	DESIRED_MAX_MAPPED_BYTES
    mmc_cfg_set_param( MMC_P_DESIRED_MAX_MAPPED_BYTES,
				DESIRED_MAX_MAPPED_BYTES );
#endif
#ifdef	DESIRED_MAX_OPENED_FILES
    mmc_cfg_set_param( MMC_P_DESIRED_MAX_OPENED_FILES,
				DESIRED_MAX_OPENED_FILES );
#endif
#ifdef	MAX_SENDFILE_BLK_SIZE
    httpd_set_sf_blksize( MAX_SENDFILE_BLK_SIZE );
#endif
#ifdef	USE_SENDFILE
    mmc_cfg_set_param( MMC_P_USE_SENDFILE,
				1 );
#endif
#ifdef	USE_O_NOATIME
    mmc_cfg_set_param( MMC_P_USE_O_NOATIME,
				USE_O_NOATIME );
#endif
#ifdef	MAX_FILE_SIZE_L0
    mmc_cfg_set_param( MMC_P_MAX_FILE_SIZE_L0,
				MAX_FILE_SIZE_L0 );
#endif
#ifdef	MAX_FILE_SIZE_L1
    mmc_cfg_set_param( MMC_P_MAX_FILE_SIZE_L1,
				MAX_FILE_SIZE_L1 );
#endif
#ifdef	MAX_FILE_SIZE_L2
    mmc_cfg_set_param( MMC_P_MAX_FILE_SIZE_L2,
				MAX_FILE_SIZE_L2 );
#endif
#ifdef	MAX_FILE_SIZE_L3
    mmc_cfg_set_param( MMC_P_MAX_FILE_SIZE_L3,
				MAX_FILE_SIZE_L3 );
#endif
#ifdef	MAX_FILE_SIZE_L4
    mmc_cfg_set_param( MMC_P_MAX_FILE_SIZE_L4,
				MAX_FILE_SIZE_L4 );
#endif
#ifdef MAX_KEEPALIVE_FILE_SIZE
    MaxKeepAliveFileSize = MAX_KEEPALIVE_FILE_SIZE;
#else
    MaxKeepAliveFileSize = 0;
#endif
    {
    int	DefaultExpireAge =
			mmc_cfg_get_param( MMC_P_DEFAULT_EXPIRE_AGE );
    int	DesiredMaxMallocBytes = /* value should always fit into a int */
			mmc_cfg_get_param( MMC_P_DESIRED_MAX_MALLOC_BYTES );
    int	DesiredMaxMallocFiles =
			mmc_cfg_get_param( MMC_P_DESIRED_MAX_MALLOC_FILES );
    int	DesiredMaxMappedFiles =
			mmc_cfg_get_param( MMC_P_DESIRED_MAX_MAPPED_FILES );
    int	DesiredMaxMappedBytes =
			mmc_cfg_get_param( MMC_P_DESIRED_MAX_MAPPED_BYTES );
    int	DesiredMaxOpenedFiles =
			mmc_cfg_get_param( MMC_P_DESIRED_MAX_OPENED_FILES );

    if ( DefaultExpireAge < 1 ||
	 DesiredMaxMallocBytes < 1 ||
	 DesiredMaxMallocFiles < 1 ||
	 DesiredMaxMappedFiles < 1 ||
	 DesiredMaxMappedBytes < 1 ||
	 DesiredMaxOpenedFiles < 1 )
	{
	fprintf( stderr,
	"%s: bad mmc default parameter (%s %d %s %d %s %d %s %d %s %d %s %d)\n",
		argv0,
		"DefaultExpireAge",	DefaultExpireAge,
		"DesiredMaxMallocBytes",DesiredMaxMallocBytes,
		"DesiredMaxMallocFiles",DesiredMaxMallocFiles,
		"DesiredMaxMappedFiles",DesiredMaxMappedFiles,
		"DesiredMaxMappedBytes",DesiredMaxMappedBytes,
		"DesiredMaxOpenedFiles",DesiredMaxOpenedFiles
		);
	exit( 60 );
	}
    }

    {
    int	MaxFileSizeL0 = mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L0 );
    int	MaxFileSizeL1 = mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L1 );
    int	MaxFileSizeL2 = mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L2 );
    int	MaxFileSizeL3 = mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L3 );
    int	MaxFileSizeL4 = mmc_cfg_get_param( MMC_P_MAX_FILE_SIZE_L4 );

    if ( MaxFileSizeL0 < 0 ||
	 MaxFileSizeL1 < 1 ||
	 MaxFileSizeL2 < 1 ||
	 MaxFileSizeL3 < 1 ||
	 MaxFileSizeL4 < 1 )
	{
	fprintf( stderr,
	"%s: bad mmc default parameter (%s %d %s %d %s %d %s %d %s %d)\n",
		argv0,
		"MaxFileSizeL0",	MaxFileSizeL0,
		"MaxFileSizeL1",	MaxFileSizeL1,
		"MaxFileSizeL2",	MaxFileSizeL2,
		"MaxFileSizeL3",	MaxFileSizeL3,
		"MaxFileSizeL4",	MaxFileSizeL4
		);
	exit( 60 );
	}
    }

    argn = 1;
    while ( argn < argc && argv[argn][0] == '-' )
	{
	if ( strcmp( argv[argn], "-C" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    if (!flgCfg)
		{
		flgCfg = 1;
		read_config( argv[argn] );
		}
	    }
	else if ( strcmp( argv[argn], "-p" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    port = atoi( argv[argn] );
	    }
	else if ( strcmp( argv[argn], "-d" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    dir = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-r" ) == 0 )
	    {
	    do_chroot = 1;
	    no_symlink = 1;
	    }
	else if ( strcmp( argv[argn], "-nor" ) == 0 )
	    {
	    do_chroot = 0;
	    no_symlink = 0;
	    }
	else if ( strcmp( argv[argn], "-dd" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    data_dir = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-s" ) == 0 )
	    no_symlink = 0;
	else if ( strcmp( argv[argn], "-nos" ) == 0 )
	    no_symlink = 1;
	else if ( strcmp( argv[argn], "-u" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    user = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-mcbl" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    MaxConnBytesLimit = atol( argv[argn] );
	    if ( MaxConnBytesLimit < MIN_MAX_CONN_BYTES_LIMIT )
		{
		fprintf(stderr, "%s: -mcbl %ld, value too low ( < %ld ) !\n",
			argv0, MaxConnBytesLimit, MIN_MAX_CONN_BYTES_LIMIT );
		usage();
		}
	    }
	else if ( strcmp( argv[argn], "-nopc" ) == 0 ||
		  strcmp( argv[argn], "-noka" ) == 0 )
	    {
	    do_keepalive_conns = 0;
	    }
	else if ( strcmp( argv[argn], "-nogi" ) == 0 )
	    {
	    do_generate_indexes = 0;
#ifndef GENERATE_INDEXES
	    print_arg_msg( MSG_ARG_NOINDEXES, "-nogi" );
#endif
	    }
	else if ( strcmp( argv[argn], "-c" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
#ifdef EXECUTE_CGI
	    cgi_pattern = argv[argn];
#else
	    print_arg_msg( MSG_ARG_NOCGI, "-c" );
#endif /* EXECUTE_CGI */
	    }
	else if ( strcmp( argv[argn], "-cgicli" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
#ifdef EXECUTE_CGICLI
	    cgiclifile = argv[argn];
#else
	    print_arg_msg( MSG_ARG_NOCGICLI, "-cgicli" );
#endif /* EXECUTE_CGICLI */
	    }
	else if ( strcmp( argv[argn], "-t" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    urithrottlefile = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-ti" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
#ifdef USE_IPTHROTTLE
	    ipthrottlefile = argv[argn];
#else
	    print_arg_msg( MSG_ARG_NOIPTHROTTLE, "-ti" );
#endif /* USE_IPTHROTTLE */
	    }
	else if ( strcmp( argv[argn], "-sn" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
#ifdef USE_IPTHROTTLE
	    subnetsfile = argv[argn];
#else
	    print_arg_msg( MSG_ARG_NOIPTHROTTLE, "-sn" );
#endif /* USE_IPTHROTTLE */
	    }
	else if ( strcmp( argv[argn], "-h" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    hostname = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-l" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    logfile = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-v" ) == 0 )
	    do_vhost = 1;
	else if ( strcmp( argv[argn], "-nov" ) == 0 )
	    do_vhost = 0;
	else if ( strcmp( argv[argn], "-g" ) == 0 )
	    do_global_passwd = 1;
	else if ( strcmp( argv[argn], "-nog" ) == 0 )
	    do_global_passwd = 0;
	else if ( strcmp( argv[argn], "-i" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    pidfile = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-T" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    charset = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-M" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    max_age = atoi( argv[argn] );
	    }
	else if ( strcmp( argv[argn], "-V" ) == 0 )
	    {
	    (void) fprintf( stderr, "%s\n", SERVER_SOFTWARE );
	    exit( 0 );
	    }
	else if ( strcmp( argv[argn], "-D" ) == 0 )
	    debug = 1;
	else
	    usage();
	++argn;
	}
    if ( argn != argc )
	usage();
    }


static void
usage( void )
    {
    (void) fprintf( stderr,
"usage:  %s [-C configfile] [-p port] [-d dir] [-r|-nor] [-dd data_dir] [-s|-nos] [-v|-nov] [-g|-nog] [-u user] [-nogi] [-nopc|-noka] [-mcbl MaxConnBytesLimit] [-c cgipat] [-cgicli clifile] [-t throttlefile] [-ti ipthrottlefile] [-sn subnetsfile] [-h host] [-l logfile] [-i pidfile] [-T charset] [-M maxage] [-V] [-D]\n",
	argv0 );
    exit( 60 );
    }


#ifdef USE_LAYOUT
static void *
map_layoutfile( char* filename, int* pfilesize )
    {
    struct stat sb = { 0 };
    int   filefd = EOF;
    void *pfilebuf;

    /* sanity checks */
    if ( filename == (char*) 0 )
	return NULL;
    if ( filename[0] == '\0' )
	return NULL;
    if ( pfilesize == (int*) 0 )
	return NULL;

    /* get file size */
    if ( stat( filename, &sb ) != 0)
	return NULL;

    /* an empty file or a too big file is not mapped */
    if ( sb.st_size == 0 )
	return NULL;

    if ( sb.st_size > 16384 )
	return NULL;

    /* alloc file contents (no fdmap) */
    if ( ( pfilebuf = malloc( sb.st_size + sizeof(long) ) ) == NULL )
	return NULL;

    if ( ( filefd = open( filename, O_RDONLY ) ) == -1 )
	{
	free( pfilebuf );
	return NULL;
	}

    if ( read( filefd, pfilebuf, sb.st_size ) != (ssize_t) sb.st_size )
	{
	free( pfilebuf );
	(void) close( filefd );
	return NULL;
	}

    (void) close( filefd );

    /* OK, return */

    *pfilesize = (int) sb.st_size;

    return pfilebuf;
    }
#endif /* USE_LAYOUT */


static void
read_config( char* filename )
    {
    int    line_num = 0;
    size_t line_length = 0;
    const char *word_seps = " \t\n\r"; /* word separators */
    FILE* fp;
    char* cp;
    char* cp2;
    char* name;
    char* value;
    char line[4096];

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	{
	perror( filename );
	exit( 61 );
	}

    while ( fgets( line, sizeof(line), fp ) != (char*) 0 )
	{
	/* increment line number */
	line_num++;

	/* check for a normal text line */
	line_length = strlen( line );
	if ( line_length == 0 || line[line_length - 1] != '\n' )
	    {
	    (void) fprintf( stderr,
		"%s: binary data or line too long: no newline (line %d)\n",
		argv0, line_num );
	    exit( 62 );
	    }

	/* Trim comments. */
	if ( ( cp = strchr( line, '#' ) ) != (char*) 0 )
	    *cp = '\0';

	/* Skip leading whitespace (for empty lines) */
	/* and split line into words. */
	for ( cp = line + strspn( line, word_seps ); *cp != '\0'; cp = cp2 )
	    {
	    /* Skip leading whitespace. */
	    cp += strspn( cp, word_seps );
	    /* Find next whitespace. */
	    cp2 = cp + strcspn( cp, word_seps );
	    /* Insert EOS and advance next-word pointer. */
	    while ( *cp2 && strchr( word_seps, *cp2 ) != (char*) 0 )
		*cp2++ = '\0';
	    /* Split into name and value. */
	    name = cp;
	    value = strchr( name, '=' );
	    if ( value != (char*) 0 )
		*value++ = '\0';
	    /* Interpret. */
	    if ( strcasecmp( name, "debug" ) == 0 )
		{
		no_value_required( name, value );
		debug = 1;
		}
	    else if ( strcasecmp( name, "port" ) == 0 )
		{
		value_required( name, value );
		port = atoi( value );
		}
	    else if ( strcasecmp( name, "dir" ) == 0 )
		{
		value_required( name, value );
		dir = e_strdup( value );
		}
	    else if ( strcasecmp( name, "chroot" ) == 0 )
		{
		no_value_required( name, value );
		do_chroot = 1;
		no_symlink = 1;
		}
	    else if ( strcasecmp( name, "nochroot" ) == 0 )
		{
		no_value_required( name, value );
		do_chroot = 0;
		no_symlink = 0;
		}
	    else if ( strcasecmp( name, "data_dir" ) == 0 )
		{
		value_required( name, value );
		data_dir = e_strdup( value );
		}
	    else if ( strcasecmp( name, "symlink"  ) == 0  ||
		      strcasecmp( name, "symlinks" ) == 0 )
		{
		no_value_required( name, value );
		no_symlink = 0;
		}
	    else if ( strcasecmp( name, "nosymlink" )  == 0 ||
		      strcasecmp( name, "nosymlinks" ) == 0 )
		{
		no_value_required( name, value );
		no_symlink = 1;
		}
	    else if ( strcasecmp( name, "user" ) == 0 )
		{
		value_required( name, value );
		user = e_strdup( value );
		}
	    else if ( strcasecmp( name, "NoPersistentConns" ) == 0 ||
		      strcasecmp( name, "NoKeepAliveConns"  ) == 0 )
		{
		no_value_required( name, value );
		do_keepalive_conns = 0;
		}
	    else if ( strcasecmp( name, "NoGenerateIndexes" ) == 0 )
		{
		no_value_required( name, value );
		do_generate_indexes = 0;
#ifndef GENERATE_INDEXES
		print_arg_msg( MSG_ARG_NOINDEXES, name );
#endif
		}
	    else if ( strcasecmp( name, "cgipat" ) == 0 )
		{
		value_required( name, value );
#ifdef EXECUTE_CGI
		cgi_pattern = e_strdup( value );
#else
		print_arg_msg( MSG_ARG_NOCGI, name );
#endif /* EXECUTE_CGI */
		}
	    else if ( strcasecmp( name, "cgicli" ) == 0 )
		{
		value_required( name, value );
#ifdef EXECUTE_CGICLI
		cgiclifile = e_strdup( value );
#else
		print_arg_msg( MSG_ARG_NOCGICLI, name );
#endif /* EXECUTE_CGICLI */
		}
	    else if ( strcasecmp( name, "urlpat" ) == 0 )
		{
		value_required( name, value );
		url_pattern = e_strdup( value );
		}
	    else if ( strcasecmp( name, "noemptyreferers" ) == 0 )
		{
		no_value_required( name, value );
		no_empty_referers = 1;
		}
	    else if ( strcasecmp( name, "localpat" ) == 0 )
		{
		value_required( name, value );
		local_pattern = e_strdup( value );
		}
	    else if ( strcasecmp( name, "throttles" ) == 0 )
		{
		value_required( name, value );
		urithrottlefile = e_strdup( value );
		}
	    else if ( strcasecmp( name, "ipthrottles" ) == 0 )
		{
		value_required( name, value );
#ifdef USE_IPTRHOTTLE
		ipthrottlefile = e_strdup( value );
#else
		print_arg_msg( MSG_ARG_NOIPTHROTTLE, name );
#endif /* USE_IPTHROTTLE */
		}
	    else if ( strcasecmp( name, "subnets" ) == 0 )
		{
		value_required( name, value );
#ifdef USE_IPTRHOTTLE
		subnetsfile = e_strdup( value );
#else
		print_arg_msg( MSG_ARG_NOIPTHROTTLE, name );
#endif /* USE_IPTHROTTLE */
		}
	    else if ( strcasecmp( name, "host" ) == 0 )
		{
		value_required( name, value );
		hostname = e_strdup( value );
		}
	    else if ( strcasecmp( name, "logfile" ) == 0 )
		{
		value_required( name, value );
		logfile = e_strdup( value );
		}
	    else if ( strcasecmp( name, "vhost" ) == 0 )
		{
		no_value_required( name, value );
		do_vhost = 1;
		}
	    else if ( strcasecmp( name, "novhost" ) == 0 )
		{
		no_value_required( name, value );
		do_vhost = 0;
		}
	    else if ( strcasecmp( name, "globalpasswd" ) == 0 )
		{
		no_value_required( name, value );
		do_global_passwd = 1;
		}
	    else if ( strcasecmp( name, "noglobalpasswd" ) == 0 )
		{
		no_value_required( name, value );
		do_global_passwd = 0;
		}
	    else if ( strcasecmp( name, "pidfile" ) == 0 )
		{
		value_required( name, value );
		pidfile = e_strdup( value );
		}
	    else if ( strcasecmp( name, "charset" ) == 0 )
		{
		value_required( name, value );
		charset = e_strdup( value );
		}
	    else if ( strcasecmp( name, "max_age" ) == 0 )
		{
		value_required( name, value );
		max_age = atoi( value );
		}
	    else if ( strcasecmp( name, "CONN_SO_RCVBUF" ) == 0 )
		{
		value_required( name, value );
		ConnSoRcvBuf = atoi( value );
		}
	    else if ( strcasecmp( name, "CONN_SO_SNDBUF" ) == 0 )
		{
		value_required( name, value );
		ConnSoSndBuf = atoi( value );
		}
	    else if ( strcasecmp( name, "MAX_CONN_BYTES_LIMIT" ) == 0 )
		{
		value_required( name, value );
		MaxConnBytesLimit = atol( value );
		if ( MaxConnBytesLimit < MIN_MAX_CONN_BYTES_LIMIT )
		     MaxConnBytesLimit = MIN_MAX_CONN_BYTES_LIMIT;
		}
	    else if ( strcasecmp( name, "DEFAULT_EXPIRE_AGE" ) == 0 )
		{
		int	DefaultExpireAge;
		value_required( name, value );
		DefaultExpireAge = mmc_cfg_set_param(
				MMC_P_DEFAULT_EXPIRE_AGE,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "DESIRED_MAX_MALLOC_BYTES" ) == 0 )
		{
		int	DesiredMaxMallocBytes;
		value_required( name, value );
		DesiredMaxMallocBytes = mmc_cfg_set_param(
				MMC_P_DESIRED_MAX_MALLOC_BYTES,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "DESIRED_MAX_MALLOC_FILES" ) == 0 )
		{
		int	DesiredMaxMallocFiles;
		value_required( name, value );
		DesiredMaxMallocFiles = mmc_cfg_set_param(
				MMC_P_DESIRED_MAX_MALLOC_FILES,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "DESIRED_MAX_MAPPED_FILES" ) == 0 )
		{
		int	DesiredMaxMappedFiles;
		value_required( name, value );
		DesiredMaxMappedFiles = mmc_cfg_set_param(
				MMC_P_DESIRED_MAX_MAPPED_FILES,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "DESIRED_MAX_MAPPED_BYTES" ) == 0 )
		{
		int	DesiredMaxMappedBytes;
		value_required( name, value );
		DesiredMaxMappedBytes = mmc_cfg_set_param(
				MMC_P_DESIRED_MAX_MAPPED_BYTES,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "DESIRED_MAX_OPENED_FILES" ) == 0 )
		{
		int	DesiredMaxOpenedFiles;
		value_required( name, value );
		DesiredMaxOpenedFiles = mmc_cfg_set_param(
				MMC_P_DESIRED_MAX_OPENED_FILES,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "MAX_SENDFILE_BLK_SIZE" ) == 0 )
		{
		size_t	MaxSendfileBlkSize;
		value_required( name, value );
		MaxSendfileBlkSize = (size_t) atoi( value );
		(void) httpd_set_sf_blksize( MaxSendfileBlkSize );
		}
	    else if ( strcasecmp( name, "USE_SENDFILE" ) == 0 )
		{
		int	UseSendFile;
		UseSendFile = mmc_cfg_set_param(
				MMC_P_USE_SENDFILE,
				1 );
		}
	    else if ( strcasecmp( name, "NO_SENDFILE" ) == 0 )
		{
		int	NoSendFile;
		NoSendFile = mmc_cfg_set_param(
				MMC_P_USE_SENDFILE,
				0 );
		}
	    else if ( strcasecmp( name, "USE_O_NOATIME" ) == 0 )
		{
		int	UseNoATime;
		UseNoATime = mmc_cfg_set_param(
				MMC_P_USE_O_NOATIME,
				1 );
		}
	    else if ( strcasecmp( name, "NO_O_NOATIME" ) == 0 )
		{
		int	NoNoATime;
		NoNoATime = mmc_cfg_set_param(
				MMC_P_USE_O_NOATIME,
				0 );
		}
	    else if ( strcasecmp( name, "MAX_FILE_SIZE_L0" ) == 0 )
		{
		int	MaxFileSizeL0;
		value_required( name, value );
		MaxFileSizeL0 = mmc_cfg_set_param(
				MMC_P_MAX_FILE_SIZE_L0,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "MAX_FILE_SIZE_L1" ) == 0 )
		{
		int	MaxFileSizeL1;
		value_required( name, value );
		MaxFileSizeL1 = mmc_cfg_set_param(
				MMC_P_MAX_FILE_SIZE_L1,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "MAX_FILE_SIZE_L2" ) == 0 )
		{
		int	MaxFileSizeL2;
		value_required( name, value );
		MaxFileSizeL2 = mmc_cfg_set_param(
				MMC_P_MAX_FILE_SIZE_L2,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "MAX_FILE_SIZE_L3" ) == 0 )
		{
		int	MaxFileSizeL3;
		value_required( name, value );
		MaxFileSizeL3 = mmc_cfg_set_param(
				MMC_P_MAX_FILE_SIZE_L3,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "MAX_FILE_SIZE_L4" ) == 0 )
		{
		int	MaxFileSizeL4;
		value_required( name, value );
		MaxFileSizeL4 = mmc_cfg_set_param(
				MMC_P_MAX_FILE_SIZE_L4,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "OCCASIONAL_MMC_TIME" ) == 0 )
		{
		value_required( name, value );
		OccasionalMmcTime = mmc_cfg_set_param(
				MMC_P_CLEANUP_TIME,
				atoi( value ) );
		}
	    else if ( strcasecmp( name, "IDLE_SEND_RESP_TIMELIMIT" ) == 0 )
		{
		int	IdleSendRespTimeLimit;
		value_required( name, value );
		IdleSendRespTimeLimit = atoi( value );
		if ( IdleSendRespTimeLimit < 2 )
		     IdleSendRespTimeLimit = 2;
		else
		if ( IdleSendRespTimeLimit > 300 )
		     IdleSendRespTimeLimit = 300;
		SecIdleSendRespTimeLimit = IdleSendRespTimeLimit;
		}
	    else if ( strcasecmp( name, "IDLE_KEEPALIVE_TIMELIMIT" ) == 0 )
		{
		int	IdleKeepAliveTimeLimit;
		value_required( name, value );
		IdleKeepAliveTimeLimit = atoi( value );
		if ( IdleKeepAliveTimeLimit < 1 )
		     IdleKeepAliveTimeLimit = 1;
		else
		if ( IdleKeepAliveTimeLimit > 300 )
		     IdleKeepAliveTimeLimit = 300;
		SecIdleKeepAliveTimeLimit = IdleKeepAliveTimeLimit;
		}
	    else if ( strcasecmp( name, "LOWM_KEEPALIVE_RQSLIMIT" ) == 0 )
		{
		int	iValue;
		value_required( name, value );
		iValue = atoi( value );
		if ( iValue < 0 )
		     iValue = 0;
		else
		if ( iValue > 32000 )
		     iValue = 32000;
		LoWmKeepAliveRqsLimit = iValue;
		}
	    else if ( strcasecmp( name, "HIWM_KEEPALIVE_RQSLIMIT" ) == 0 )
		{
		int	iValue;
		value_required( name, value );
		iValue = atoi( value );
		if ( iValue < 0 )
		     iValue = 0;
		else
		if ( iValue > 1000 )
		     iValue = 1000;
		HiWmKeepAliveRqsLimit = iValue;
		}
	    else if ( strcasecmp( name, "MAX_KEEPALIVE_FILE_SIZE" ) == 0 )
		{
		int	iValue;
		value_required( name, value );
		iValue = atoi( value );
		if ( iValue < 0 )
		     iValue = 0;
		else
		if ( iValue > 1073741824)
		     iValue = 1073741824;
		MaxKeepAliveFileSize = iValue;
		}
#ifdef USE_LAYOUT
	    /* we assume to find out at most one file */
	    /* per type (header / footer) */
	    else if ( strcasecmp( name, "layout_header" ) == 0 )
		{
		value_required( name, value );
		/* avoid memory leak when there are multiple layout_header= */
		if ( lheaderfile != NULL )
		    free( lheaderfile );
		if ( lheaderfile_map != NULL )
		    free( lheaderfile_map );
		lheaderfile = value;
		lheaderfile_len = 0;
		if ( ( lheaderfile_map = (char*) map_layoutfile(
				lheaderfile, &lheaderfile_len ) ) == NULL )
		    lheaderfile = NULL;
		else
		    lheaderfile = e_strdup( value );
		}
	    else if ( strcasecmp( name, "layout_footer" ) == 0 )
		{
		value_required( name, value );
		/* avoid memory leak when there are multiple layout_footer= */
		if ( lfooterfile != NULL )
		    free( lfooterfile );
		if ( lfooterfile_map != NULL )
		    free( lfooterfile_map );
		lfooterfile = value;
		lfooterfile_len = 0;
		if ( ( lfooterfile_map = (char*) map_layoutfile(
				lfooterfile, &lfooterfile_len ) ) == NULL )
		    lfooterfile = NULL;
		else
		    lfooterfile = e_strdup( value );
		}
#endif /* USE_LAYOUT */
	    else
		{
		(void) fprintf( stderr,
			"%s: unknown config option '%s' (line %d)\n",
			argv0, name, line_num );
		exit( 62 );
		}
	    }
	}

    (void) fclose( fp );
    }


static void
value_required( char* name, char* value )
    {
    if ( value == (char*) 0 )
	{
	(void) fprintf(
	    stderr, "%s: value required for %s option\n", argv0, name );
	exit( 63 );
	}
    }


static void
no_value_required( char* name, char* value )
    {
    if ( value != (char*) 0 )
	{
	(void) fprintf(
	    stderr, "%s: no value required for %s option\n",
	    argv0, name );
	exit( 64 );
	}
    }


static char*
e_strdup( char* oldstr )
    {
    char* newstr;

    newstr = strdup( oldstr );
    if ( newstr == (char*) 0 )
	{
	syslog( LOG_CRIT, "out of memory copying a string" );
	(void) fprintf( stderr, "%s: out of memory copying a string\n", argv0 );
	exit( 65 );
	}
    return newstr;
    }


static void
lookup_hostname( httpd_sockaddr* sa4P, size_t sa4_len, int* gotv4P, httpd_sockaddr* sa6P, size_t sa6_len, int* gotv6P )
    {
#if defined(HAVE_GETADDRINFO) && defined(HAVE_GAI_STRERROR)

    struct addrinfo hints;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv4;
    struct addrinfo* aiv6;
    int gaierr;
    char strport[32];

    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    /* we should use my_snprintf(),
    ** but port value has already been checked by caller
    ** thus no buffer overflow is possible (last famous words).
    */
    (void) sprintf( strport, "%d", port );
    if ( (gaierr = getaddrinfo( hostname, strport, &hints, &ai )) != 0 )
	{
	syslog(
	    LOG_CRIT, "getaddrinfo %.80s - %.80s",
	    hostname, gai_strerror( gaierr ) );
	(void) fprintf(
	    stderr, "%s: getaddrinfo %.80s - %.80s\n",
	    argv0, hostname, gai_strerror( gaierr ) );
	exit( 66 );
	}

    /* Find the first IPv4 and IPv6 entries. */
    aiv4 = (struct addrinfo*) 0;
    aiv6 = (struct addrinfo*) 0;
    for ( ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next )
	{
	switch ( ai2->ai_family )
	    {
	    case AF_INET:
	    if ( aiv4 == (struct addrinfo*) 0 )
		aiv4 = ai2;
	    break;
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
	    case AF_INET6:
	    if ( aiv6 == (struct addrinfo*) 0 )
		aiv6 = ai2;
	    break;
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
	    }
	}

    if ( aiv4 == (struct addrinfo*) 0 )
	*gotv4P = 0; 
    else
	{
	if ( sa4_len < aiv4->ai_addrlen )
	    {
	    syslog(
		LOG_CRIT, "%.80s - sockaddr too small (%d < %d)",
		hostname, sa4_len, aiv4->ai_addrlen );
	    exit( 67 );
	    }
	memset( sa4P, 0, sa4_len );
	memcpy( sa4P, aiv4->ai_addr, aiv4->ai_addrlen );
	*gotv4P = 1;
	}
    if ( aiv6 == (struct addrinfo*) 0 )
	*gotv6P = 0; 
    else
	{
	if ( sa6_len < aiv6->ai_addrlen )
	    {
	    syslog(
		LOG_CRIT, "%.80s - sockaddr too small (%d < %d)",
		hostname, sa6_len, aiv6->ai_addrlen );
	    exit( 68 );
	    }
	memset( sa6P, 0, sa6_len );
	memcpy( sa6P, aiv6->ai_addr, aiv6->ai_addrlen );
	*gotv6P = 1;
	}

    freeaddrinfo( ai );

#else /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */

    struct hostent* he;

    *gotv6P = 0;

    memset( sa4P, 0, sa4_len );
#ifdef notdef
    /* We don't really need to set sa_len. */
#ifdef HAVE_SA_LEN
    sa4P->sa_len = sa4_len;
#endif /* HAVE_SA_LEN */
#endif
    sa4P->sa.sa_family = AF_INET;
    if ( hostname == (char*) 0 )
	sa4P->sa_in.sin_addr.s_addr = htonl( INADDR_ANY );
    else
	{
	sa4P->sa_in.sin_addr.s_addr = inet_addr( hostname );
	if ( (int) sa4P->sa_in.sin_addr.s_addr == -1 )
	    {
	    he = gethostbyname( hostname );
	    if ( he == (struct hostent*) 0 )
		{
#ifdef HAVE_HSTRERROR
		syslog(
		    LOG_CRIT, "gethostbyname %.80s - %.80s",
		    hostname, hstrerror( h_errno ) );
		(void) fprintf(
		    stderr, "%s: gethostbyname %.80s - %.80s\n",
		    argv0, hostname, hstrerror( h_errno ) );
#else /* HAVE_HSTRERROR */
		syslog( LOG_CRIT, "gethostbyname %.80s failed", hostname );
		(void) fprintf(
		    stderr, "%s: gethostbyname %.80s failed\n",
			argv0, hostname );
#endif /* HAVE_HSTRERROR */
		exit( 69 );
		}
	    if ( he->h_addrtype != AF_INET )
		{
		syslog( LOG_CRIT, "%.80s - non-IP network address", hostname );
		(void) fprintf(
		    stderr, "%s: %s - non-IP network address\n",
		    argv0, hostname );
		exit( 70 );
		}
	    (void) memcpy(
		&sa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length );
	    }
	}
    sa4P->sa_in.sin_port = htons( port );
    *gotv4P = 1;

#endif /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */
    }


#ifdef EXECUTE_CGICLI
static void
read_cgiclifile( char* cgiclifile )
    {
    int status = 0;
    int len;
    int	numline = 0;
    FILE* fp;
    char buf[4096];
    char* cp;
    char clipattern[4096];
    char clipath[256];

    fp = fopen( cgiclifile, "r" );
    if ( fp == (FILE*) 0 )
	{
	syslog( LOG_CRIT, "%.80s - %m", cgiclifile );
	perror( cgiclifile );
	exit( 71 );
	}

    while ( fgets( buf, sizeof(buf), fp ) != (char*) 0 )
	{
	++numline;

	/* Nuke comments. */
	cp = strchr( buf, '#' );
	if ( cp != (char*) 0 )
	    *cp = '\0';

	/* Nuke trailing whitespace. */
	len = strlen( buf );
	while ( len > 0 &&
		( buf[len-1] == ' ' || buf[len-1] == '\t' ||
		  buf[len-1] == '\n' || buf[len-1] == '\r' ) )
	    buf[--len] = '\0';

	/* Ignore empty lines. */
	if ( len == 0 )
	    continue;

	/* Parse line. */
	if ( sscanf( buf, " %4000[^ \t] %255[^ \t]",
		clipattern, clipath ) != 2 )
	    {
	    syslog( LOG_CRIT,
		"unparsable line(%d) in %.80s - %.80s",
			numline, cgiclifile, buf );
	    (void) fprintf( stderr,
		"%s: unparsable line(%d) in %.80s - %.80s\n",
		argv0, numline, cgiclifile, buf );
	    continue;
	    }

	/* Nuke any leading slashes in pattern. */
	match_nuke_slashpat( clipattern );

	if ( cgicli_vrec == (httpd_cgicli_vrec*) 0 )
	    {
	    cgicli_vrec = httpd_alloc_cgicli_vrec();
	    if ( cgicli_vrec == (httpd_cgicli_vrec*) 0 )
		{
		syslog( LOG_CRIT, "httpd_alloc_cgicli_vrec: %m" );
		(void) fprintf(
		    stderr, "%s: httpd_alloc_cgicli_vrec: %s\n",
		    argv0, strerror( errno ) );
		exit( 72 );
		}
	    }
	if ( ( status = httpd_add_cgicli_entry(
		cgicli_vrec, clipattern, clipath ) ) != 0 )
	    {
	    char *pmsg = "";
	    switch( status )
		{
		case -1:
		    pmsg = "bad formal parameters";
		    break;
		case 99:
		    pmsg = "too many CGICLI entries";
		    break;
		case 100:
		    pmsg = "pattern already exists";
		    break;
		default:
		    pmsg = "allocation failed";
		    break;
		}
	    syslog( LOG_CRIT, "httpd_add_cgicli_entry: ERROR %d, line %d, %s",
			status, numline, pmsg );
	    (void) fprintf(
		    stderr, "%s: httpd_add_cgicli: ERROR %d, line %d, %s\n",
		    argv0, status, numline, pmsg );
	    exit( 72 );
	    }
	}
    (void) fclose( fp );
    }
#endif	/* EXECUTE_CGICLI */


static void
read_throttlefile( char* throttlefile, int* numthrottlesP )
    {
    int len;
    int numline = 0;
    FILE* fp;
    char buf[4096];
    char* cp;
    char pattern[4096];
    long limit;

    fp = fopen( throttlefile, "r" );
    if ( fp == (FILE*) 0 )
	{
	syslog( LOG_CRIT, "%.80s - %m", throttlefile );
	perror( throttlefile );
	exit( 71 );
	}

    while ( fgets( buf, sizeof(buf), fp ) != (char*) 0 )
	{
	++numline;

	/* Nuke comments. */
	cp = strchr( buf, '#' );
	if ( cp != (char*) 0 )
	    *cp = '\0';

	/* Nuke trailing whitespace. */
	len = strlen( buf );
	while ( len > 0 &&
		( buf[len-1] == ' ' || buf[len-1] == '\t' ||
		  buf[len-1] == '\n' || buf[len-1] == '\r' ) )
	    buf[--len] = '\0';

	/* Ignore empty lines. */
	if ( len == 0 )
	    continue;

	/* Parse line. */
	if ( sscanf( buf, " %4000[^ \t] %ld", pattern, &limit ) != 2 ||
	     limit <= 0 )
	    {
	    syslog( LOG_CRIT,
		"unparsable line(%d) in %.80s - %.80s",
		numline, throttlefile, buf );
	    (void) fprintf( stderr,
		"%s: unparsable line(%d) in %.80s - %.80s\n",
		argv0, numline, throttlefile, buf );
	    continue;
	    }

	if ( limit < MIN_THROTTLE_LIMIT )
	    {
	    syslog( LOG_WARNING,
		"highered limit %ld to %ld at line(%d) in %.80s - %.80s",
		limit, ( MIN_THROTTLE_LIMIT * 2 ), numline, throttlefile, buf );
	     limit = MIN( MIN_THROTTLE_LIMIT * 2, MAX_THROTTLE_LIMIT );
	    }
	else
	if ( limit > MAX_THROTTLE_LIMIT )
	    {
	    syslog( LOG_WARNING,
		"lowered limit %ld to %ld at line(%d) in %.80s - %.80s",
		limit, MAX_THROTTLE_LIMIT, numline, throttlefile, buf );
	     limit = MAX_THROTTLE_LIMIT;
	    }
	/* Nuke any leading slashes in pattern. */
	match_nuke_slashpat( pattern );

	/* Check for room in throttles. */
	if ( numthrottles >= maxthrottles )
	    {
	    if ( maxthrottles == 0 )
		{
		maxthrottles = 16;	/* arbitrary */
		throttles = NEW( throttletab, maxthrottles );
		}
	    else
		{
		maxthrottles *= 2;
		throttles = RENEW( throttles, throttletab, maxthrottles );
		}
	    if ( throttles == (throttletab*) 0 )
		{
		syslog( LOG_CRIT, "out of memory allocating a throttletab" );
		(void) fprintf(
		    stderr, "%s: out of memory allocating a throttletab\n",
		    argv0 );
		exit( 72 );
		}
	    }

	/* Add to table. */
	throttles[numthrottles].pattern = strdup( pattern );
	if ( throttles[numthrottles].pattern == (char*) 0 )
	    {
	    syslog( LOG_CRIT, "out of memory copying a throttle pattern" );
	    (void) fprintf(
		stderr, "%s: out of memory copying a throttle pattern\n",
		argv0 );
	    exit( 73 );
	    }
	throttles[numthrottles].limit = limit;
	throttles[numthrottles].rate = 0;
	throttles[numthrottles].bytes_since_avg = 0;
	throttles[numthrottles].num_sending = 0;

	++numthrottles;
	++(*numthrottlesP);
	}
    (void) fclose( fp );
    }


static void
shut_down( void )
    {
    int cnum = 0;
    struct timeval tv = { 0, 0 };

    if (in_shut_down != 0)
	return;

    in_shut_down = 1;

    (void) gettimeofday( &tv, (struct timezone*) 0 );
    logstats( &tv );

    if ( connects != (connecttab*) 0 )
	{
	for ( cnum = 0; cnum < maxconnects; ++cnum )
	    {
	    if ( connects[cnum].conn_state != CNST_FREE )
		{
		if ( connects[cnum].hc != (httpd_conn*) 0 )
		    {
		    /* no need to uncork (connection is going to be closed) */
		    httpd_complete_request( connects[cnum].hc, &tv, CR_DO_LOGIT );
		    httpd_close_conn( connects[cnum].hc, &tv );
		    }
		connects[cnum].conn_state = CNST_FREE;
		}

	    if ( connects[cnum].hc != (httpd_conn*) 0 )
		{
		httpd_destroy_conn( connects[cnum].hc );
		free( (void*) connects[cnum].hc );
		--httpd_conn_count;
		connects[cnum].hc = (httpd_conn*) 0;
		}
	    }

	if ( hs != (httpd_server*) 0 )
	    {
	    if ( hs->listen4_fd != -1 &&
		fdwatch_is_fd ( hs->listen4_fd ) )
		fdwatch_del_fd( hs->listen4_fd );
	    if ( hs->listen6_fd != -1 &&
		fdwatch_is_fd ( hs->listen6_fd ) )
		fdwatch_del_fd( hs->listen6_fd );
	    fdwatch_sync();
	    httpd_terminate( hs );
	    hs = (httpd_server*) 0;
	    }

	mmc_destroy();
	tmr_destroy();

	free( (void*) freeconnects );
	free( (void*) connects );

	freeconnects = (connecttab **) 0;
	connects     = (connecttab *) 0;
	}

    if ( throttles != (throttletab*) 0 )
	{
	free( (void*) throttles );
	throttles = (throttletab*) 0;
	}

    in_shut_down = 0;

    }


/*
** It's better to not call tmr_run() here.
*/
static int
handle_newconnect( struct timeval* tvP, int listen_fd )
    {
    int numconnects0 = numconnects;
    connecttab* c;

    /* This loops until the accept() fails, trying to start new
    ** connections as fast as possible so we don't overrun the
    ** listen queue.
    */
    for (;;)
	{
	/* Is there room in the connection table? */
	if ( numconnects >= maxconnects )
	    {
	    /* If at least one connection has been accepted,
	    ** then return without triggering overflow code.
	    */
	    if ( numconnects0 != numconnects )
		return 0;

	    /* Out of connection slots.
	    ** Disable FD, return, run the existing connections
	    ** then run the timers and maybe we'll free up a slot
	    ** by the time we get back here.
	    */

#ifndef SYSLOG_EACH_TOOMCONNS
	    /* remove server socket from watched fdset */
	    if ( fdwatch_is_fd( listen_fd ) )
		fdwatch_del_fd( listen_fd );

	    if ( ovfconnects == 0 )
		{
		++stats_ovfconnects;
#ifdef SYSLOG_BEGEND_TOOMCONNS
		syslog( LOG_WARNING, "BEGIN of TOO MANY CONNECTIONS (%d) !",
			numconnects );
#else
		syslog( LOG_WARNING, "TOO MANY CONNECTIONS (%d) !",
			numconnects );
#endif /* SYSLOG_BEGEND_TOOMCONNS */
		}
	    ++ovfconnects;
#else
	    ++stats_ovfconnects;
	    syslog( LOG_WARNING, "too many connections (%d) !",
			numconnects );
#endif	/* SYSLOG_EACH_TOOMCONNS */
	    return 0;
	    }

	if ( numfreeconnects <= 0 )
	    {
	    syslog( LOG_CRIT,
		"numconnects %d, numfreeconnects %d <= 0",
		numconnects, numfreeconnects );
	    exit( 74 );
	    }

	/* Find a free connection entry. */
	c = freeconnects[--numfreeconnects];

	if ( c == (connecttab*) 0 || c->conn_state != CNST_FREE )
	    {
	    syslog( LOG_CRIT,
		"numconnects %d, numfreeconnects %d, conn_state %d != FREE",
		numconnects, numfreeconnects,
		( ( c == (connecttab*) 0 ) ? -1 : c->conn_state ) );
	    exit( 75 );
	    }

	/* Make the httpd_conn if necessary. */
	if ( c->hc == (httpd_conn*) 0 )
	    {
	    c->hc = CNEW( httpd_conn, 1 );
	    if ( c->hc == (httpd_conn*) 0 )
		{
		syslog( LOG_CRIT, "out of memory allocating an httpd_conn" );
		exit( 76 );
		}
	    c->hc->initialized = 0;
	    ++httpd_conn_count;
	    }

	/* Get the connection. */
	switch ( httpd_get_conn( hs, listen_fd, c->hc ) )
	    {
	    case GC_OK:
		break;
	    case GC_NO_MORE:
		++numfreeconnects;
		return 1;
	    case GC_ABORT:
		++numfreeconnects;
		++stats_connaborted;
		return 0;
	    case GC_FAIL:
	    default:
		++numfreeconnects;
		return 0;
	    }

	++numconnects;

	c->conn_state = CNST_READING;

	c->numtnums = 0;
	c->tnums[0] = -1;
	c->keep_alive = 0;
	c->pipelining = 0;
	c->iotimeout_at = tvP->tv_sec + IDLE_READ_TIMELIMIT;
	c->wakeup_timer = (Timer*) 0;
	c->linger_timer = (Timer*) 0;
	c->bytes_throttled = 0;
	c->bytes_to_send = 0;
	c->bytes_sent = 0;
#ifdef USE_LAYOUT
	c->hc->layout = 0;
	c->hc->lheaderfile_len = 0;
	c->hc->lfooterfile_len = 0;
#endif /* USE_LAYOUT */

#ifndef INHERIT_FD_NONBLOCK_AA
	/*
	** Set accepted socket to non-blocking mode.
	** NOTE: in some kernels no-delay / no-block mode might be inherited
	**       from listen socket, thus, in theory in such a case,
	**       there is no need to reset it after each accept.
	*/
#ifdef TEST_INHERIT_FD_NONBLOCK
	/*
	** NOTE: define TEST_INHERIT_FD_NONBLOCK to discover/log
	**       if accepted socket inherits non-blocking mode,
	**       then don't forget to UNDEFINE it as soon as possible.
	*/
	{
	int	flg_on = -1;
	flg_on = -1;
	if (httpd_get_nonblock( c->hc->conn_fd, &flg_on ) < 0 )
	    {
		syslog( LOG_CRIT, "httpd_get_nonblock: fcntl - %m" );
	    }
	if ( flg_on != SOPT_ON )
	    {
		syslog( LOG_NOTICE, "accepted socket in BLOCKING mode %d",
			flg_on );
		(void) httpd_set_nonblock( c->hc->conn_fd, ON );
	    }
	}
#else
	/* Set non-blocking mode. */
	(void) httpd_set_nonblock( c->hc->conn_fd, SOPT_ON );

#endif	/* TEST_INHERIT_FD_NONBLOCK */

#endif /* !INHERIT_FD_NONBLOCK_AA */

	fdwatch_add_fd( c->hc->conn_fd, c, FDW_READ );

	++stats_connections;
	if ( numconnects > stats_simultaneous )
	    stats_simultaneous = numconnects;

	} /* END for */
	/* NOTREACHED */
    }


static void
handle_buf_read( connecttab* c, struct timeval* tvP )
    {
    int status;
    httpd_conn* hc = c->hc;
    char* pszErr = "";

    /* Do we have a complete request yet? */
    status = httpd_got_request( hc );

    switch ( status )
	{
	case GR_NO_REQUEST:
	    return;
	case GR_GOT_REQUEST:
	    /* OK, got request */
	    ++stats_requests;
	    break;
	case GR_BAD_REQUEST_CRLF:
	    pszErr = " Too many extra CRLFs between two HTTP requests.";
	    /* fall down */
	case GR_BAD_REQUEST:
	default:
	    /* Default is to linger */
	    if ( status != GR_BAD_REQUEST_CRLF2 )
		{
		httpd_send_err( hc, 400, httpd_err_title(400),
			httpd_err_titlelen(400), "",
			httpd_err_form(400), pszErr );
		}
	    resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	    return;
	}

    /* Yes.  Try parsing and resolving it. */
    if ( httpd_parse_request( hc ) < 0 )
	{
	resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}

    /* Check the throttle table (but only if this is a GET or a POST method) */
    if ( ! check_throttles( c ) )
	{
	char* err503form = (char*) 0;
	/* if load is getting high then don't reply with a body
	** (only HTTP headers), many browsers know what to display anyway.
	*/
	if ( numconnects <= hiwmconnects1 )
	    err503form = httpd_err_form(503);
	httpd_send_err(
	    hc, 503, httpd_err_title(503),
		httpd_err_titlelen(503), "",
		err503form, hc->encodedurl );
	resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}

    /* If there are too many connections or there are no more
    ** buffered requests, then figure if connection should be closed
    ** after this reply.  NOTE: c->keep_alive is set only after first reply.
    */
    if ( hc->do_keep_alive &&
	(  c->keep_alive >= LoWmKeepAliveRqsLimit ||
	 ( hc->checked_idx + 4 >= c->hc->read_idx )
	) )
	{
	if ( numconnects < hiwmconnects1 )
	    {
	    if ( c->keep_alive >= LoWmKeepAliveRqsLimit )
		hc->do_keep_alive = 0;
	    }
	else
	    {
	    if ( numconnects >= hiwmconnects2 ||
		c->keep_alive >= HiWmKeepAliveRqsLimit )
		hc->do_keep_alive = 0;
	    }
	}

    /* Start the connection going. */
    if ( httpd_start_request( hc, tvP, numconnects, maxconnects,
					MaxKeepAliveFileSize ) < 0 )
	{
	/* Something went wrong.  Close down the connection. */
	resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}

    /* Fill in bytes_to_send. */
#ifdef USE_LAYOUT
    if ( hc->layout && hc->got_range )
	{
	/* we assume that the following conditions have already been checked */
	/*    1) init_byte_loc   <= end_byte_loc */
	/*    2) lheaderfile_len <= end_byte_loc */
	/*    3) end_byte_loc    < lheaderfile_len + bytes_to_send */
	/*    4) bytes_to_send   > 0 (if bytes_to_send < 1 then no layout) */
	/* NOTE: send_mime() has already been called so we cannot change */
	/*       init_byte_loc and end_byte_loc here, they must be right ! */

	if ( hc->end_byte_loc < hc->lheaderfile_len + hc->bytes_to_send )
	    {
	    hc->lfooterfile_len = 0;
	    c->bytes_to_send = hc->end_byte_loc + 1 - hc->lheaderfile_len;
	    }
	else
	    c->bytes_to_send = hc->bytes_to_send;

	if ( hc->init_byte_loc < hc->lheaderfile_len )
	    /* c->bytes_sent == 0 */
	    hc->lheaderfile_len -= hc->init_byte_loc;
	else
	    { /* hc->lheaderfile_len = 0 is setted later */
	    if ( hc->init_byte_loc < hc->lheaderfile_len + hc->bytes_to_send )
		c->bytes_sent = hc->init_byte_loc - hc->lheaderfile_len;
	    else
		{
		c->bytes_sent = hc->bytes_to_send;
		hc->lfooterfile_len -= ( hc->init_byte_loc -
			( hc->lheaderfile_len + hc->bytes_to_send ) );
		}
	    hc->lheaderfile_len = 0;
	    }
	}
    else
#endif /* USE_LAYOUT */
    if ( hc->got_range )
	{
	c->bytes_sent = hc->init_byte_loc;
	c->bytes_to_send = hc->end_byte_loc + 1;
	}
    else
	c->bytes_to_send = hc->bytes_to_send;

    /* Check if there are file contents to send. */
    if ( hc->file_address == (char*) 0 && hc->file_fd == EOF )
	{
	/* No file address / fd means someone else is handling it
	** (and this guy has already set do_keep_alive = 0)
	** or that there is no GET 200 + file body to send
	** (i.e. GET 304, HEAD, etc.)
	*/
	resp_clear_connection( c, tvP, DO_KEEP_ALIVE );
	return;
	}
#ifndef USE_LAYOUT
    if ( c->bytes_sent >= c->bytes_to_send )
#else  /* USE_LAYOUT */
    if ( c->bytes_sent >= c->bytes_to_send &&
	 hc->lheaderfile_len == 0 &&
	 hc->lfooterfile_len == 0 )
#endif /* USE_LAYOUT */
	{
	/* There's no body to send (zero sized file) */
	resp_clear_connection( c, tvP, DO_KEEP_ALIVE );
	return;
	}

    /* Cool, we have a valid request and a file to send. */
    c->conn_state = CNST_SENDING;
    c->throttled_at = tvP->tv_sec;
    c->iotimeout_at = tvP->tv_sec + IDLE_SEND_TIMELIMIT;
    c->wouldblock_delay = 0;
    c->bytes_throttled = 0;

    fdwatch_mod_fd( hc->conn_fd, c, FDW_WRITE );

    /* Set cork mode */
    if ( hc->file_fd != EOF && numthrottles == 0 )
	(void) httpd_set_cork( hc->conn_fd, SOPT_ON );

    /* don't call handle_send here ! */
    }

#ifdef EXECUTE_CGI
#define MAX_RQS_LEN	5632		/* max. URI length around 4-5 KB */
#else
#define MAX_RQS_LEN	(1536 * 3)	/* shorter length (no CGI, referrer) */
#endif

static void
handle_read( connecttab* c, struct timeval* tvP )
    {
    int sz;
    httpd_conn* hc = c->hc;

    /* Is there room in our buffer to read more bytes? */
    if ( hc->read_idx >= hc->read_size )
	{
	if ( hc->read_size >= MAX_RQS_LEN )
	    {
	    httpd_send_err( hc, 413, httpd_err_title(413),
				httpd_err_titlelen(413), "",
				httpd_err_form(413), "" );
	    /* Default is to linger, but try to discard input early too */
	    (void) read_linger( c, tvP );
	    resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	    return;
	    }
	/* NOTE: we want to double initial size (1536),
	**       thus we keep the increment small enough to allow that.
	*/
	httpd_realloc_str(
	    &hc->read_buf, &hc->read_size, hc->read_size + 1000 );
	}

    /* Read some more bytes. */
    sz = read(
	hc->conn_fd, &(hc->read_buf[hc->read_idx]),
	hc->read_size - hc->read_idx );
    if ( sz == 0 )
	{
	/* EOF */
	hc->should_linger = 0;
	if ( !c->keep_alive && hc->read_idx > 0 )
	    /* try to complain about EOF only on first partial request */
	    httpd_send_err(
		hc, 400, httpd_err_title(400),
			httpd_err_titlelen(400), "",
			httpd_err_form(400), "" );
	resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}
    if ( sz < 0 )
	{
	/* Ignore EINTR, EAGAIN and EWOULDBLOCK errors.
	** At first glance you would think that connections
	** returned by fdwatch as readable should never give an
	** EWOULDBLOCK; however, this apparently can happen if a packet gets
	** garbled.
	*/
	if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK )
	    return;
	if ( errno == EPIPE )
	    { /* No need to linger */
	    hc->should_linger = 0;
	    }
	else
	    {
	    /* we have to linger in order to read unread input */
	    httpd_send_err(
		hc, 400, httpd_err_title(400),
			httpd_err_titlelen(400), "",
			httpd_err_form(400), "" );
	    }
	resp_clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}
    hc->read_idx += sz;

    /* terminate EOB (End Of Buffer) */
    hc->read_buf[ hc->read_idx ] = '\0';

    /*
    ** if we start getting new subsequent requests on this socket
    ** then adjust read timeout (we do this only once per request).
    */
    if ( c->hc->keep_alive_tmo )
	{
	c->iotimeout_at = tvP->tv_sec + c->hc->keep_alive_tmo;
	/* stop resetting timer interval while we are reading client request */
    	c->hc->keep_alive_tmo = 0;
	}

    handle_buf_read( c, tvP );
    }


static void
handle_send( connecttab* c, struct timeval* tvP )
    {
    int i, sz = 0;
    int max_bytes;
    int bytes_to_write = 0;
    ClientData client_data;
    httpd_conn* hc = c->hc;
#ifdef USE_LAYOUT
    int iovidx = 0;
    struct iovec iv[5];
#endif

    /* Are we done?  We don't check for headers because here */
    /* we always send non empty files. */
#ifndef USE_LAYOUT
    if ( c->bytes_sent >= c->bytes_to_send )
#else
    if ( c->bytes_sent >= c->bytes_to_send &&
	( hc->layout == 0 ||
	( hc->lheaderfile_len == 0 && hc->lfooterfile_len == 0 ) ) )
#endif /* USE_LAYOUT */
	{
	/* This reply is over and socket send buffer should be almost empty.
	** Now we can safely start reading next HTTP/1.1 request without
	** fears about timing out too early, see below similar check condition.
	*/
	clear_connection( c, tvP, DO_KEEP_ALIVE );
	return;
	}

    max_bytes = (int) ( c->limit / 2 );

#ifndef USE_LAYOUT

    /* Do we need to write the headers first? */
    if ( hc->responselen <= 0 )
	{
	/* No, just write the file. */
	bytes_to_write = (int)
		MIN( c->bytes_to_send - c->bytes_sent, max_bytes );
	if ( hc->file_fd != EOF )
	    sz = httpd_sendfile( hc->conn_fd, hc->file_fd, c->bytes_sent,
		bytes_to_write );
	else
	    sz = write( hc->conn_fd, &(hc->file_address[c->bytes_sent]),
		bytes_to_write );
	}
    else
	{
	/* Yes.  We'll combine headers and file into a single writev(),
	** hoping that this generates a single packet.
	*/
	if ( hc->file_fd != EOF )
	    {
	    /* send header (always in RAM) */
	    sz = write( hc->conn_fd, hc->response, hc->responselen );

	    if ( sz == hc->responselen &&
		 c->bytes_sent < c->bytes_to_send )
		{ /* we have just written all headers and there is */
		  /* something else to send, so try to send it */
		int sz2;
		bytes_to_write = (int)
			MIN( c->bytes_to_send - c->bytes_sent, max_bytes );
		sz2 = httpd_sendfile( hc->conn_fd, hc->file_fd, c->bytes_sent,
			bytes_to_write );
		if ( sz2 > 0 )
		    sz += sz2;
		/* otherwise ignore I/O errors */
		}
	    }
	else
	    {
	    struct iovec iv[2];

	    iv[0].iov_base = hc->response;
	    iv[0].iov_len = (size_t) hc->responselen;
	    iv[1].iov_base = &(hc->file_address[c->bytes_sent]);
	    iv[1].iov_len = (size_t)
		MIN( c->bytes_to_send - c->bytes_sent, max_bytes );
	    sz = writev( hc->conn_fd, iv, 2 );
	    }
	}
#else
    /* USE_LAYOUT */

    /*
    ** we don't deploy sendfilev() (available in Solaris 8/9) capabilities,
    ** so we have to do some dirty "hack" when we use httpd_sendfile()
    */

    if ( hc->file_fd != EOF )
	{
	int hdrlen = 0;

	/* Do we have header bytes to send ? */
	if ( hc->responselen > 0 )
	    {
	    iv[iovidx].iov_base = hc->response;
	    iv[iovidx++].iov_len = (size_t) hc->responselen;
	    hdrlen += hc->responselen;
	    }

	/* Do we have layout header bytes to send ? */
	if ( hc->layout && hc->lheaderfile_len > 0 )
	    {
	    iv[iovidx].iov_base = lheaderfile_map +
				( lheaderfile_len - hc->lheaderfile_len );
	    iv[iovidx++].iov_len = (size_t) hc->lheaderfile_len;
	    hdrlen += hc->lheaderfile_len;
	    }

	/* if needed then write headers */
	if ( iovidx > 0 )
	    sz = writev( hc->conn_fd, iv, iovidx );

	/* if headers have been completely sent then send file content */
	if ( sz == hdrlen && c->bytes_sent < c->bytes_to_send )
	    {
	    int sz2;
	    bytes_to_write = (int)
		MIN( c->bytes_to_send - c->bytes_sent, max_bytes );
	    sz2 = httpd_sendfile( hc->conn_fd, hc->file_fd, c->bytes_sent,
		bytes_to_write );
	    if ( hdrlen > 0 )
		{
		if ( sz2 > 0 )
		    /* OK, we successfully sent */
		    /* some file content after headers */
		    sz += sz2;
		else
		    /* otherwise ignore I/O errors */
		    bytes_to_write = 0;
		}
	    else
		/* headers were sent in previous calls */
		sz = sz2;
	    }
	else
	/* Do we have layout footer bytes to send ? */
	if ( c->bytes_sent >= c->bytes_to_send &&
	     hdrlen == 0 && hc->layout && hc->lfooterfile_len > 0)
	    {
	    sz = write( hc->conn_fd,
		lfooterfile_map + ( lfooterfile_len - hc->lfooterfile_len ),
		hc->lfooterfile_len );
	    }
	}
    else
	{
	/* Do we have header bytes to send ? */
	if ( hc->responselen > 0 )
	    {
	    iv[iovidx].iov_base = hc->response;
	    iv[iovidx++].iov_len = (size_t) hc->responselen;
	    }

	/* Do we have layout header bytes to send ? */
	if ( hc->layout && hc->lheaderfile_len > 0 )
	    {
	    iv[iovidx].iov_base = lheaderfile_map +
				( lheaderfile_len - hc->lheaderfile_len );
	    iv[iovidx++].iov_len = (size_t) hc->lheaderfile_len;
	    }

	/* Do we have file content bytes to send ? */
	if ( c->bytes_sent < c->bytes_to_send )
	    {
	    bytes_to_write = (int)
		MIN( c->bytes_to_send - c->bytes_sent, max_bytes );
	    iv[iovidx].iov_base = &(hc->file_address[c->bytes_sent]);
	    iv[iovidx++].iov_len = (size_t) bytes_to_write;
	    }

	/* Do we have layout footer bytes to send ? */
	if ( hc->layout && hc->lfooterfile_len > 0)
	    {
	    iv[iovidx].iov_base = lfooterfile_map +
				( lfooterfile_len - hc->lfooterfile_len );
	    iv[iovidx++].iov_len = (size_t) hc->lfooterfile_len;
	    }

	/* Do we need a single write ? */
	if ( iovidx == 1 )
	    /* Yes, then use write */
	    sz = write( hc->conn_fd, iv[0].iov_base, iv[0].iov_len );
	else 
	    /* No.  We'll combine headers, layout and file into
	    ** a single writev(), hoping that this generates a single packet.
	    */
	    sz = writev( hc->conn_fd, iv, iovidx );
	}

#endif /* USE_LAYOUT */

    if ( sz == 0 ||
	 ( sz < 0 && ( errno == EWOULDBLOCK || errno == EAGAIN ) ) )
	{
	/* This shouldn't happen, but some kernels, e.g.
	** SunOS 4.1.x, are broken and select() says that
	** O_NDELAY sockets are always writable even when
	** they're actually not.
	**
	** Current workaround is to block sending on this
	** socket for a brief adaptively-tuned period.
	** Fortunately we already have all the necessary
	** blocking code, for use with throttling.
	*/
	fdwatch_del_fd( hc->conn_fd );

	c->conn_state = CNST_PAUSING;
	c->iotimeout_at = tvP->tv_sec + IDLE_SEND_TIMELIMIT;
	c->wouldblock_delay += MIN_WOULDBLOCK_DELAY;

	client_data.p = c;
	c->wakeup_timer = tmr_create(
	    tvP, wakeup_connection, client_data, c->wouldblock_delay,
		TMR_ONE_SHOT );
	if ( c->wakeup_timer == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(wakeup_connection) failed" );
	    exit( 78 );
	    }
	return;
	}
    if ( sz < 0 )
	{
	/* ignore EINTR (retry later) */
	if ( errno == EINTR )
	    return;

	/* Something went wrong, close this connection.
	**
	** If it's just an EPIPE, don't bother logging, that
	** just means the client hung up on us.
	**
	** On some systems, write() occasionally gives an EINVAL.
	** Dunno why, something to do with the socket going
	** bad.  Anyway, we don't log those either.
	**
	** And ECONNRESET and ENOTCONN aren't interesting either.
	*/
	if ( errno != EPIPE && errno != EINVAL && errno != ECONNRESET
#ifdef ENOTCONN
	  && errno != ENOTCONN
#endif
	   )
	    syslog( LOG_ERR, "write - %m sending %.80s", hc->encodedurl );
	clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}

    /* Ok, we wrote something ( sz > 0 ) */
    c->iotimeout_at = tvP->tv_sec + IDLE_SEND_TIMELIMIT;

    /* Was this a headers + file writev()? */
    if ( hc->responselen > 0 )
	{
	/* Yes; did we write only part of the headers? */
	if ( sz < hc->responselen )
	    {
	    /* Yes; move the unwritten part to the front of the buffer. */
	    hc->responselen -= sz;
	    (void)memmove( hc->response, &(hc->response[sz]), hc->responselen );
	    stats_resp_bytes += sz;
	    sz = 0;
	    }
	else
	    {
	    /* Nope, we wrote the full headers, so adjust accordingly. */
	    stats_resp_bytes += hc->responselen;
	    sz -= hc->responselen;
	    hc->responselen = 0;
	    }
	}

    stats_body_bytes += sz;

#ifndef USE_LAYOUT
    /* And update how much of the file we wrote. */
    c->bytes_throttled += sz;
    c->bytes_sent  += sz;
    c->hc->bytes_sent += sz;
    for ( i = 0; i < c->numtnums; ++i )
	throttles[c->tnums[i]].bytes_since_avg += sz;
#else
    /* USE_LAYOUT */

    if ( hc->layout && hc->lheaderfile_len > 0 )
	/* was this a layout header write too ? */
	if ( sz < hc->lheaderfile_len )
	    {	/* did we finish writing it ? */
	    hc->lheaderfile_len -= sz;
	    sz = 0;
	    }
	else
	    {
	    sz -= hc->lheaderfile_len;
	    hc->lheaderfile_len = 0;
	    }

    if ( sz > 0 && c->bytes_sent < c->bytes_to_send )
	/* Have we written some file content ? */
	if ( sz < bytes_to_write )
	    {	/* update how much of the file we wrote. */
	    c->bytes_throttled += sz;
	    c->bytes_sent += sz;
	    c->hc->bytes_sent += sz;
	    for ( i = 0; i < c->numtnums; ++i )
		throttles[c->tnums[i]].bytes_since_avg += sz;
	    sz = 0;
	    }
	else
	    {
	    sz -= bytes_to_write;
	    c->bytes_throttled += bytes_to_write;
	    c->bytes_sent += bytes_to_write;
	    c->hc->bytes_sent += bytes_to_write;
	    for ( i = 0; i < c->numtnums; ++i )
		throttles[c->tnums[i]].bytes_since_avg += bytes_to_write;
	    }

    if ( sz > 0 && hc->layout && hc->lfooterfile_len > 0 )
	/* was this a layout footer write too ? */
	if ( sz < hc->lfooterfile_len )
	    {	/* did we finish writing it ? */
	    hc->lfooterfile_len -= sz;
	    sz = 0;
	    }
	else
	    {
	    sz -= hc->lfooterfile_len;
	    hc->lfooterfile_len = 0;
	    }
#endif /* USE_LAYOUT */
    /*
    ** Have we written everything ?
    ** We don't check for headers because
    ** we always send non empty files.
    */
#ifndef USE_LAYOUT
    if ( c->bytes_sent >= c->bytes_to_send )
#else
    if ( c->bytes_sent >= c->bytes_to_send &&
	( hc->layout == 0 || hc->lfooterfile_len == 0 ) )
#endif /* USE_LAYOUT */
	{
	/* This reply is over,
	** if we don't do keep-alive or we do it and there is
	** at least a partial HTTP/1.1 pipelined request
	** then we clear connection here.
	*/
	if ( c->hc->do_keep_alive == 0 ||
	   (c->pipelining == 0 && c->hc->bytes_sent < 8192) ||
	    httpd_is_next_request( c->hc ) )
	    {
	    clear_connection( c, tvP, DO_KEEP_ALIVE );
	    }
	/* else
	** we wait for next event of send socket buffer empty
	** and then we clear the request connection,
	** see above at the beginning of this function.
	*/
	return;
	}

    /* Tune the (blockheaded) wouldblock delay. */
    if ( c->wouldblock_delay > MIN_WOULDBLOCK_DELAY )
	c->wouldblock_delay -= MIN_WOULDBLOCK_DELAY;

    /* If we're throttling, check if we're sending too fast. */
    if ( c->limit != THROTTLE_NOLIMIT )
	{
	long coast = 0;
	time_t elapsed = tvP->tv_sec - c->throttled_at;

	if ( elapsed == 0 )
	     elapsed++;

	if ( c->bytes_throttled / elapsed > c->limit )
	    {
	    c->conn_state = CNST_PAUSING;
	    fdwatch_del_fd( hc->conn_fd );
	    /* When should we send the next c->limit bytes
	    ** to get back on schedule?  If less than a second
	    ** (integer math rounding), use 1/2 second.
	    */
	    coast = (long) ( c->bytes_throttled / c->limit - elapsed );
	    if ( coast < 1 )
		coast = 500L;
	    else
		coast = 1000L;
	    client_data.p = c;
	    c->wakeup_timer = tmr_create(
		tvP, wakeup_connection, client_data, coast, TMR_ONE_SHOT );
	    if ( c->wakeup_timer == (Timer*) 0 )
		{
		syslog( LOG_CRIT, "tmr_create(wakeup_connection) failed" );
		exit( 79 );
		}
	    }
	}
    }


/*
** MANDATORY: before returning we must call clear_connection() or
**            we must set c->conn_state + set new watch event for this fd.
*/
static void
handle_send_resp( connecttab* c, struct timeval* tvP )
    {
    int sz;
    httpd_conn* hc = c->hc;

    /* Do we need to write the headers ?
    ** NOTE: here we never send other optional header and footer content.
    */
    if ( hc->responselen < 1 )
	{
	/* No, just clear connection */
	clear_connection( c, tvP, hc->do_keep_alive );
	return;
	}

    /* write, retry immediately on EINTR */
    do
	{
	sz = write( hc->conn_fd, hc->response, hc->responselen );
	}
    while( sz == -1 && errno == EINTR );

    if ( sz == 0 ||
	 ( sz < 0 && ( errno == EWOULDBLOCK || errno == EAGAIN ) ) )
	{
	/* This shouldn't happen, but some kernels, e.g.
	** SunOS 4.1.x, are broken and select() says that
	** O_NDELAY sockets are always writable even when
	** they're actually not.
	**
	** Current workaround is to block sending on this
	** socket for a brief adaptively-tuned period.
	** Fortunately we already have all the necessary
	** blocking code, for use with throttling.
	*/
	ClientData client_data;

	fdwatch_del_fd( hc->conn_fd );

	c->conn_state = CNST_PAUSING;
	c->wouldblock_delay += MIN_WOULDBLOCK_DELAY;

	client_data.p = c;
	c->wakeup_timer = tmr_create(
	    tvP, wakeup_resp_connection, client_data, c->wouldblock_delay,
		TMR_ONE_SHOT );
	if ( c->wakeup_timer == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(wakeup_resp_connection) failed" );
	    exit( 78 );
	    }
	return;
	}
    if ( sz < 0 )
	{
	/* Something went wrong, close this connection.
	**
	** If it's just an EPIPE, don't bother logging, that
	** just means the client hung up on us.
	**
	** On some systems, write() occasionally gives an EINVAL.
	** Dunno why, something to do with the socket going
	** bad.  Anyway, we don't log those either.
	**
	** And ECONNRESET and ENOTCONN aren't interesting either.
	*/
	if ( errno != EPIPE && errno != EINVAL && errno != ECONNRESET
#ifdef ENOTCONN
	  && errno != ENOTCONN
#endif
	   )
	    syslog( LOG_ERR, "write - %m sending resp. %.80s", hc->encodedurl );
	clear_connection( c, tvP, NO_KEEP_ALIVE );
	return;
	}

    /* Ok, we wrote something. */
    stats_resp_bytes += sz;

    if ( sz < hc->responselen )
	{
	/* Very rare condition */

	/* Partial write, move the unwritten part to the front of the buffer */
	hc->responselen -= sz;
	(void) memmove( hc->response, &(hc->response[sz]), hc->responselen );

	/* Tune the (blockheaded) wouldblock delay. */
	if ( c->wouldblock_delay  > MIN_WOULDBLOCK_DELAY )
	     c->wouldblock_delay -= MIN_WOULDBLOCK_DELAY;

	c->iotimeout_at = tvP->tv_sec + SecIdleSendRespTimeLimit;
	if ( c->conn_state != CNST_SENDING_RESP )
	    {
	    /* We have not been called from main loop, change state */
	    c->conn_state = CNST_SENDING_RESP;

	    /* Set new watch event */
	    fdwatch_mod_fd( c->hc->conn_fd, c, FDW_WRITE );

	    /* ... and retry later in main loop */
	    }
	}
    else
	{
	/* OK, we wrote the full headers, so adjust accordingly */
	hc->responselen = 0;
	c->iotimeout_at = tvP->tv_sec + SecIdleSendRespTimeLimit;
	clear_connection( c, tvP, hc->do_keep_alive );
	}

    }


static int
read_linger( connecttab* c, struct timeval* tvP )
    {
    static char buf[4096];
    int i = 4;
    int r = 0;

    /* In lingering-close mode we just read and ignore bytes.  An error
    ** or EOF ends things, otherwise we go until a timeout.
    */
    do
	{
	r = read( c->hc->conn_fd, buf, sizeof(buf) );
	}
    while( ( r == -1 && errno == EINTR ) || ( r == sizeof(buf) && --i ) );

    if ( r == 0 || ( r == -1 && errno == EPIPE ) )
	c->hc->should_linger = 0;

    return r;
    }


static void
handle_linger( connecttab* c, struct timeval* tvP )
    {
    /* In lingering-close mode we just read and ignore bytes.  An error
    ** or EOF ends things, otherwise we go until a timeout.
    */
    if ( read_linger( c, tvP ) <= 0 )
	really_clear_connection( c, tvP );
    }


static int 
in_check_throttles( connecttab* c, int tnum )
    {
    long l;

    /* If we're way over the limit, don't even start. */
    if ( throttles[tnum].rate > throttles[tnum].limit * 2 )
	return 0;
    if ( throttles[tnum].num_sending < 0 )
	{
	syslog( LOG_ERR,
		"throttle sending count (%d) was negative - shouldn't happen!",
		throttles[tnum].num_sending );
	throttles[tnum].num_sending = 0;
	}
    l = throttles[tnum].limit / ( throttles[tnum].num_sending + 1 );
    /* if we're below minimum limit, don't even start */
    if ( l < MIN_THROTTLE_LIMIT &&
	 l < throttles[tnum].limit )
	return 0;

    /* slow start */
    l /= 4;
    if ( c->limit > l )
	 c->limit = l;

    ++throttles[tnum].num_sending;
    c->tnums[c->numtnums++] = tnum;

    return 1;
    }


static int
check_throttles( connecttab* c )
    {
    int tnum;

    c->numtnums = 0;
    c->limit = MaxConnBytesLimit;	/* it was THROTTLE_NOLIMIT */

#ifdef USE_IPTHROTTLE

    tnum = c->tnums[0];
    if ( tnum != -1 ) /* keep alive */
	{
	if ( in_check_throttles( c, tnum ) == 0 )
	    return 0;
	}
    else
    if ( c->hc->client_addr.sa.sa_family == AF_INET )
	{
	tnum = searchinsubnets( c->hc->client_addr.sa_in.sin_addr );
	if ( tnum != -1 )
	    if ( in_check_throttles( c, tnum ) == 0 )
		return 0;
	}

#endif /* USE_IPTHROTTLE */

    for ( tnum = 0; tnum < numurithrottles && c->numtnums < MAXTHROTTLENUMS;
	++tnum )
	if ( match( throttles[tnum].pattern, c->hc->expnfilename ) )
	    if ( in_check_throttles( c, tnum ) == 0 )
		return 0;

    return 1;
    }


static void
clear_throttles( connecttab* c, struct timeval* tvP )
    {
    int i;

    if ( c->numtnums == 0 )
	return;

    for ( i = 0; i < c->numtnums; ++i )
	--throttles[c->tnums[i]].num_sending;

#ifdef USE_IPTHROTTLE
    if ( c->tnums[0] < numurithrottles ) /* keep alive for ipthrottles */
	c->tnums[0] = -1; 
#endif /* USE_IPTHROTTLE */

    /* we are done, set counter to zero */
    c->numtnums = 0;
    }


static void
update_throttles( ClientData client_data, struct timeval* nowP )
    {
    int tnum;
    int i, cnum;
    connecttab* c;
    long l1, l2;

    for ( tnum = 0; tnum < numthrottles; ++tnum )
	{
	throttles[tnum].rate =
	    ( 2 * throttles[tnum].rate +
	      throttles[tnum].bytes_since_avg / THROTTLE_TIME ) / 3;
	throttles[tnum].bytes_since_avg = 0;
	/* Log a warning message if necessary. */
	if ( throttles[tnum].rate > throttles[tnum].limit &&
	     throttles[tnum].num_sending > 0 )
	    {
	    if ( throttles[tnum].rate > throttles[tnum].limit * 2 )
		syslog( LOG_NOTICE, "throttle #%d '%.80s' rate %ld GREATLY exceeding limit %ld", tnum, throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].limit );
	    else
	    if ( throttles[tnum].rate > ( throttles[tnum].limit +
		 throttles[tnum].limit / ( THROTTLE_TIME * 4 ) ) )
		syslog( LOG_NOTICE, "throttle #%d '%.80s' rate %ld exceeding limit %ld", tnum, throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].limit );
	    }
	}

    /* Now update the sending rate on all the currently-sending connections,
    ** redistributing it evenly.
    */
    for ( cnum = 0; cnum < maxconnects; ++cnum )
	{
	c = &connects[cnum];
	if ( c->conn_state == CNST_SENDING || c->conn_state == CNST_PAUSING )
	    {
	    if ( c->numtnums == 0 )
		continue;
	    if ( c->limit == THROTTLE_NOLIMIT )
		continue;
	    for ( i = 0, l1 = MaxConnBytesLimit; i < c->numtnums; ++i )
		{
		tnum = c->tnums[i];
		l2 = throttles[tnum].limit / throttles[tnum].num_sending;
		if ( l1 > l2 )
		     l1 = l2;
		}
	    if ( l1 == c->limit )
		continue;
	    /* new limit != previous limit, update throttle time and bytes */
	    c->throttled_at = nowP->tv_sec;
	    c->bytes_throttled = l1 / 8;
	    if ( l1 < c->limit )
		{ /* lower it fastly */
		c->limit = l1;
		continue;
		}
	    /* l1 > c->limit, higher it slowly */
	    l2 = l1 - c->limit;
	    if ( l2 < ( c->limit / 16 ) )
		c->limit = l1;
	    else
		c->limit += l2 / 2;
	    }
	}
    }


#ifdef USE_IPTHROTTLE

static int 
subnetcmp( const void *p1, const void *p2 )
    {
    struct in_addr i = ((subnet_t *)p1)->net;
    struct in_addr j = ((subnet_t *)p2)->net;

    if (i.s_addr > j.s_addr)
	return 1;
    if (i.s_addr < j.s_addr)
	return -1;
    return 0;
    }


static void
initmatchsubnet( char* filename )
    {
    int len;
    int numline = 0;
    FILE* fp;
    char buf[4096];
    char* cp;
    char pattern[4096];
    int tnum, maxtnum;
    char ip_s[16];
    char mask_s[4];
    struct in_addr ip;
    int mask;
    subnet_t* nettab = (subnet_t*) 0;
    int nettab_len=0;
    int nettab_max=0;

    maxtnum = numurithrottles+numipthrottles;

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	{
	syslog( LOG_CRIT, "%.80s - %m", filename );
	if ( subnets_reload )
	    return;
	perror( filename );
	exit( 71 );
	}

    while ( fgets( buf, sizeof(buf), fp ) != (char*) 0 )
	{
	++numline;

	cp = strchr( buf, '#' );
	if ( cp != (char*) 0 )
	    *cp = '\0';

	len = strlen( buf );
	while ( len > 0 &&
		( buf[len-1] == ' ' || buf[len-1] == '\t' ||
		  buf[len-1] == '\n' || buf[len-1] == '\r' ) )
		buf[--len] = '\0';

	if ( len == 0 )
	    continue;

	if ( sscanf( buf, "%15[^/]/%3[^ \t] %4000[^ \t]",
		ip_s, mask_s, pattern ) != 3 ||
	    inet_aton(ip_s, &ip) != 1 ||
	    ( mask = atoi( mask_s ) ) > 33 )
	    {
	    syslog( LOG_CRIT,
		"unparsable line(%d) in %.80s - %.80s",
		numline, filename, buf );
	    (void) fprintf( stderr,
		"%s: unparsable line(%d) in %.80s - %.80s\n",
		argv0, numline, filename, buf );
	    continue;
	    }

	/* search subnet rule in ipthrottles rule */
	for ( tnum = numurithrottles;
		(tnum < maxtnum) &&
		( match( throttles[tnum].pattern, pattern ) == 0 );
	    ++tnum )
	    ;

	/* if no rules set it to -1 */
	if ( tnum >= maxtnum )
	    {
	    syslog( LOG_CRIT,
		"unmatch pattern at line(%d) in %.80s - %.80s",
		numline, filename, buf );
	    (void) fprintf( stderr,
		"%s: unmatch pattern at line(%d) in %.80s - %.80s\n",
		argv0, numline, filename, buf );
	    tnum = -1;
	    }

	ip.s_addr = htonl(ip.s_addr);

	/* if subnet is 0.0.0.0/0, set the 'out' subnet rule */
	if ( ip.s_addr == 0 )
	    {
	    outiprule = tnum;
	    continue;
	    }

	if ( nettab_len >= nettab_max )
	    {
	    if ( nettab_max == 0 )
		{
		nettab_max = 16;
		nettab = NEW(subnet_t, nettab_max);
		}
	    else
		{
		nettab_max *= 2;
		nettab = RENEW( nettab, subnet_t, nettab_max );
		}
	    if ( nettab == (subnet_t*) 0 )
		{
		syslog( LOG_CRIT, "out of memory allocating a nettab" );
		(void) fprintf( stderr,
				"%s: out of memory allocating a nettab\n",
				argv0 );
		if ( subnets_reload )
		    {
		    fclose(fp);
		    return;
		    }
		exit(72);
		}
	    }
	    nettab[nettab_len].net = ip;
	    nettab[nettab_len].mask = ~0 << (32 - mask);
	    nettab[nettab_len].rule = tnum;
	    ++nettab_len;
	}

    fclose(fp);

    qsort( (void *)nettab, nettab_len, sizeof (subnet_t), subnetcmp );

    if ( subnets != (subnet_t*) 0 )
	free(subnets);

    subnets = nettab;
    subnets_uselen = nettab_len;
    subnets_maxlen = nettab_max;

    return;
    }


static int
searchinsubnets( struct in_addr ip )
    {
    int lo = 0;
    int hi = subnets_uselen;
    int mid;
    struct in_addr ipmask, ipref;

    ip.s_addr = htonl(ip.s_addr);
    while( lo < hi )
	{
	mid = ( lo + hi ) / 2;
	ipref = subnets[mid].net;
	ipmask.s_addr = ip.s_addr & subnets[mid].mask;
	if ( ipmask.s_addr == ipref.s_addr )
	    return subnets[mid].rule;
	if ( ipmask.s_addr < ipref.s_addr )
	    hi = mid;
	else
	    lo = mid + 1;
	}
    return outiprule;
    }

#endif /* USE_IPTHROTTLE */


static void
resp_clear_connection( connecttab* c, struct timeval* tvP, int do_keep_alive )
    {
    httpd_conn* hc = c->hc;

    if ( c->wakeup_timer != (Timer*) 0 )
	{
	tmr_cancel( c->wakeup_timer );
	c->wakeup_timer = (Timer*) 0;
	}
    if ( c->linger_timer != (Timer*) 0 )
	{
	tmr_cancel( c->linger_timer );
	c->linger_timer = (Timer*) 0;
	}
    /* we should have already disabled keep alive
    ** but "better later than never".
    */
    if ( !do_keep_alive && hc->do_keep_alive )
	hc->do_keep_alive = 0;

    /* If we haven't actually sent the buffered response yet,
    ** then do so now.
    ** NOTE: sending at most 1-2 KB of data should fit into default
    **		send buffer (4-16 KB), unless we are pipelining
    **		but in this case we don't care because we handle
    **		partial writes.
    */
    if ( hc->responselen > 0 )
	{
	/* reset counters,
	** if required, c->conn_state will be changed to CNST_SENDING_RESP
	** by handle_send_resp().
	*/
	c->throttled_at = tvP->tv_sec;
	c->iotimeout_at = tvP->tv_sec + SecIdleSendRespTimeLimit;
	c->wouldblock_delay = 0;
	c->bytes_throttled = 0;

	/* don't reset watch event now, if necessary it will be done later */

	/* send response */
	handle_send_resp( c, tvP );
	return;
	}

    clear_connection( c, tvP, hc->do_keep_alive );

    }


static void
clear_connection( connecttab* c, struct timeval* tvP, int do_keep_alive )
    {

    /* caller should have just managed to eventually send error response */
    /* so c->hc->responselen should be == 0, */
    /* there is no need to call write() here */

    if ( c->wakeup_timer != (Timer*) 0 )
	{
	tmr_cancel( c->wakeup_timer );
	c->wakeup_timer = (Timer*) 0;
	}
    if ( c->linger_timer != (Timer*) 0 )
	{
	tmr_cancel( c->linger_timer );
	c->linger_timer = (Timer*) 0;
	}

    /* Here we do one of these actions:
    **     1) keep alive connection and continue to read next request;
    **     2) linger close connection;
    **     3) close connection.
    */

    if ( c->hc->do_keep_alive && do_keep_alive )
	{
	long secKeepAlive = SecIdleKeepAliveTimeLimit;

	c->conn_state = CNST_READING;

	/* Figure out if client is pipelining requests (no POST method here) */
	if ( c->pipelining == 0 && httpd_is_next_request( c->hc ) )
	    c->pipelining = 1;

	/* Tweak: if client is pipelining then increment keep alive time;
	** this because client is probably saturating its bandwidth,
	** thus single replies get less bandwidth and may require more time
	** (this is useful only for non buffered requests).
	*/
	if ( c->pipelining && numconnects < hiwmconnects2 )
	    secKeepAlive += 2L;

	/* TWEAK: if server has just replied with a body content
	** (maybe also length could be checked) then try to increment
	** keep alive timeout to not close connection too early;
	** if server is overloaded then decrease keep alive timeout
	** to lower the number of idle connections.
	** RANT: if there were a socket event fired only when send buffer
	** is completely empty, the algorithm could be much more efficient
	** (if send buffer is not filled over high water mark,
	** then it remains writeable);  yeah, we don't want to use a
	** costly ioctl to know about how many bytes are in send buffer.
	*/
	if ( numconnects < hiwmconnects1 &&
	     c->hc->method == METHOD_GET &&
	     ( c->hc->status == 200 || c->hc->status == 206 ) )
	    secKeepAlive += secKeepAlive / 4;
	else
	if ( numconnects >= hiwmconnects3 &&
	    secKeepAlive >= 4L )
	    secKeepAlive -= secKeepAlive / 4;

	/* stats_body_bytes has already been updated after every write */

	/* clears also tnums */
	clear_throttles( c, tvP );

	c->bytes_throttled = 0;
	c->bytes_to_send = 0;
	c->bytes_sent = 0;
	c->keep_alive++;

	c->iotimeout_at = tvP->tv_sec + secKeepAlive + 1;

	/* uncork and complete request */
	if ( c->hc->file_fd != EOF && numthrottles == 0 )
	    (void) httpd_set_cork( c->hc->conn_fd, SOPT_OFF );

	/* log and unmap file */
	httpd_complete_request( c->hc, tvP, CR_DO_LOGIT );

	if (!fdwatch_is_fd( c->hc->conn_fd ) )
	    fdwatch_add_fd( c->hc->conn_fd, c, FDW_READ );
	else
	    fdwatch_mod_fd( c->hc->conn_fd, c, FDW_READ );

	/* we can call the following function because
	** httpd_got_request() certainly returned GR_GOT_REQUEST.
	*/
	httpd_request_reset2( c->hc );
    	c->hc->keep_alive_tmo = ( ( IDLE_READ_TIMELIMIT / 2 ) + 1 );

	/* we might already have next request in buffer
	** if client is sending pipelined requests,
	** thus we make a call here;  if there is no data or not enough data
	** then we will wait till data arrives or read timer expires.
	** NOTE: be careful about recursive calls of same function.
	*/
	handle_buf_read( c, tvP );
	}
    else if ( c->hc->should_linger )
        {
	/* This is our version of Apache's lingering_close() routine, which is
	** their version of the often-broken SO_LINGER socket option.
	** For why this is necessary,
	** see http://www.apache.org/docs/misc/fin_wait_2.html.
	** What we do is delay the actual closing for a few seconds,
	** while reading any bytes that come over the connection.
	** However, we don't want to do this unless it's necessary,
	** because it ties up a connection slot and file descriptor
	** which means our maximum connection-handling rate is lower.
	** So, elsewhere we set a flag when we detect the few
	** circumstances that make a lingering close necessary.
	*/
	ClientData client_data;
	long mlsLingerTime = LINGER_TIME * 1000L;

	if (!fdwatch_is_fd( c->hc->conn_fd ) )
	    fdwatch_add_fd( c->hc->conn_fd, c, FDW_READ );
	else
	    fdwatch_mod_fd( c->hc->conn_fd, c, FDW_READ );

	c->conn_state = CNST_LINGERING;

	/* No need to uncork because we are going to
	** half close connection now, just before lingering.
	*/
	httpd_close_conn_wr( c->hc );

#ifdef  DYNAMIC_LINGER_TIME
	/* dynamically adapt linger time
	** NOTE: keep alive (including pipelining) requires more time.
	*/
	if ( c->pipelining && numconnects < hiwmconnects2 )
	if ( c->keep_alive == 0 )
	    mlsLingerTime /= 2;
	else
	if ( c->pipelining != 0 )
	    mlsLingerTime += 1000L;
	else
	    mlsLingerTime += 500L;
#endif /* DYNAMIC_LINGER_TIME */

	client_data.p = c;
	c->linger_timer = tmr_create(
	    tvP, linger_clear_connection, client_data, mlsLingerTime,
		TMR_ONE_SHOT );
	if ( c->linger_timer == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(linger_clear_connection) failed" );
	    exit( 81 );
	    }
	/* log and unmap file */
    	httpd_complete_request( c->hc, tvP, CR_DO_LOGIT );
	}
     else
        {
	/*
	** should_linger flag isn't set, thus we do the real close now.
	*/
	/* no need to uncork (because connection is going to be closed) */
    	httpd_complete_request( c->hc, tvP, !c->keep_alive );
	really_clear_connection( c, tvP );
	}
    }


static void
really_clear_connection( connecttab* c, struct timeval* tvP )
    {
    if ( c->conn_state == CNST_FREE )
	{   /* this should never happen */
	syslog( LOG_ERR,
	    "really_clear_connection, already FRED (numconnects %d)",
	    numconnects );
	return;
	}

    /* stats_body_bytes has already been updated after every write */

    if ( c->hc->should_linger != 0 )
	(void) read_linger( c, tvP );

    /* connection could be pausing */
    if ( fdwatch_is_fd( c->hc->conn_fd ) )
	fdwatch_del_fd( c->hc->conn_fd );

#ifdef SYNC_FD_ON_CLOSE
    /* synchronize buffered events (not strictly required here) */
    (void) fdwatch_sync();
#endif /* SYNC_FD_ON_CLOSE */

    /* close connection and update its state */
    httpd_close_conn( c->hc, tvP );
    clear_throttles( c, tvP );
    if ( c->linger_timer != (Timer*) 0 )
	{
	tmr_cancel( c->linger_timer );
	c->linger_timer = (Timer*) 0;
	}
    c->hc->do_keep_alive = 0;
    c->hc->should_linger = 0;
    c->conn_state = CNST_FREE;
    c->keep_alive = 0;
    c->pipelining = 0;

    if ( numfreeconnects >= maxconnects )
	{
	syslog( LOG_CRIT,
	"really_clear_connection(exit): numfreeconnects %d >= %d maxconnects",
		numfreeconnects, maxconnects );
	exit( 77 );
	}
    freeconnects[numfreeconnects++] = c;
    --numconnects;

    /* if required, re-add listen sockets to watched fdset */
#ifndef SYSLOG_EACH_TOOMCONNS
    if ( ovfconnects != 0 &&
	numconnects < hiwmconnects4 &&
	hs != (httpd_server*) 0 )
	{
	if ( hs->listen4_fd != -1 &&
	   ! fdwatch_is_fd( hs->listen4_fd ) )
	    fdwatch_add_fd( hs->listen4_fd, (void*) 0, FDW_READ );
	if ( hs->listen6_fd != -1 &&
	   ! fdwatch_is_fd( hs->listen6_fd ) )
	    fdwatch_add_fd( hs->listen6_fd, (void*) 0, FDW_READ );

	/* Syslog flood limit */
#ifdef SYSLOG_BEGEND_TOOMCONNS
	syslog( LOG_WARNING, "END   of TOO MANY CONNECTIONS (%d) ovf %6d !",
		numconnects, ovfconnects );
#endif /* SYSLOG_BEGEND_TOOMCONNS */
	ovfconnects = 0;
	}
#endif /* SYSLOG_EACH_TOOMCONNS */
    }


static void
wakeup_connection( ClientData client_data, struct timeval* nowP )
    {
    connecttab* c;

    c = (connecttab*) client_data.p;
    c->wakeup_timer = (Timer*) 0;
    if ( c->conn_state == CNST_PAUSING )
	{
	c->conn_state = CNST_SENDING;
	fdwatch_add_fd( c->hc->conn_fd, c, FDW_WRITE );
	}
    }


static void
wakeup_resp_connection( ClientData client_data, struct timeval* nowP )
    {
    connecttab* c;

    c = (connecttab*) client_data.p;
    c->wakeup_timer = (Timer*) 0;
    if ( c->conn_state == CNST_PAUSING )
	{
	c->conn_state = CNST_SENDING_RESP;
	fdwatch_add_fd( c->hc->conn_fd, c, FDW_WRITE );
	}
    }


static void
linger_clear_connection( ClientData client_data, struct timeval* nowP )
    {
    connecttab* c;

    c = (connecttab*) client_data.p;
    if ( c == (connecttab*) 0 )
	return;
    c->linger_timer = (Timer*) 0;
    really_clear_connection( c, nowP );
    }


static void
occasional_idle( ClientData client_data, struct timeval* nowP )
    {
    time_t now;
    connecttab* c;
    connecttab* ce;
#ifdef SYSLOG_TOTCNT_CONNTMO
    int num_rdtmo = 0;
    int num_wrtmo = 0;
#endif /* SYSLOG_TOTCNT_CONNTMO */
    int num_checked = 0;
    char *strconnstate = "";

    /* Get the current time, if necessary. */
    if ( nowP != (struct timeval*) 0 )
	now = nowP->tv_sec;
    else
	now = time( (time_t*) 0 );

    /* Check for connections timed out */
    for ( c = connects, ce = connects + maxconnects;
	  c < ce && num_checked < numconnects;
	  ++c )
	{

	if ( c->conn_state == CNST_FREE )
	    continue;

	if ( now < c->iotimeout_at )
	    continue;

	++num_checked;

	switch( c->conn_state )
	    {
	    case CNST_READING:
		if ( !c->keep_alive && c->hc->responselen == 0 )
		    {
		    /* we log timeout only on first read because timing out
		    ** with keep-alive is not a warning nor an error.
		    */
#ifdef SYSLOG_TOTCNT_CONNTMO
		    ++num_rdtmo;
#endif /* SYSLOG_TOTCNT_CONNTMO */
#ifdef SYSLOG_EACH_CONNTMO
		    syslog( LOG_INFO,
			    "%.80s connection timed out reading",
			    httpd_ntoa( &c->hc->client_addr ) );
#endif /* SYSLOG_EACH_CONNTMO */
		    httpd_send_err( c->hc, 408,
				httpd_err_title(408),
				httpd_err_titlelen(408), "",
				httpd_err_form(408), "" );
		    }
		resp_clear_connection( c, nowP, NO_KEEP_ALIVE );
		continue;

	    case CNST_SENDING:
	    case CNST_SENDING_RESP:
	    case CNST_PAUSING:
		/* pausing only in send state */
		switch( c->conn_state )
		    {
		    case CNST_SENDING:
			strconnstate = "sending data";
			break;
		    case CNST_SENDING_RESP:
			strconnstate = "sending response";
			break;
		    case CNST_PAUSING:
		    default:
			strconnstate = "pausing";
			break;
		    }
#ifdef SYSLOG_TOTCNT_CONNTMO
		++num_wrtmo;
#endif /* SYSLOG_TOTCNT_CONNTMO */
#ifdef SYSLOG_EACH_CONNTMO
		syslog( LOG_INFO,
		    "%.80s connection timed out %s",
		    httpd_ntoa( &c->hc->client_addr ), strconnstate );
#endif /* SYSLOG_EACH_CONNTMO */
		/* there is no need to send a response */
		clear_connection( c, nowP, NO_KEEP_ALIVE );
		continue;

	    default:
		continue;
	    }
	}
#ifdef SYSLOG_TOTCNT_CONNTMO
	if ( num_rdtmo > 0 || num_wrtmo > 0 )
	    syslog( LOG_INFO, "Timed out %d (RD), %d (WR) connections",
		num_rdtmo, num_wrtmo );
#endif /* SYSLOG_TOTCNT_CONNTMO */
    }


#if defined(LOG_FLUSH_TIME) && (LOG_FLUSH_TIME > 0)
static void
occasional_log( ClientData client_data, struct timeval* nowP )
    {
    httpd_flush_logfp( hs );
    }
#endif /* LOG_FLUSH_TIME */


static void
occasional_mmc( ClientData client_data, struct timeval* nowP )
    {
    mmc_cleanup( nowP );
    }


static void
occasional_tmr( ClientData client_data, struct timeval* nowP )
    {
    tmr_cleanup();
    }


#ifdef STATS_TIME
static void
show_stats( ClientData client_data, struct timeval* nowP )
    {
    logstats( nowP );
    }
#endif /* STATS_TIME */


/* Generate debugging statistics syslog messages for all packages. */
static void
logstats( struct timeval* nowP )
    {
    struct timeval tv;
    time_t now;
    long up_secs, stats_secs;

    if ( nowP == (struct timeval*) 0 )
	{
	(void) gettimeofday( &tv, (struct timezone*) 0 );
	nowP = &tv;
	}
    now = nowP->tv_sec;
    up_secs    = (long) (now - start_time);
    stats_secs = (long) (now - stats_time);
    if ( stats_secs < 1L )
	 stats_secs = 1L;	/* fudge */
    stats_time = now;
    syslog( LOG_INFO,
	"up %ld seconds, stats for %ld seconds:", up_secs, stats_secs );

    thttpd_logstats( stats_secs );
    httpd_logstats( stats_secs );
    mmc_logstats( stats_secs );
    fdwatch_logstats( stats_secs );
    tmr_logstats( stats_secs );
    }


/* Generate debugging statistics syslog message. */
static void
thttpd_logstats( long secs )
    {
    /* NOTE: CGIs and directory listings are NOT counted / reported here ! */

    syslog( LOG_INFO,
	"  thttpd - %lu requests (%g/sec)",
	stats_requests,    (float) stats_requests / secs
	);

    syslog( LOG_INFO,
	"  thttpd - %lu connections (%g/sec)",
	stats_connections, (float) stats_connections / secs
	);

    syslog( LOG_INFO,
	"  thttpd - %d max simultaneous connections, %d httpd_conns allocated",
	stats_simultaneous,
	httpd_conn_count
	);

    syslog( LOG_INFO,
	"  thttpd - %lu accept_aborted, %lu overflows (too many connections)",
	stats_connaborted,
	stats_ovfconnects
	);

    syslog( LOG_INFO,
#ifdef HAVE_INT64T
	"  thttpd - resp. %lld bytes (%lld/sec), body %lld bytes (%lld/sec)",
#else
	"  thttpd - resp. %lu bytes (%lu/sec), body %lu bytes (%lu/sec)",
#endif
	stats_resp_bytes, ( stats_resp_bytes / secs ),
	stats_body_bytes, ( stats_body_bytes / secs )
	);

    stats_requests     = 0;
    stats_connections  = 0;
    stats_connaborted  = 0;
    stats_simultaneous = 0;
    stats_resp_bytes   = 0;
    stats_body_bytes   = 0;
    stats_ovfconnects  = 0;
    }
