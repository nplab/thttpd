/* thttpd.c - tiny/turbo/throttling HTTP server
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


static char* argv0;
static int debug;
static int port;
static char* dir;
static int do_chroot, no_log, no_symlink, do_vhost, do_global_passwd;
static char* cgi_pattern;
static char* url_pattern;
static int no_empty_referers;
static char* local_pattern;
static char* logfile;
static char* throttlefile;
static char* hostname;
static char* pidfile;
static char* user;
static char* charset;


typedef struct {
    char* pattern;
    long limit;
    long rate;
    off_t bytes_since_avg;
    int num_sending;
    } throttletab;
static throttletab* throttles;
static int numthrottles, maxthrottles;

#define THROTTLE_NOLIMIT 1234567890L	/* default limit (if none) */


typedef struct {
    int conn_state;
    httpd_conn* hc;
    int tnums[MAXTHROTTLENUMS];         /* throttle indexes */
    int numtnums;
    long limit;
    time_t started_at;
    Timer* idle_read_timer;
    Timer* idle_send_timer;
    Timer* wakeup_timer;
    Timer* linger_timer;
    long wouldblock_delay;
    off_t bytes;
    off_t bytes_sent;
    off_t bytes_to_send;
    } connecttab;
static connecttab* connects;
static int numconnects, maxconnects;
static int httpd_conn_count;

/* The connection states. */
#define CNST_FREE 0
#define CNST_READING 1
#define CNST_SENDING 2
#define CNST_PAUSING 3
#define CNST_LINGERING 4


static httpd_server* hs = (httpd_server*) 0;
int terminate = 0;
time_t start_time, stats_time;
long stats_connections, stats_bytes;
int stats_simultaneous;

static int got_usr1;


/* Forwards. */
static void parse_args( int argc, char** argv );
static void usage( void );
static void read_config( char* filename );
static void value_required( char* name, char* value );
static void no_value_required( char* name, char* value );
static char* e_strdup( char* oldstr );
static void lookup_hostname( httpd_sockaddr* sa4P, size_t sa4_len, int* gotv4P, httpd_sockaddr* sa6P, size_t sa6_len, int* gotv6P );
static void read_throttlefile( char* throttlefile );
static void shut_down( void );
static int handle_newconnect( struct timeval* tvP, int listen_fd );
static void handle_read( connecttab* c, struct timeval* tvP );
static void handle_send( connecttab* c, struct timeval* tvP );
static void handle_linger( connecttab* c, struct timeval* tvP );
static int check_throttles( connecttab* c );
static void clear_throttles( connecttab* c, struct timeval* tvP );
static void update_throttles( ClientData client_data, struct timeval* nowP );
static void clear_connection( connecttab* c, struct timeval* tvP );
static void really_clear_connection( connecttab* c, struct timeval* tvP );
static void idle_read_connection( ClientData client_data, struct timeval* nowP );
static void idle_send_connection( ClientData client_data, struct timeval* nowP );
static void wakeup_connection( ClientData client_data, struct timeval* nowP );
static void linger_clear_connection( ClientData client_data, struct timeval* nowP );
static void occasional( ClientData client_data, struct timeval* nowP );
#ifdef STATS_TIME
static void show_stats( ClientData client_data, struct timeval* nowP );
#endif /* STATS_TIME */
static void logstats( struct timeval* nowP );
static void thttpd_logstats( long secs );


static void
handle_term( int sig )
    {
    shut_down();
    syslog( LOG_NOTICE, "exiting due to signal %d", sig );
    closelog();
    exit( 1 );
    }


static void
handle_hup( int sig )
    {
    FILE* logfp;

    if ( no_log )
	return;

    /* Re-open the log file. */
    if ( logfile != (char*) 0 )
	{
	logfp = fopen( logfile, "a" );
	if ( logfp == (FILE*) 0 )
	    {
	    syslog( LOG_CRIT, "reopening %.80s - %m", logfile );
	    return;
	    }
	(void) fcntl( fileno( logfp ), F_SETFD, 1 );
	httpd_set_logfp( hs, logfp );
	}
    }


static void
handle_usr1( int sig )
    {
    got_usr1 = 1;
    }


static void
handle_usr2( int sig )
    {
    logstats( (struct timeval*) 0 );
    }


int
main( int argc, char** argv )
    {
    char* cp;
    struct passwd* pwd;
    uid_t uid;
    gid_t gid;
    char cwd[MAXPATHLEN];
    FILE* logfp;
    int num_ready;
    int cnum, ridx;
    connecttab* c;
    httpd_conn* hc;
    httpd_sockaddr sa4;
    httpd_sockaddr sa6;
    int gotv4, gotv6;
    struct timeval tv;

    argv0 = argv[0];

    cp = strrchr( argv0, '/' );
    if ( cp != (char*) 0 )
	++cp;
    else
	cp = argv0;
    openlog( cp, LOG_NDELAY|LOG_PID, LOG_FACILITY );

    /* Handle command-line arguments. */
    parse_args( argc, argv );

    /* Check port number. */
    if ( port <= 0 )
	{
	syslog( LOG_CRIT, "illegal port number" );
	(void) fprintf( stderr, "%s: illegal port number\n", argv0 );
	exit( 1 );
	}

    /* Read zone info now, in case we chroot(). */
    tzset();

    /* Look up hostname now, in case we chroot(). */
    lookup_hostname( &sa4, sizeof(sa4), &gotv4, &sa6, sizeof(sa6), &gotv6 );
    if ( ! ( gotv4 || gotv6 ) )
	{
	syslog( LOG_ERR, "can't find any valid address" );
	(void) fprintf( stderr, "%s: can't find any valid address\n", argv0 );
	exit( 1 );
	}

    /* Throttle file. */
    numthrottles = 0;
    maxthrottles = 0;
    throttles = (throttletab*) 0;
    if ( throttlefile != (char*) 0 )
	read_throttlefile( throttlefile );

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
		exit( 1 );
		}
	    (void) fcntl( fileno( logfp ), F_SETFD, 1 );
	    }
	}
    else
	logfp = (FILE*) 0;

    /* Figure out uid/gid from user. */
    pwd = getpwnam( user );
    if ( pwd == (struct passwd*) 0 )
	{
	syslog( LOG_CRIT, "unknown user - '%.80s'", user );
	(void) fprintf( stderr, "%s: unknown user - '%s'\n", argv0, user );
	exit( 1 );
	}
    uid = pwd->pw_uid;
    gid = pwd->pw_gid;

    /* Switch directories if requested. */
    if ( dir != (char*) 0 )
	{
	if ( chdir( dir ) < 0 )
	    {
	    syslog( LOG_CRIT, "chdir - %m" );
	    perror( "chdir" );
	    exit( 1 );
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
	    exit( 1 );
	    }
	}
#endif /* USE_USER_DIR */

    /* Get current directory. */
    (void) getcwd( cwd, sizeof(cwd) - 1 );
    if ( cwd[strlen( cwd ) - 1] != '/' )
	(void) strcat( cwd, "/" );

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
	    exit( 1 );
	    }
#else /* HAVE_DAEMON */
	switch ( fork() )
	    {
	    case 0:
	    break;
	    case -1:
	    syslog( LOG_CRIT, "fork - %m" );
	    exit( 1 );
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
	    exit( 1 );
	    }
	(void) fprintf( pidfp, "%d\n", (int) getpid() );
	(void) fclose( pidfp );
	}

    /* Chroot if requested. */
    if ( do_chroot )
	{
	if ( chroot( cwd ) < 0 )
	    {
	    syslog( LOG_CRIT, "chroot - %m" );
	    perror( "chroot" );
	    exit( 1 );
	    }
	(void) strcpy( cwd, "/" );
	/* Always chdir to / after a chroot. */
	if ( chdir( cwd ) < 0 )
	    {
	    syslog( LOG_CRIT, "chroot chdir - %m" );
	    perror( "chroot chdir" );
	    exit( 1 );
	    }
	}

    /* Set up to catch signals. */
    (void) signal( SIGTERM, handle_term );
    (void) signal( SIGINT, handle_term );
    (void) signal( SIGPIPE, SIG_IGN );          /* get EPIPE instead */
    (void) signal( SIGHUP, handle_hup );
    got_usr1 = 0;
    (void) signal( SIGUSR1, handle_usr1 );
    (void) signal( SIGUSR2, handle_usr2 );

    /* Initialize the timer package. */
    tmr_init();

    /* Initialize the HTTP layer.  Got to do this before giving up root,
    ** so that we can bind to a privileged port.
    */
    hs = httpd_initialize(
	hostname,
	gotv4 ? &sa4 : (httpd_sockaddr*) 0, gotv6 ? &sa6 : (httpd_sockaddr*) 0,
	port, cgi_pattern, charset, cwd, no_log, logfp, no_symlink, do_vhost,
	do_global_passwd, url_pattern, local_pattern, no_empty_referers );
    if ( hs == (httpd_server*) 0 )
	exit( 1 );

    /* Set up the occasional timer. */
    if ( tmr_create( (struct timeval*) 0, occasional, JunkClientData, OCCASIONAL_TIME * 1000L, 1 ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(occasional) failed" );
	exit( 1 );
	}
    if ( numthrottles > 0 )
	{
	/* Set up the throttles timer. */
	if ( tmr_create( (struct timeval*) 0, update_throttles, JunkClientData, THROTTLE_TIME * 1000L, 1 ) == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(update_throttles) failed" );
	    exit( 1 );
	    }
	}
#ifdef STATS_TIME
    /* Set up the stats timer. */
    if ( tmr_create( (struct timeval*) 0, show_stats, JunkClientData, STATS_TIME * 1000L, 1 ) == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(show_stats) failed" );
	exit( 1 );
	}
#endif /* STATS_TIME */
    start_time = stats_time = time( (time_t*) 0 );
    stats_connections = stats_bytes = 0L;
    stats_simultaneous = 0;

    /* If we're root, try to become someone else. */
    if ( getuid() == 0 )
	{
	/* Set aux groups to null. */
	if ( setgroups( 0, (const gid_t*) 0 ) < 0 )
	    {
	    syslog( LOG_CRIT, "setgroups - %m" );
	    exit( 1 );
	    }
	/* Set primary group. */
	if ( setgid( gid ) < 0 )
	    {
	    syslog( LOG_CRIT, "setgid - %m" );
	    exit( 1 );
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
	    exit( 1 );
	    }
	/* Check for unnecessary security exposure. */
	if ( ! do_chroot )
	    syslog(
		LOG_CRIT,
		"started as root without requesting chroot(), warning only" );
	}

    /* Initialize our connections table. */
    maxconnects = fdwatch_get_nfiles();
    if ( maxconnects < 0 )
	{
	syslog( LOG_CRIT, "fdwatch initialization failure" );
	exit( 1 );
	}
    maxconnects -= SPARE_FDS;
    connects = NEW( connecttab, maxconnects );
    if ( connects == (connecttab*) 0 )
	{
	syslog( LOG_CRIT, "out of memory allocating a connecttab" );
	exit( 1 );
	}
    for ( cnum = 0; cnum < maxconnects; ++cnum )
	{
	connects[cnum].conn_state = CNST_FREE;
	connects[cnum].hc = (httpd_conn*) 0;
	}
    numconnects = 0;
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
    while ( ( ! terminate ) || numconnects > 0 )
	{
	/* Do the fd watch. */
	num_ready = fdwatch( tmr_mstimeout( &tv ) );
	if ( num_ready < 0 )
	    {
	    if ( errno == EINTR )
		continue;       /* try again */
	    syslog( LOG_ERR, "fdwatch - %m" );
	    exit( 1 );
	    }
	(void) gettimeofday( &tv, (struct timezone*) 0 );
	if ( num_ready == 0 )
	    {
	    /* No fd's are ready - run the timers. */
	    tmr_run( &tv );
	    continue;
	    }

	/* Is it a new connection? */
	if ( hs != (httpd_server*) 0 && hs->listen6_fd != -1 && 
	     fdwatch_check_fd( hs->listen6_fd ) )
	    {
	    if ( handle_newconnect( &tv, hs->listen6_fd ) )
		/* Go around the loop and do another fdwatch, rather than
		** dropping through and processing existing connections.
		** New connections always get priority.
		*/
		continue;
	    }
	if ( hs != (httpd_server*) 0 && hs->listen4_fd != -1 && 
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
	    if ( c == (connecttab*) 0 )
		continue;
	    hc = c->hc;
	    if ( c->conn_state == CNST_READING &&
		 fdwatch_check_fd( hc->conn_fd ) )
		handle_read( c, &tv );
	    else if ( c->conn_state == CNST_SENDING &&
		 fdwatch_check_fd( hc->conn_fd ) )
		handle_send( c, &tv );
	    else if ( c->conn_state == CNST_LINGERING &&
		 fdwatch_check_fd( hc->conn_fd ) )
		handle_linger( c, &tv );
	    }
	tmr_run( &tv );

	if ( got_usr1 && ! terminate )
	    {
	    terminate = 1;
	    if ( hs != (httpd_server*) 0 )
		{
		httpd_terminate( hs );
		hs = (httpd_server*) 0;
		}
	    }
	}

    /* The main loop terminated. */
    shut_down();
    syslog( LOG_NOTICE, "exiting" );
    closelog();
    exit( 0 );
    }


static void
parse_args( int argc, char** argv )
    {
    int argn;

    debug = 0;
    port = DEFAULT_PORT;
    dir = (char*) 0;
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
#ifdef CGI_PATTERN
    cgi_pattern = CGI_PATTERN;
#else /* CGI_PATTERN */
    cgi_pattern = (char*) 0;
#endif /* CGI_PATTERN */
    url_pattern = (char*) 0;
    no_empty_referers = 0;
    local_pattern = (char*) 0;
    throttlefile = (char*) 0;
    hostname = (char*) 0;
    logfile = (char*) 0;
    pidfile = (char*) 0;
    user = DEFAULT_USER;
    charset = DEFAULT_CHARSET;
    argn = 1;
    while ( argn < argc && argv[argn][0] == '-' )
	{
	if ( strcmp( argv[argn], "-C" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    read_config( argv[argn] );
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
	else if ( strcmp( argv[argn], "-s" ) == 0 )
	    no_symlink = 0;
	else if ( strcmp( argv[argn], "-nos" ) == 0 )
	    no_symlink = 1;
	else if ( strcmp( argv[argn], "-u" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    user = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-c" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    cgi_pattern = argv[argn];
	    }
	else if ( strcmp( argv[argn], "-t" ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    throttlefile = argv[argn];
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
"usage:  %s [-C configfile] [-p port] [-d dir] [-r|-nor] [-v|-nov] [-g|-nog] [-u user] [-c cgipat] [-t throttles] [-h host] [-l logfile] [-i pidfile] [-T charset] [-V] [-D]\n",
	argv0 );
    exit( 1 );
    }


static void
read_config( char* filename )
    {
    FILE* fp;
    char line[10000];
    char* cp;
    char* cp2;
    char* name;
    char* value;

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	{
	perror( filename );
	exit( 1 );
	}

    while ( fgets( line, sizeof(line), fp ) != (char*) 0 )
	{
	/* Trim comments. */
	if ( ( cp = strchr( line, '#' ) ) != (char*) 0 )
	    *cp = '\0';

	/* Split line into words. */
	for ( cp = line; *cp != '\0'; cp = cp2 )
	    {
	    /* Skip leading whitespace. */
	    cp += strspn( cp, " \t\n\r" );
	    /* Find next whitespace. */
	    cp2 = cp + strcspn( cp, " \t\n\r" );
	    /* Insert EOS and advance next-word pointer. */
	    while ( *cp2 == ' ' || *cp2 == '\t' || *cp2 == '\n' || *cp2 == '\r' )
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
	    else if ( strcasecmp( name, "symlink" ) == 0 )
		{
		no_value_required( name, value );
		no_symlink = 0;
		}
	    else if ( strcasecmp( name, "nosymlink" ) == 0 )
		{
		no_value_required( name, value );
		no_symlink = 1;
		}
	    else if ( strcasecmp( name, "symlinks" ) == 0 )
		{
		no_value_required( name, value );
		no_symlink = 0;
		}
	    else if ( strcasecmp( name, "nosymlinks" ) == 0 )
		{
		no_value_required( name, value );
		no_symlink = 1;
		}
	    else if ( strcasecmp( name, "user" ) == 0 )
		{
		value_required( name, value );
		user = e_strdup( value );
		}
	    else if ( strcasecmp( name, "cgipat" ) == 0 )
		{
		value_required( name, value );
		cgi_pattern = e_strdup( value );
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
		throttlefile = e_strdup( value );
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
	    else
		{
		(void) fprintf(
		    stderr, "%s: unknown config option '%s'\n", argv0, name );
		exit( 1 );
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
	exit( 1 );
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
	exit( 1 );
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
	exit( 1 );
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
    char strport[10];

    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf( strport, sizeof(strport), "%d", port );
    if ( (gaierr = getaddrinfo( hostname, strport, &hints, &ai )) != 0 )
	{
	syslog(
	    LOG_CRIT, "getaddrinfo %.80s - %.80s",
	    hostname, gai_strerror( gaierr ) );
	(void) fprintf(
	    stderr, "%s: getaddrinfo %s - %s\n",
	    argv0, hostname, gai_strerror( gaierr ) );
	exit( 1 );
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
	    exit( 1 );
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
	    exit( 1 );
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
		    stderr, "%s: gethostbyname %s - %s\n",
		    argv0, hostname, hstrerror( h_errno ) );
#else /* HAVE_HSTRERROR */
		syslog( LOG_CRIT, "gethostbyname %.80s failed", hostname );
		(void) fprintf(
		    stderr, "%s: gethostbyname %s failed\n", argv0, hostname );
#endif /* HAVE_HSTRERROR */
		exit( 1 );
		}
	    if ( he->h_addrtype != AF_INET )
		{
		syslog( LOG_CRIT, "%.80s - non-IP network address", hostname );
		(void) fprintf(
		    stderr, "%s: %s - non-IP network address\n",
		    argv0, hostname );
		exit( 1 );
		}
	    (void) memcpy(
		&sa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length );
	    }
	}
    sa4P->sa_in.sin_port = htons( port );
    *gotv4P = 1;

#endif /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */
    }


static void
read_throttlefile( char* throttlefile )
    {
    FILE* fp;
    char buf[5000];
    char* cp;
    int len;
    char pattern[5000];
    long limit;
    struct timeval tv;

    fp = fopen( throttlefile, "r" );
    if ( fp == (FILE*) 0 )
	{
	syslog( LOG_CRIT, "%.80s - %m", throttlefile );
	perror( throttlefile );
	exit( 1 );
	}

    (void) gettimeofday( &tv, (struct timezone*) 0 );

    while ( fgets( buf, sizeof(buf), fp ) != (char*) 0 )
	{
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
	if ( sscanf( buf, " %4900[^ \t] %ld", pattern, &limit ) != 2 || limit <= 0 )
	    {
	    syslog( LOG_CRIT,
		"unparsable line in %.80s - %.80s", throttlefile, buf );
	    (void) fprintf( stderr,
		"%s: unparsable line in %.80s - %.80s\n",
		argv0, throttlefile, buf );
	    continue;
	    }

	/* Nuke any leading slashes in pattern. */
	if ( pattern[0] == '/' )
	    (void) strcpy( pattern, &pattern[1] );
	while ( ( cp = strstr( pattern, "|/" ) ) != (char*) 0 )
	    (void) strcpy( cp + 1, cp + 2 );

	/* Check for room in throttles. */
	if ( numthrottles >= maxthrottles )
	    {
	    if ( maxthrottles == 0 )
		{
		maxthrottles = 100;     /* arbitrary */
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
		exit( 1 );
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
	    exit( 1 );
	    }
	throttles[numthrottles].limit = limit;
	throttles[numthrottles].rate = 0;
	throttles[numthrottles].bytes_since_avg = 0;
	throttles[numthrottles].num_sending = 0;

	++numthrottles;
	}
    (void) fclose( fp );
    }


static void
shut_down( void )
    {
    int cnum;
    struct timeval tv;

    (void) gettimeofday( &tv, (struct timezone*) 0 );
    logstats( &tv );
    for ( cnum = 0; cnum < maxconnects; ++cnum )
	{
	if ( connects[cnum].conn_state != CNST_FREE )
	    httpd_close_conn( connects[cnum].hc, &tv );
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
	httpd_server* ths = hs;
	hs = (httpd_server*) 0;
	httpd_terminate( ths );
	}
    mmc_destroy();
    tmr_destroy();
    free( (void*) connects );
    if ( throttles != (throttletab*) 0 )
	free( (void*) throttles );
    }


static int
handle_newconnect( struct timeval* tvP, int listen_fd )
    {
    int cnum;
    connecttab* c;
    ClientData client_data;

    /* This loops until the accept() fails, trying to start new
    ** connections as fast as possible so we don't overrun the
    ** listen queue.
    */
    for (;;)
	{
	/* Is there room in the connection table? */
	if ( numconnects >= maxconnects )
	    {
	    /* Out of connection slots.  Run the timers, then the
	    ** existing connections, and maybe we'll free up a slot
	    ** by the time we get back here.
	    **/
	    syslog( LOG_WARNING, "too many connections!" );
	    tmr_run( tvP );
	    return 0;
	    }
	/* Find a free connection entry. */
	for ( cnum = 0; cnum < maxconnects; ++cnum )
	    if ( connects[cnum].conn_state == CNST_FREE )
		break;
	c = &connects[cnum];
	/* Make the httpd_conn if necessary. */
	if ( c->hc == (httpd_conn*) 0 )
	    {
	    c->hc = NEW( httpd_conn, 1 );
	    if ( c->hc == (httpd_conn*) 0 )
		{
		syslog( LOG_CRIT, "out of memory allocating an httpd_conn" );
		exit( 1 );
		}
	    c->hc->initialized = 0;
	    ++httpd_conn_count;
	    }

	/* Get the connection. */
	switch ( httpd_get_conn( hs, listen_fd, c->hc ) )
	    {
	    case GC_FAIL:
	    case GC_NO_MORE:
	    return 1;
	    }
	c->conn_state = CNST_READING;
	++numconnects;
	client_data.p = c;
	c->idle_read_timer = tmr_create(
	    tvP, idle_read_connection, client_data, IDLE_READ_TIMELIMIT * 1000L,
	    0 );
	if ( c->idle_read_timer == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(idle_read_connection) failed" );
	    exit( 1 );
	    }
	c->idle_send_timer = (Timer*) 0;
	c->wakeup_timer = (Timer*) 0;
	c->linger_timer = (Timer*) 0;
	c->bytes_sent = 0;
	c->numtnums = 0;

	/* Set the connection file descriptor to no-delay mode. */
	httpd_set_ndelay( c->hc->conn_fd );

	fdwatch_add_fd( c->hc->conn_fd, c, FDW_READ );

	++stats_connections;
	if ( numconnects > stats_simultaneous )
	    stats_simultaneous = numconnects;
	}
    }


static void
handle_read( connecttab* c, struct timeval* tvP )
    {
    int sz;
    ClientData client_data;
    httpd_conn* hc = c->hc;

    /* Is there room in our buffer to read more bytes? */
    if ( hc->read_idx >= hc->read_size )
	{
	if ( hc->read_size > 5000 )
	    {
	    httpd_send_err( hc, 400, httpd_err400title, "", httpd_err400form, "" );
	    clear_connection( c, tvP );
	    return;
	    }
	httpd_realloc_str(
	    &hc->read_buf, &hc->read_size, hc->read_size + 1000 );
	}

    /* Read some more bytes. */
    sz = read(
	hc->conn_fd, &(hc->read_buf[hc->read_idx]),
	hc->read_size - hc->read_idx );
    /* Ignore EWOULDBLOCK errors.  At first glance you would think that
    ** connections returned by fdwatch as readable should never give an
    ** EWOULDBLOCK; however, this apparently can happen if a packet gets
    ** garbled.
    */
    if ( sz == 0 || ( sz < 0 && ( errno != EWOULDBLOCK ) ) )
	{
	httpd_send_err( hc, 400, httpd_err400title, "", httpd_err400form, "" );
	clear_connection( c, tvP );
	return;
	}
    hc->read_idx += sz;

    /* Do we have a complete request yet? */
    switch ( httpd_got_request( hc ) )
	{
	case GR_NO_REQUEST:
	return;
	case GR_BAD_REQUEST:
	httpd_send_err( hc, 400, httpd_err400title, "", httpd_err400form, "" );
	clear_connection( c, tvP );
	return;
	}

    /* Yes.  Try parsing and resolving it. */
    if ( httpd_parse_request( hc ) < 0 )
	{
	clear_connection( c, tvP );
	return;
	}

    /* Check the throttle table */
    if ( ! check_throttles( c ) )
	{
	httpd_send_err(
	    hc, 503, httpd_err503title, "", httpd_err503form, hc->encodedurl );
	clear_connection( c, tvP );
	return;
	}

    /* Start the connection going. */
    if ( httpd_start_request( hc, tvP ) < 0 )
	{
	/* Something went wrong.  Close down the connection. */
	clear_connection( c, tvP );
	return;
	}

    /* Fill in bytes_to_send. */
    if ( hc->got_range )
	{
	c->bytes_sent = hc->init_byte_loc;
	c->bytes_to_send = hc->end_byte_loc + 1;
	}
    else
	c->bytes_to_send = hc->bytes_to_send;

    /* Check if it's already handled. */
    if ( hc->file_address == (char*) 0 )
	{
	/* No file address means someone else is handling it. */
	c->bytes_sent = hc->bytes_sent;
	clear_connection( c, tvP );
	return;
	}
    if ( c->bytes_sent >= c->bytes_to_send )
	{
	/* There's nothing to send. */
	clear_connection( c, tvP );
	return;
	}

    /* Cool, we have a valid connection and a file to send to it. */
    c->conn_state = CNST_SENDING;
    c->started_at = tvP->tv_sec;
    c->wouldblock_delay = 0;
    client_data.p = c;
    tmr_cancel( c->idle_read_timer );
    c->idle_read_timer = (Timer*) 0;
    c->idle_send_timer = tmr_create(
	tvP, idle_send_connection, client_data, IDLE_SEND_TIMELIMIT * 1000L,
	0 );
    if ( c->idle_send_timer == (Timer*) 0 )
	{
	syslog( LOG_CRIT, "tmr_create(idle_send_connection) failed" );
	exit( 1 );
	}

    fdwatch_del_fd( hc->conn_fd );
    fdwatch_add_fd( hc->conn_fd, c, FDW_WRITE );
    }


static void
handle_send( connecttab* c, struct timeval* tvP )
    {
    int sz, coast;
    ClientData client_data;
    time_t elapsed;
    httpd_conn* hc = c->hc;

    /* Do we need to write the headers first? */
    if ( hc->responselen == 0 )
	{
	/* No, just write the file. */
	sz = write(
	    hc->conn_fd, &(hc->file_address[c->bytes_sent]),
	    MIN( c->bytes_to_send - c->bytes_sent, c->limit ) );
	}
    else
	{
	/* Yes.  We'll combine headers and file into a single writev(),
	** hoping that this generates a single packet.
	*/
	struct iovec iv[2];

	iv[0].iov_base = hc->response;
	iv[0].iov_len = hc->responselen;
	iv[1].iov_base = &(hc->file_address[c->bytes_sent]);
	iv[1].iov_len = MIN( c->bytes_to_send - c->bytes_sent, c->limit );
	sz = writev( hc->conn_fd, iv, 2 );
	}

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
	c->wouldblock_delay += MIN_WOULDBLOCK_DELAY;
	c->conn_state = CNST_PAUSING;
	fdwatch_del_fd( hc->conn_fd );
	client_data.p = c;
	c->wakeup_timer = tmr_create(
	    tvP, wakeup_connection, client_data, c->wouldblock_delay, 0 );
	if ( c->wakeup_timer == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(wakeup_connection) failed" );
	    exit( 1 );
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
	** And ECONNRESET isn't interesting either.
	*/
	if ( errno != EPIPE && errno != EINVAL && errno != ECONNRESET )
	    syslog( LOG_ERR, "write - %m sending %.80s", hc->encodedurl );
	clear_connection( c, tvP );
	return;
	}

    /* Ok, we wrote something. */
    tmr_reset( tvP, c->idle_send_timer );
    /* Was this a headers + file writev()? */
    if ( hc->responselen > 0 )
	{
	/* Yes; did we write only part of the headers? */
	if ( sz < hc->responselen )
	    {
	    /* Yes; move the unwritten part to the front of the buffer. */
	    int newlen = hc->responselen - sz;
	    (void) memcpy( hc->response, &(hc->response[sz]), newlen );
	    hc->responselen = newlen;
	    sz = 0;
	    }
	else
	    {
	    /* Nope, we wrote the full headers, so adjust accordingly. */
	    sz -= hc->responselen;
	    hc->responselen = 0;
	    }
	}
    /* And update how much of the file we wrote. */
    c->bytes_sent += sz;
    c->hc->bytes_sent += sz;

    /* Are we done? */
    if ( c->bytes_sent >= c->bytes_to_send )
	{
	/* This conection is finished! */
	clear_connection( c, tvP );
	return;
	}

    /* Tune the (blockheaded) wouldblock delay. */
    if ( c->wouldblock_delay > MIN_WOULDBLOCK_DELAY )
	c->wouldblock_delay -= MIN_WOULDBLOCK_DELAY;

    /* If we're throttling, check if we're sending too fast. */
    if ( c->limit != THROTTLE_NOLIMIT )
	{
	elapsed = tvP->tv_sec - c->started_at;
	if ( elapsed == 0 || c->hc->bytes_sent / elapsed > c->limit )
	    {
	    c->conn_state = CNST_PAUSING;
	    fdwatch_del_fd( hc->conn_fd );
	    /* When should we send the next c->limit bytes
	    ** to get back on schedule?  If less than a second
	    ** (integer math rounding), use 1/8 second.
	    */
	    coast = ( c->hc->bytes_sent + c->limit ) / c->limit - elapsed;
	    client_data.p = c;
	    c->wakeup_timer = tmr_create(
		tvP, wakeup_connection, client_data,
		coast ? ( coast * 1000L ) : 125L, 0 );
	    if ( c->wakeup_timer == (Timer*) 0 )
		{
		syslog( LOG_CRIT, "tmr_create(wakeup_connection) failed" );
		exit( 1 );
		}
	    }
	}
    }


static void
handle_linger( connecttab* c, struct timeval* tvP )
    {
    char buf[1024];
    int r;

    /* In lingering-close mode we just read and ignore bytes.  An error
    ** or EOF ends things, otherwise we go until a timeout.
    */
    r = read( c->hc->conn_fd, buf, sizeof(buf) );
    if ( r <= 0 )
	really_clear_connection( c, tvP );
    }


static int
check_throttles( connecttab* c )
    {
    int tnum;

    c->numtnums = 0;
    c->limit = THROTTLE_NOLIMIT;
    for ( tnum = 0; tnum < numthrottles && c->numtnums < MAXTHROTTLENUMS;
	  ++tnum )
	if ( match( throttles[tnum].pattern, c->hc->expnfilename ) )
	    {
	    /* If we're way over the limit, don't even start. */
	    if ( throttles[tnum].rate > throttles[tnum].limit * 2 )
		return 0;
	    if ( throttles[tnum].num_sending < 0 )
		{
		syslog( LOG_ERR, "throttle sending count was negative - shouldn't happen!" );
		throttles[tnum].num_sending = 0;
		}
	    c->tnums[c->numtnums++] = tnum;
	    ++throttles[tnum].num_sending;
	    c->limit = MIN(
		c->limit, throttles[tnum].limit / throttles[tnum].num_sending );
	    }
    return 1;
    }


static void
clear_throttles( connecttab* c, struct timeval* tvP )
    {
    int i, tnum;

    for ( i = 0; i < c->numtnums; ++i )
	{
	tnum = c->tnums[i];
	--throttles[tnum].num_sending;
	throttles[tnum].bytes_since_avg += c->hc->bytes_sent;
	}
    }


static void
update_throttles( ClientData client_data, struct timeval* nowP )
    {
    int tnum;

    for ( tnum = 0; tnum < numthrottles; ++tnum )
	{
	throttles[tnum].rate =
	    ( 3 * throttles[tnum].rate +
	      throttles[tnum].bytes_since_avg / THROTTLE_TIME ) / 4;
	throttles[tnum].bytes_since_avg = 0;
	/* Log a warning message if necessary. */
	if ( throttles[tnum].rate > throttles[tnum].limit )
	    {
	    if ( throttles[tnum].rate > throttles[tnum].limit * 2 )
		syslog( LOG_NOTICE, "throttle #%d '%.80s' rate %ld GREATLY exceeding limit %ld", tnum, throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].limit );
	    else
		syslog( LOG_NOTICE, "throttle #%d '%.80s' rate %ld exceeding limit %ld", tnum, throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].limit );
	    }
	}
    }


static void
clear_connection( connecttab* c, struct timeval* tvP )
    {
    ClientData client_data;

    /* If we haven't actually sent the buffered response yet, do so now. */
    httpd_write_response( c->hc );

    if ( c->idle_read_timer != (Timer*) 0 )
	{
	tmr_cancel( c->idle_read_timer );
	c->idle_read_timer = 0;
	}
    if ( c->idle_send_timer != (Timer*) 0 )
	{
	tmr_cancel( c->idle_send_timer );
	c->idle_send_timer = 0;
	}
    if ( c->wakeup_timer != (Timer*) 0 )
	{
	tmr_cancel( c->wakeup_timer );
	c->wakeup_timer = 0;
	}

    /* This is our version of Apache's lingering_close() routine, which is
    ** their version of the often-broken SO_LINGER socket option.  For why
    ** this is necessary, see http://www.apache.org/docs/misc/fin_wait_2.html
    ** What we do is delay the actual closing for a few seconds, while reading
    ** any bytes that come over the connection.  However, we don't want to do
    ** this unless it's necessary, because it ties up a connection slot and
    ** file descriptor which means our maximum connection-handling rate
    ** is lower.  So, elsewhere we set a flag when we detect the few
    ** circumstances that make a lingering close necessary.  If the flag
    ** isn't set we do the real close now.
    */
    if ( c->hc->should_linger )
	{
	c->conn_state = CNST_LINGERING;
	fdwatch_del_fd( c->hc->conn_fd );
	fdwatch_add_fd( c->hc->conn_fd, c, FDW_READ );
	/* Make sure we are still in no-delay mode. */
	httpd_set_ndelay( c->hc->conn_fd );
	client_data.p = c;
	c->linger_timer = tmr_create(
	    tvP, linger_clear_connection, client_data, LINGER_TIME * 1000L, 0 );
	if ( c->linger_timer == (Timer*) 0 )
	    {
	    syslog( LOG_CRIT, "tmr_create(linger_clear_connection) failed" );
	    exit( 1 );
	    }
	}
    else
	really_clear_connection( c, tvP );
    }


static void
really_clear_connection( connecttab* c, struct timeval* tvP )
    {
    stats_bytes += c->bytes_to_send;
    fdwatch_del_fd( c->hc->conn_fd );
    httpd_close_conn( c->hc, tvP );
    clear_throttles( c, tvP );
    if ( c->linger_timer != (Timer*) 0 )
	{
	tmr_cancel( c->linger_timer );
	c->linger_timer = 0;
	}
    c->conn_state = CNST_FREE;
    --numconnects;
    }


static void
idle_read_connection( ClientData client_data, struct timeval* nowP )
    {
    connecttab* c;

    c = (connecttab*) client_data.p;
    c->idle_read_timer = (Timer*) 0;
    if ( c->conn_state != CNST_FREE )
	{
	syslog( LOG_INFO,
	    "%.80s connection timed out reading",
	    httpd_ntoa( &c->hc->client_addr ) );
	httpd_send_err( c->hc, 408, httpd_err408title, "", httpd_err408form, "" );
	clear_connection( c, nowP );
	}
    }


static void
idle_send_connection( ClientData client_data, struct timeval* nowP )
    {
    connecttab* c;

    c = (connecttab*) client_data.p;
    c->idle_send_timer = (Timer*) 0;
    if ( c->conn_state != CNST_FREE )
	{
	syslog( LOG_INFO,
	    "%.80s connection timed out sending",
	    httpd_ntoa( &c->hc->client_addr ) );
	clear_connection( c, nowP );
	}
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
linger_clear_connection( ClientData client_data, struct timeval* nowP )
    {
    connecttab* c;

    c = (connecttab*) client_data.p;
    c->linger_timer = (Timer*) 0;
    really_clear_connection( c, nowP );
    }


static void
occasional( ClientData client_data, struct timeval* nowP )
    {
    mmc_cleanup( nowP );
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
    up_secs = now - start_time;
    stats_secs = now - stats_time;
    if ( stats_secs == 0 )
	stats_secs = 1;	/* fudge */
    stats_time = now;
    syslog( LOG_NOTICE,
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
    syslog( LOG_NOTICE,
	"  thttpd - %ld connections (%g/sec), %d max simultaneous, %ld bytes (%g/sec), %d httpd_conns allocated",
	stats_connections, (float) stats_connections / secs,
	stats_simultaneous, stats_bytes, (float) stats_bytes / secs,
	httpd_conn_count );
    stats_connections = stats_bytes = 0L;
    stats_simultaneous = 0;
    }
