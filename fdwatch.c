/* fdwatch.c - fd watcher routines, either select() or poll()
**
** Copyright � 1999,2000 by Jef Poskanzer <jef@acme.com>.
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

#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <syslog.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#if	defined( HAVE_EPOLL_CREATE )	||	\
	defined( HAVE_EPOLL_CTL )	||	\
	defined( HAVE_EPOLL_WAIT )
#ifndef HAVE_EPOLL
#define HAVE_EPOLL	1
#endif /* HAVE_EPOLL */
#endif /* HAVE_EPOLL_* */

#if   defined( HAVE_KQUEUE )
# ifdef HAVE_SYS_EVENT_H
#  include <sys/event.h>
# endif /* HAVE_SYS_EVENT_H */
#elif defined( HAVE_EPOLL )
# ifdef HAVE_SYS_EPOLL_H
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <sys/epoll.h>
# endif /* HAVE_SYS_EPOLL_H */
#elif defined( HAVE_DEVPOLL )
# ifdef HAVE_SYS_DEVPOLL_H
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <sys/ioctl.h>
#  include <sys/devpoll.h>
# endif /* HAVE_SYS_DEVPOLL_H */
#elif defined( HAVE_POLL_H )
#  include <poll.h>
#elif defined( HAVE_SYS_POLL_H )
#  include <sys/poll.h>
#else
	/* nothing */
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

#include "fdwatch.h"

#define FDWATCH_DEBUG	1	/* enable debug-code */
#ifdef notdef
#endif

#ifdef F_SETFD
#ifndef FD_CLOEXEC
#define FD_CLOEXEC	1	/* fcntl(2): set close-on-exec bit */
#endif /* F_SETFD */
#endif /* !FD_CLOEXEC */

#ifdef HAVE_SELECT
#ifndef FD_SET
#define NFDBITS         32
#define FD_SETSIZE      32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char*)(p), sizeof(*(p)))
#endif /* !FD_SET */
#endif /* HAVE_SELECT */

static int  nrevents;	/* n. of returned events from fdwatch() */
static int  nfds;	/* active fd(s) currently watched in array(s) */
static int  nfiles;	/* max. number of files allowed by system */
static int  fatal_errno;/* fatal errno returned by fdwatch() */
static long nfderrs;	/* n. of fd add, mod, del errors */
static long neverrs;	/* n. of event errors */
static long nwatches;	/* n. of fdwatch calls */
static int* fd_rw;
static void** fd_data;

static void fdwatch_free_data( void );

#if   defined( HAVE_KQUEUE )
static int kqueue_init( int nfiles );
static int kqueue_add_fd( int fd, int rw );
static int kqueue_mod_fd( int fd, int rw );
static int kqueue_del_fd( int fd );
static int kqueue_sync( void );
static int kqueue_watch( long timeout_msecs );
static int kqueue_check_fd( int fd );
static int kqueue_get_fd( int ridx );
#elif defined( HAVE_EPOLL )
static int epoll_init( int nfiles );
static int epoll_add_fd( int fd, int rw );
static int epoll_mod_fd( int fd, int rw );
static int epoll_del_fd( int fd );
static int epoll_watch( long timeout_msecs );
static int epoll_check_fd( int fd );
static int epoll_get_fd( int ridx );
#elif defined( HAVE_DEVPOLL )
static int devpoll_init( int nfiles );
static int devpoll_add_fd( int fd, int rw );
static int devpoll_mod_fd( int fd, int rw );
static int devpoll_del_fd( int fd );
static int devpoll_sync( void );
static int devpoll_watch( long timeout_msecs );
static int devpoll_check_fd( int fd );
static int devpoll_get_fd( int ridx );
#elif defined( HAVE_POLL )
static int poll_init( int nfiles );
static int poll_add_fd( int fd, int rw );
static int poll_mod_fd( int fd, int rw );
static int poll_del_fd( int fd );
static int poll_watch( long timeout_msecs );
static int poll_check_fd( int fd );
static int poll_get_fd( int ridx );
#elif defined( HAVE_SELECT )
static int select_init( int nfiles );
static int select_add_fd( int fd, int rw );
static int select_mod_fd( int fd, int rw );
static int select_del_fd( int fd );
static int select_watch( long timeout_msecs );
static int select_check_fd( int fd );
static int select_get_fd( int ridx );
static int select_get_maxfd( void );
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */


/* Routines. */

/* Free allocated data */
static void
fdwatch_free_data( void )
    {
    nfds    = 0;
    nfiles  = 0;
    free( fd_rw );
    free( fd_data );
    fd_rw   = NULL;
    fd_data = NULL;
    }


/* Initialize the fdwatch data structures and figure out
** how many file descriptors the system allows.
** Returns -1 on failure.
*/
int
fdwatch_init( void )
    {
#ifdef RLIMIT_NOFILE
    struct rlimit rl;
#endif /* RLIMIT_NOFILE */

    /* Check if the package has already been initialized */
    if ( nfiles != 0 )
	return nfiles;

    /* Figure out how many fd's we can have. */
    nfiles = getdtablesize();
    if ( nfiles < 1 )
	{
	nfiles = 0;
	return -1;
	}

#ifdef RLIMIT_NOFILE
    /* If we have getrlimit(), use that, and attempt to raise the limit. */
    if ( getrlimit( RLIMIT_NOFILE, &rl ) == 0 )
	{
	nfiles = rl.rlim_cur;
	if ( rl.rlim_max == RLIM_INFINITY )
	    rl.rlim_cur = 8192;         /* arbitrary */
	else if ( rl.rlim_max > rl.rlim_cur )
	    rl.rlim_cur = rl.rlim_max;
	if ( setrlimit( RLIMIT_NOFILE, &rl ) == 0 )
	    nfiles = rl.rlim_cur;
	}
#endif /* RLIMIT_NOFILE */

#if defined( HAVE_SELECT ) && ! ( defined( HAVE_POLL ) || defined( HAVE_DEVPOLL ) || defined( HAVE_EPOLL ) || defined( HAVE_KQUEUE ) )
    /* If we use select(), then we must limit ourselves to FD_SETSIZE. */
    nfiles = MIN( nfiles, FD_SETSIZE );
#endif /* HAVE_SELECT && ! ( HAVE_POLL || HAVE_DEVPOLL || HAVE_EPOLL || HAVE_KQUEUE ) */

    /* Initialize the fdwatch data structures. */
    nrevents = 0;
    nfds     = 0;
    nfderrs  = 0;
    neverrs  = 0;
    nwatches = 0;
    fd_rw   = (int*)   calloc( nfiles, sizeof(int) );
    fd_data = (void**) calloc( nfiles, sizeof(void*) );
    if ( fd_rw == (int*) 0 || fd_data == (void**) 0 )
	{
	fdwatch_free_data();
	return -1;
	}
#if FDW_NORW != 0
    /* we have to explicitely initialize fd read/write status to no r/w */
    {
    int	i;
    for ( i = 0; i < nfiles; ++i )
	fd_rw[i] = FDW_NORW;
    }
#endif
#if    defined( HAVE_KQUEUE )
    if ( kqueue_init( nfiles ) == -1 )
	{
	fdwatch_free_data();
	return -1;
	}
#elif defined( HAVE_EPOLL )
    if ( epoll_init( nfiles ) == -1 )
	{
	fdwatch_free_data();
	return -1;
	}
#elif defined( HAVE_DEVPOLL )
    if ( devpoll_init( nfiles ) == -1 )
	{
	fdwatch_free_data();
	return -1;
	}
#elif defined( HAVE_POLL )
    if ( poll_init( nfiles ) == -1 )
	{
	fdwatch_free_data();
	return -1;
	}
#elif defined( HAVE_SELECT )
    if ( select_init( nfiles ) == -1 )
	{
	fdwatch_free_data();
	return -1;
	}
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

    return nfiles;
    }


/* Figure out how many file descriptors the system allows, and
** initialize the fdwatch data structures.  Returns -1 on failure.
*/
int
fdwatch_get_nfiles( void )
    {
    if ( nfiles > 0 )
	return nfiles;
    if ( fdwatch_init() < 1 || nfiles < 1 )
	return -1;
    return nfiles;
    }


/* Figure out how many file descriptors are in active set.
** initialize the fdwatch data structures.  Returns -1 on failure.
*/
int
fdwatch_get_nfds( void )
    {
    if ( nfiles > 0 )
	return nfds;
    if ( fdwatch_init() < 1 || nfiles < 1 )
	return -1;
    return nfds;
    }


/* Returns the number of event errors (which should be considered fatal) */
long
fdwatch_get_neverrs( void )
    {
    return neverrs;
    }


/* Returns the number of fd errors happened in add, mod or del fd. */
long
fdwatch_get_nfderrs( void )
    {
    return nfderrs;
    }


/* Check whether an fd is in active set.
** Returns 0 (FALSE) or 1 (TRUE).
*/
int
fdwatch_is_fd( int fd )
    {
    if ( fd < 0 || fd >= nfiles )
	return 0;
    if ( fd_rw[fd] == FDW_NORW )
	return 0;
    return 1;
    }


/* Returns the fdwatch state of passed fd:
**      FDW_NORW
**      FDW_READ
**      FDW_WRITE
*/
int
fdwatch_get_fdw( int fd )
    {
    if ( fd < 0 || fd >= nfiles )
	return FDW_NORW;
    return fd_rw[fd];
    }


/* Add a descriptor to the watch list.
** Returns -1 on failure.
*/
int
fdwatch_add_fd( int fd, void* client_data, int rw )
    {
    if ( fd < 0 || fd >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad fd (%d) passed to fdwatch_add_fd!", fd );
#endif
	++nfderrs;
	errno = EBADF;
	return -1;
	}

    if ( fd_rw[fd] != FDW_NORW )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fd_rw[%d] is not free: %d in fdwatch_add_fd!",
			fd, fd_rw[fd] );
#endif
	++nfderrs;
	errno = EEXIST;
	return -1;
	}

    if ( rw != FDW_READ &&
	 rw != FDW_WRITE )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fd (%d): invalid rw %d in fdwatch_add_fd!", fd, rw );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
#if   defined( HAVE_KQUEUE )
    if ( kqueue_add_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_EPOLL )
    if ( epoll_add_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_DEVPOLL )
    if ( devpoll_add_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_POLL )
    if ( poll_add_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_SELECT )
    if ( select_add_fd( fd, rw ) != 0 )
	return -1;
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

    ++nfds;
    fd_rw[fd] = rw;
    fd_data[fd] = client_data;
    return 0;
    }


/* Modify a descriptor in the watch list.
** Returns -1 on failure.
*/
int
fdwatch_mod_fd( int fd, void* client_data, int rw )
    {
    if ( fd < 0 || fd >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad fd (%d) passed to fdwatch_mod_fd!", fd );
#endif
	++nfderrs;
	errno = EBADF;
	return -1;
	}

    if ( fd_rw[fd] != FDW_READ &&
	 fd_rw[fd] != FDW_WRITE )
	{    /* this fd is not active */
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR,
		"fd (%d), passed to fdwatch_mod_fd, does not exists: fd_rw %d!",
		fd, fd_rw[fd] );
#endif
	++nfderrs;
	errno = ENOENT;
	return -1;
	}

    if ( rw != FDW_READ &&
	 rw != FDW_WRITE )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fd (%d): invalid rw %d in fdwatch_mod_fd!", fd, rw );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}

    if ( fd_rw[fd] == rw )
	{
	/* fd is already in required mode */
	if ( fd_data[fd] != client_data )
	     fd_data[fd]  = client_data;
	return 0;
	}

#if   defined( HAVE_KQUEUE )
    if ( kqueue_mod_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_EPOLL )
    if ( epoll_mod_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_DEVPOLL )
    if ( devpoll_mod_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_POLL )
    if ( poll_mod_fd( fd, rw ) != 0 )
	return -1;
#elif defined( HAVE_SELECT )
    if ( select_mod_fd( fd, rw ) != 0 )
	return -1;
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

    fd_rw[fd] = rw;
    fd_data[fd] = client_data;
    return 0;
    }


/* Remove a descriptor from the watch list.
** Returns -1 on failure.
*/
int
fdwatch_del_fd( int fd )
    {
    if ( fd < 0 || fd >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad fd (%d) passed to fdwatch_del_fd!", fd );
#endif
	++nfderrs;
	errno = EBADF;
	return -1;
	}

    if ( fd_rw[fd] != FDW_READ &&
	 fd_rw[fd] != FDW_WRITE )
	{    /* this fd is not active */
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR,
		"fd (%d), passed to fdwatch_del_fd, does not exists: fd_rw %d!",
		fd, fd_rw[fd] );
#endif
	++nfderrs;
	errno = ENOENT;
	return -1;
	}

#if   defined( HAVE_KQUEUE )
    if ( kqueue_del_fd( fd ) != 0 )
	return -1;
#elif defined( HAVE_EPOLL )
    if ( epoll_del_fd( fd ) != 0 )
	return -1;
#elif defined( HAVE_DEVPOLL )
    if ( devpoll_del_fd( fd ) != 0 )
	return -1;
#elif defined( HAVE_POLL )
    if ( poll_del_fd( fd ) != 0 )
	return -1;
#elif defined( HAVE_SELECT )
    if ( select_del_fd( fd ) != 0 )
	return -1;
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

    --nfds;
    fd_rw[fd]   = FDW_NORW;
    fd_data[fd] = (void*) 0;
    return 0;
    }


/* Sync the buffered watch events.  It is useful to remove pending
** watched files that are not automatically removed when they are closed.
** Return value is 0 if successful or -1 on errors.
*/
int
fdwatch_sync( void )
    {
#if defined( HAVE_KQUEUE )
    return kqueue_sync();
#elif defined( HAVE_EPOLL )
    return 0;
#elif defined( HAVE_DEVPOLL )
    return devpoll_sync();
#elif defined( HAVE_POLL )
    return 0;
#elif defined( HAVE_SELECT )
    return 0;
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */
    }


/* Do the watch.  Return value is the number of descriptors that are ready,
** or 0 if the timeout expired, or -1 on errors.  A timeout of INFTIM means
** wait indefinitely.
*/
int
fdwatch( long timeout_msecs )
    {
    ++nwatches;
#if   defined( HAVE_KQUEUE )
    nrevents = kqueue_watch( timeout_msecs );
#elif defined( HAVE_EPOLL )
    nrevents = epoll_watch( timeout_msecs );
#elif defined( HAVE_DEVPOLL )
    nrevents = devpoll_watch( timeout_msecs );
#elif defined( HAVE_POLL )
    nrevents = poll_watch( timeout_msecs );
#elif defined( HAVE_SELECT )
    nrevents = select_watch( timeout_msecs );
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */
    return nrevents;
    }


/* Check if a descriptor was ready. */
int
fdwatch_check_fd( int fd )
    {
    if ( fd < 0 || fd >= nfiles )
	{
	++nfderrs;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad fd (%d) passed to fdwatch_check_fd!", fd );
#endif
	return 0;
	}

    if ( fd_rw[fd] == FDW_NORW )
	return 0;

#if   defined( HAVE_KQUEUE )
    return kqueue_check_fd( fd );
#elif defined( HAVE_EPOLL )
    return epoll_check_fd( fd );
#elif defined( HAVE_DEVPOLL )
    return devpoll_check_fd( fd );
#elif defined( HAVE_POLL )
    return poll_check_fd( fd );
#elif defined( HAVE_SELECT )
    return select_check_fd( fd );
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */
    }


void*
fdwatch_get_client_data( int ridx )
    {
    int fd;
#if   defined( HAVE_KQUEUE )
    fd = kqueue_get_fd( ridx );
#elif defined( HAVE_EPOLL )
    fd = epoll_get_fd( ridx );
#elif defined( HAVE_DEVPOLL )
    fd = devpoll_get_fd( ridx );
#elif defined( HAVE_POLL )
    fd = poll_get_fd( ridx );
#elif defined( HAVE_SELECT )
    fd = select_get_fd( ridx );
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

    if ( fd < 0 || fd >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR,
	"bad fd (%d), got from ridx %d passed to fdwatch_get_client_data!",
		fd, ridx );
#endif
	++nfderrs;
	errno = EINVAL;
	return (void*) 0;
	}
    return fd_data[fd];
    }


/* Generate debugging statistics syslog message. */
void
fdwatch_logstats( long secs )
    {
    const
    char* which =
#if   defined( HAVE_KQUEUE )
	"kevent";
#elif defined( HAVE_EPOLL )
	"epoll";
#elif defined( HAVE_DEVPOLL )
	"devpoll";
#elif defined( HAVE_POLL )
	"poll";
#elif defined( HAVE_SELECT )
	"select";
#else
# error Unknown fdwatch interface !
#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */

    if ( secs > 0 )
	syslog( ( (nfderrs+neverrs) ? LOG_NOTICE : LOG_INFO),
	"  fdwatch - %ld %s(s) (%g/sec), %ld fd-errors, %ld ev-errors",
		nwatches, which, (float) nwatches / secs, nfderrs, neverrs );
    nfderrs  = 0;
    neverrs  = 0;
    nwatches = 0;
    }


#if   defined( HAVE_KQUEUE )

#define FDW_MAX_KQEVENTS	131072	/* max. number of change events */
#define FDW_MIN_KQEVENTS	32	/* min. number of change events */

static short kqrw2evfilter[FDW_MAXRW+1];
static struct kevent* kqevents;
static int maxkqevents;
static int nkqevents;		/* events to add / delete */
static struct kevent* kqrevents;
static struct kevent* kqrevents2;
static int* kqrfdidx;
static int kq;


static int
kqueue_init( int nfiles )
    {
    if ( nfiles < FDW_MIN_KQEVENTS )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "kqueue_init: nfiles %d < %d",
		nfiles, FDW_MIN_KQEVENTS );
#endif
	errno = EINVAL;
	return -1;
	}

    kq = kqueue();
    if ( kq == -1 )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "kqueue() - %m" );
#endif
	return -1;
	}

    /* initialize filter mapper */
    kqrw2evfilter[FDW_READ]  = EVFILT_READ;
    kqrw2evfilter[FDW_WRITE] = EVFILT_WRITE;

    nkqevents = 0;
    maxkqevents = nfiles;

    /* allocate arrays */
    kqevents  = (struct kevent*) calloc( maxkqevents, sizeof(struct kevent) );
    kqrevents = (struct kevent*) calloc( nfiles,      sizeof(struct kevent) );
    kqrevents2= (struct kevent*) calloc( maxkqevents, sizeof(struct kevent) );
    kqrfdidx  = (int*)           calloc( nfiles,      sizeof(int) );
    if ( kqevents   == (struct kevent*) 0 ||
	 kqrevents  == (struct kevent*) 0 ||
	 kqrevents2 == (struct kevent*) 0 ||
	 kqrfdidx   == (int*) 0 )
	{
	int errno0 = errno;
	free( kqevents );
	free( kqrevents );
	free( kqrevents2 );
	free( kqrfdidx );
	kqevents   = (struct kevent*) 0;
	kqrevents  = (struct kevent*) 0;
	kqrevents2 = (struct kevent*) 0;
	kqrfdidx   = (int*) 0;
	close( kq );
	kq = -1;
	errno = errno0;
	return -1;
	}
    /* leave space in array for last bad fd marker */
    maxkqevents -= 2;
    return 0;
    }


/* We assume that add-del events are grouped in couples
** (no add-add or del-del events).
*/
static int
kqueue_add_fd( int fd, int rw )
    {
    if ( nkqevents >= maxkqevents )
	{
	if ( kqueue_sync() != 0 )
	    return -1;
	}
    kqevents[nkqevents].ident = fd;
    kqevents[nkqevents].flags = EV_ADD;
    kqevents[nkqevents].filter = kqrw2evfilter[rw];
    ++nkqevents;
    return 0;
}


/* We assume that add-del events are grouped in couples
** (no add-add or del-del events).
*/
static int
kqueue_mod_fd( int fd, int rw )
    {
    if ( nkqevents + 1 >= maxkqevents )
	{
	if ( kqueue_sync() != 0 )
	    return -1;
	}
    kqevents[nkqevents].ident = fd;
    kqevents[nkqevents].flags = EV_DELETE;
    kqevents[nkqevents].filter = kqrw2evfilter[ fd_rw[fd] ];
    ++nkqevents;

    kqevents[nkqevents].ident = fd;
    kqevents[nkqevents].flags = EV_ADD;
    kqevents[nkqevents].filter = kqrw2evfilter[rw];
    ++nkqevents;

    return 0;
}


/* We assume that add-del events are grouped in couples
** (no add-add or del-del events).
*/
static int
kqueue_del_fd( int fd )
    {
    if ( nkqevents >= maxkqevents )
	{
	/* write buffered events */
	if ( kqueue_sync() != 0 )
	    return -1;
	}
    kqevents[nkqevents].ident = fd;
    kqevents[nkqevents].flags = EV_DELETE;
    kqevents[nkqevents].filter = kqrw2evfilter[ fd_rw[fd] ];
    ++nkqevents;
    return 0;
    }


static int
kqueue_sync( void )
    {
    int	r = -1;			/* must be an invalid fd value */
    struct timespec ts;

    if ( nkqevents < 1 )
	return 0;

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    /* Add an invalid fd to stop processing at the end of changelist
    ** because we don't want to return I/O events in kqrevents2.
    ** NOTE: here kqueue could have a better interface
    **       to force the processing of only changelist (kqevents[]).
    */
    kqevents[nkqevents].ident = r;	/* invalid file */
    kqevents[nkqevents].flags = EV_DELETE;
    kqevents[nkqevents].filter = kqrw2evfilter[ FDW_READ ];

    ++nkqevents;

    /* There must be enough space in kqrevents2 to hold errors in kqevents. */
    r = kevent( kq, kqevents, nkqevents, kqrevents2, nkqevents, &ts );

    --nkqevents;		/* remove last invalid fd */

    /* EINTR can happen only after changelist has been processed */
    if ( r < 0 && errno != EINTR )
	{
	++neverrs;
	fatal_errno = errno;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "kqueue_sync - errno %d - %m", errno );
#endif
	return -1;
	}

    if ( r < 0 )
	{
	/* EINTR, it's harmless (well, it should not even happen here) */
	 r = 0;
	}
    else
    if ( r > 0 )
	{
	/* One or more fd events could not be registered,
	** the last one is always the dummy fd we added above.
	*/
	--r;
	if ( r > 0 )
	    {
#ifdef FDWATCH_CHK_EV_ERROR
	    int i;
	    long neverrs0 = neverrs;
	    /* One or more fd events could not be registered,
	    ** this is a real fatal error only if event.data != EBADF.
	    ** EBADF is normal if this function is not called
	    ** just before each close.
	    */
	    for ( i = 0; i < r; ++i )
		{
		if ( ( kqrevents2[i].flags & EV_ERROR ) == 0 )
		    continue;
		if (   kqrevents2[i].data == EBADF )
		    continue;
		fatal_errno = (int) kqrevents2[i].data;
		++neverrs;
		}
	    if ( neverrs0 != neverrs )
		{
#ifdef FDWATCH_DEBUG
		syslog( LOG_ERR,
		"kqueue_sync: %d / %d events could not be registered!",
		(int) (neverrs - neverrs0), nkqevents );
#endif /* FDWATCH_DEBUG */
		r = -1;
		}
	    else
		r = 0;
#else
	    r = 0;
#endif /* FDWATCH_CHK_EV_ERROR */
	    }
	}
    /* reset events,
    */
    nkqevents = 0;

    return r;
    }


static int
kqueue_watch( long timeout_msecs )
    {
    int i, r;
    struct timespec ts, *pts = (struct timespec*) 0;

    if ( fatal_errno > 0 )
	{ /* bad errors happened somewhere */
	errno = fatal_errno;
	fatal_errno = 0;
	return -2;
	}

    if ( timeout_msecs != INFTIM )
	{
	pts = &ts;
	pts->tv_sec = timeout_msecs / 1000L;
	pts->tv_nsec = ( timeout_msecs % 1000L ) * 1000000L;
	}

    r = kevent( kq, kqevents, nkqevents, kqrevents, nfiles, pts );

    /* errno == EINTR is handled by caller.
    ** NOTE: EINTR is returned only after changelist has been processed.
    */
    if ( r == -1 && errno != EINTR )
	return -1;

    /* OK, reset events */
    nkqevents = 0;

    for ( i = 0; i < r; ++i )
	kqrfdidx[kqrevents[i].ident] = i;

    return r;
    }


static int
kqueue_check_fd( int fd )
    {
    int ridx = kqrfdidx[fd];

    if ( ridx < 0 || ridx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad ridx (%d) in kqueue_check_fd!", ridx );
#endif
	++nfderrs;
	errno = EINVAL;
	return 0;
	}
    /* No need to syslog here, it's OK returning 0 */
    if ( ridx >= nrevents )
	return 0;
    if ( kqrevents[ridx].ident != fd )
	return 0;
    if ( kqrevents[ridx].flags & EV_ERROR )
	return 0;
    /* caller already checked for FDW_READ or FDW_WRITE */
    return( kqrevents[ridx].filter == kqrw2evfilter[ fd_rw[fd] ] );
    }


static int
kqueue_get_fd( int ridx )
    {
    if ( ridx < 0 || ridx >= nrevents )
	return -1;
    return kqrevents[ridx].ident;
    }
	/* HAVE_KQUEUE */


#elif defined( HAVE_EPOLL )

static int  epollrw2evt[FDW_MAXRW+1];
static int  epfd;
static int *eprfdidx;
static struct epoll_event *repollfds;


static int
epoll_init( int nfiles )
    {
    epfd = epoll_create( nfiles );
    if ( epfd == -1 )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "epoll_create( %d ) - %m", nfiles );
#endif
	return -1;
	}
    /* set close-on-exec */
    if ( fcntl( epfd, F_SETFD, FD_CLOEXEC ) == -1 )
	{
	int errno0 = errno;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fcntl( epfd, F_SETFD ) - %m" );
#endif
	close( epfd );
	epfd = -1;
	errno = errno0;
	return -1;
	}

    epollrw2evt[FDW_READ]  = EPOLLIN;
    epollrw2evt[FDW_WRITE] = EPOLLOUT;

    /* allocate arrays */
    repollfds = (struct epoll_event*)
				calloc( nfiles, sizeof(struct epoll_event) );
    eprfdidx = (int*)           calloc( nfiles, sizeof(int) );
    if ( repollfds == (struct epoll_event*) 0 ||
	 eprfdidx  == (int*) 0 )
	{
	int errno0 = errno;
	free( repollfds );
	free( eprfdidx );
	repollfds = (struct epoll_event*) 0;
	eprfdidx = (int*) 0;
	close( epfd );
	epfd = -1;
	errno = errno0;
	return -1;
	}
    return 0;
    }


static int
epoll_add_fd( int fd, int rw )
    {
    struct epoll_event ev;

    ev.data.fd = fd;
    ev.events = epollrw2evt[rw];
    /* this cannot set errno to EINTR */
    if ( epoll_ctl( epfd, EPOLL_CTL_ADD, fd, &ev ) == -1 )
	{
	++neverrs;
	fatal_errno = errno;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "epoll_ctl( %d, ADD ) - %m!", fd );
#endif
	return -1;
	}
    return 0;
    }


static int
epoll_mod_fd( int fd, int rw )
    {
    struct epoll_event ev;

    ev.data.fd = fd;
    ev.events = epollrw2evt[rw];
    /* this cannot set errno to EINTR */
    if ( epoll_ctl( epfd, EPOLL_CTL_MOD, fd, &ev ) == -1 )
	{
	++neverrs;
	fatal_errno = errno;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "epoll_ctl( %d, MOD ) - %m!", fd );
#endif
	return -1;
	}
    return 0;
    }


static int
epoll_del_fd( int fd )
    {
    struct epoll_event ev;

    ev.data.fd = 0;	/* unused */
    ev.events  = 0;	/* unused */
    /* this cannot set errno to EINTR */
    if ( epoll_ctl( epfd, EPOLL_CTL_DEL, fd, &ev ) == -1 )
	{
	++neverrs;
	fatal_errno = errno;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "epoll_ctl( %d, DEL ) - %m!", fd );
#endif
	return -1;
	}
    return 0;
    }


static int
epoll_watch( long timeout_msecs )
    {
    int i, r;

    if ( fatal_errno > 0 )
	{ /* bad errors happened somewhere */
	errno = fatal_errno;
	fatal_errno = 0;
	return -2;
	}
    r = epoll_wait( epfd, repollfds, nfiles, (int) timeout_msecs );
    if ( r == -1 )
	return -1;
    for ( i = 0; i < r; ++i )
	eprfdidx[repollfds[i].data.fd] = i;
    return r;
    }


static int
epoll_check_fd( int fd )
    {
    int ridx = eprfdidx[fd];

    if ( ridx < 0 || ridx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad ridx (%d) in epoll_check_fd!", ridx );
#endif
	++nfderrs;
	errno = EINVAL;
	return 0;
	}

    /* No need to syslog here, it's OK returning 0 */
    if ( ridx >= nrevents || repollfds[ridx].data.fd != fd )
	return 0;

    /* if ( repollfds[ridx].events & EPOLLERR ) return 0; */

    /* caller already checked for FDW_READ or FDW_WRITE */
    return repollfds[ridx].events &
		( epollrw2evt[ fd_rw[fd] ] | EPOLLERR | EPOLLHUP );
    }


static int
epoll_get_fd( int ridx )
    {
    if ( ridx < 0 || ridx >= nrevents )
	return -1;
    return repollfds[ridx].data.fd;
    }
	/* HAVE_EPOLL */


#elif defined( HAVE_DEVPOLL )


static short  pollrw2evt[FDW_MAXRW+1];
static struct pollfd* pollfds;
static int npollfds;
static struct pollfd* rpollfds;
static int* dprfdidx;
static int  dpfd;


static int
devpoll_init( int nfiles )
    {
    dpfd = open( "/dev/poll", O_RDWR );
    if ( dpfd == -1 )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "open(\"/dev/poll\") - %m" );
#endif
	return -1;
	}
    /* set close-on-exec */
    if ( fcntl( dpfd, F_SETFD, FD_CLOEXEC ) == -1 )
	{
	int errno0 = errno;
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fcntl(\"/dev/poll\", F_SETFD) - %m" );
#endif
	close( dpfd );
	dpfd = -1;
	errno = errno0;
	return -1;
	}

    pollrw2evt[FDW_READ]  = POLLIN;
    pollrw2evt[FDW_WRITE] = POLLOUT;

    /* allocate arrays */
    pollfds  = (struct pollfd*) calloc( nfiles, sizeof(struct pollfd) );
    rpollfds = (struct pollfd*) calloc( nfiles, sizeof(struct pollfd) );
    dprfdidx = (int*)           calloc( nfiles, sizeof(int) );
    if ( pollfds  == (struct pollfd*) 0 ||
	 rpollfds == (struct pollfd*) 0 ||
	 dprfdidx == (int*) 0 )
	{
	int errno0 = errno;
	free( pollfds );
	free( rpollfds );
	free( dprfdidx );
	pollfds  = (struct pollfd*) 0;
	rpollfds = (struct pollfd*) 0;
	dprfdidx = (int*) 0;
	close( dpfd );
	dpfd = -1;
	errno = errno0;
	return -1;
	}
    return 0;
    }


static int
devpoll_add_fd( int fd, int rw )
    {
    if ( npollfds >= nfiles )
	{
	/* write buffered events */
	if ( devpoll_sync() != 0 )
	    return -1;
	}
    pollfds[npollfds].fd = fd;
    pollfds[npollfds].events = pollrw2evt[rw];
    pollfds[npollfds].revents = 0;
    ++npollfds;
    return 0;
    }


static int
devpoll_mod_fd( int fd, int rw )
    {
    if ( npollfds + 1 >= nfiles )
	{
	/* write buffered events */
	if ( devpoll_sync() != 0 )
	    return -1;
	}

    pollfds[npollfds].fd = fd;
    pollfds[npollfds].events = POLLREMOVE;
    pollfds[npollfds].revents = 0;
    ++npollfds;

    pollfds[npollfds].fd = fd;
    pollfds[npollfds].events = pollrw2evt[rw];
    pollfds[npollfds].revents = 0;
    ++npollfds;

    return 0;
    }


static int
devpoll_del_fd( int fd )
    {
    if ( npollfds >= nfiles )
	{
	/* write buffered events */
	if ( devpoll_sync() != 0 )
	    return -1;
	}
    pollfds[npollfds].fd = fd;
    pollfds[npollfds].events = POLLREMOVE;
    pollfds[npollfds].revents = 0;
    ++npollfds;
    return 0;
    }


static int
devpoll_sync( void )
    {

    if ( npollfds > 0 )
	{
	ssize_t r = 0;
	size_t  cnt = sizeof( struct pollfd ) * npollfds;

	/* write changes to the watched set */
	do
	    {
	    r = write( dpfd, pollfds, cnt );
	    }
	while ( r == -1 && ( errno == EINTR || errno == EAGAIN ) );

	if ( r != (ssize_t) cnt )
	    {
	    int errno0 = errno;
	    ++neverrs;
#ifdef FDWATCH_DEBUG
	    syslog( LOG_ERR,
		"bad write(), r %d != %u cnt, in devpoll_sync - %m!", r, cnt );
#endif
	    if ( r >= 0 )
		errno = E2BIG;
	    else
		errno = errno0;
	    fatal_errno = errno;
	    return -1;
	    }
	}
    /* reset fd counter */
    npollfds = 0;

    return 0;
    }


static int
devpoll_watch( long timeout_msecs )
    {
    int i, r;
    struct dvpoll dopoll = { 0 };

    /* write buffered events */
    if ( devpoll_sync() != 0 )
	return -1;

    if ( fatal_errno > 0 )
	{ /* bad errors happened somewhere */
	errno = fatal_errno;
	fatal_errno = 0;
	return -2;
	}

    /* poll active set of file descriptors */
    dopoll.dp_timeout = (int) timeout_msecs;
    dopoll.dp_nfds    = nfiles;
    dopoll.dp_fds     = rpollfds;
    r = ioctl( dpfd, DP_POLL, &dopoll );
    if ( r == -1 )
	return -1;

    for ( i = 0; i < r; ++i )
	dprfdidx[rpollfds[i].fd] = i;

    return r;
    }


static int
devpoll_check_fd( int fd )
    {
    int ridx = dprfdidx[fd];

    if ( ridx < 0 || ridx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad ridx (%d) in devpoll_check_fd!", ridx );
#endif
	++nfderrs;
	errno = EINVAL;
	return 0;
	}

    /* No need to syslog here, it's OK returning 0 */
    if ( ridx >= nrevents || rpollfds[ridx].fd != fd )
	return 0;

    /* if ( rpollfds[ridx].revents & POLLERR ) return 0; */

    /* caller already checked for FDW_READ or FDW_WRITE */
    return rpollfds[ridx].revents &
		( pollrw2evt[ fd_rw[fd] ] | POLLERR | POLLHUP | POLLNVAL );
    }


static int
devpoll_get_fd( int ridx )
    {
    if ( ridx < 0 || ridx >= nrevents )
	return -1;
    return rpollfds[ridx].fd;
    }
	/* HAVE_DEVPOLL */


#elif defined( HAVE_POLL )

static short  pollrw2evt[FDW_MAXRW+1];
static struct pollfd* pollfds;
static int npollfds;
static int* poll_fdidx;
static int* poll_rfdidx;


static int
poll_init( int nfiles )
    {
    pollrw2evt[FDW_READ]  = POLLIN;
    pollrw2evt[FDW_WRITE] = POLLOUT;
    pollfds     = (struct pollfd*) calloc( nfiles, sizeof(struct pollfd) );
    poll_fdidx  = (int*)           calloc( nfiles, sizeof(int) );
    poll_rfdidx = (int*)           calloc( nfiles, sizeof(int) );
    if ( pollfds == (struct pollfd*) 0 ||
	 poll_fdidx == (int*) 0 ||
	 poll_rfdidx == (int*) 0 )
	{
	free( pollfds );
	free( poll_fdidx );
	free( poll_rfdidx );
	pollfds     = (struct pollfd*) 0;
	poll_fdidx  = (int*) 0;
	poll_rfdidx = (int*) 0;
	return -1;
	}
    return 0;
    }


static int
poll_add_fd( int fd, int rw )
    {
    if ( npollfds >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "npollfds %d >= %d nfiles, rw %d, in poll_add_fd!",
		npollfds, nfiles, rw );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    pollfds[npollfds].fd = fd;
    pollfds[npollfds].events = pollrw2evt[rw];
    pollfds[npollfds].revents = 0;
    poll_fdidx[fd] = npollfds;
    ++npollfds;
    return 0;
    }


static int
poll_mod_fd( int fd, int rw )
    {
    int idx = poll_fdidx[fd];

    if ( idx < 0 || idx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fd %d, bad idx (%d) in poll_mod_fd!", fd, idx );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    if ( npollfds <= 0 )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "npollfds (%d <= 0) in poll_mod_fd!", npollfds );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    if ( pollfds[idx].fd != fd )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "pollfds[%d].fd: %d != %d in poll_mod_fd!",
		idx, pollfds[idx].fd, fd );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    pollfds[idx].events = pollrw2evt[rw];
    pollfds[idx].revents = 0;

    return 0;
    }


static int
poll_del_fd( int fd )
    {
    int idx = poll_fdidx[fd];

    if ( idx < 0 || idx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "fd %d, bad idx (%d) in poll_del_fd!", fd, idx );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    if ( npollfds <= 0 )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "npollfds (%d <= 0) in poll_del_fd!", npollfds );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    --npollfds;
    if ( npollfds != idx )
	{
	/* copy / move last element */
	pollfds[idx] = pollfds[npollfds];
	poll_fdidx[pollfds[idx].fd] = idx;
	}
    /* initialize last element */
    pollfds[npollfds].fd      = -1;
    pollfds[npollfds].revents = 0;

    return 0;
    }


static int
poll_watch( long timeout_msecs )
    {
    int r, ridx, i;

    r = poll( pollfds, npollfds, (int) timeout_msecs );
    if ( r == -1 )
	return -1;

    ridx = 0;
    for ( i = 0; i < npollfds; ++i )
	if ( pollfds[i].revents &
		( POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL ) )
	    poll_rfdidx[ridx++] = pollfds[i].fd;

    return ridx;	/* not r */
    }


static int
poll_check_fd( int fd )
    {
    int fdidx = poll_fdidx[fd];

    if ( fdidx < 0 || fdidx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad fdidx (%d) in poll_check_fd!", fdidx );
#endif
	++nfderrs;
	errno = EINVAL;
	return 0;
	}

    /* NOTE: no need to check if ( pollfds[fdidx].fd != fd ) then error */
    /* because poll has the same number of input and output elements */

    /* caller already checked for FDW_READ or FDW_WRITE */
    return pollfds[fdidx].revents &
		( pollrw2evt[ fd_rw[fd] ] | POLLERR | POLLHUP | POLLNVAL );
    }


static int
poll_get_fd( int ridx )
    {
    if ( ridx < 0 || ridx >= nrevents )
	return -1;
    return poll_rfdidx[ridx];
    }
	/* HAVE_POLL */


#elif defined( HAVE_SELECT )

static fd_set mast_rw2fdset[FDW_MAXRW+1];
static fd_set work_rw2fdset[FDW_MAXRW+1];
static int* select_fds;
static int* select_fdidx;
static int* select_rfdidx;
static int nselect_fds;
static int maxfd;
static int maxfd_changed;


static int
select_init( int nfiles )
    {

    FD_ZERO( &mast_rw2fdset[FDW_READ] );
    FD_ZERO( &mast_rw2fdset[FDW_WRITE] );

    select_fds    = (int*) calloc( nfiles, sizeof(int) );
    select_fdidx  = (int*) calloc( nfiles, sizeof(int) );
    select_rfdidx = (int*) calloc( nfiles, sizeof(int) );
    if ( select_fds == (int*) 0 ||
	 select_fdidx == (int*) 0 ||
	 select_rfdidx == (int*) 0 )
	{
	free( select_fds );
	free( select_fdidx );
	free( select_rfdidx );
	select_fds    = (int*) 0;
	select_fdidx  = (int*) 0;
	select_rfdidx = (int*) 0;
	return -1;
	}
    nselect_fds = 0;
    maxfd = -1;
    maxfd_changed = 0;
    return 0;
    }


static int
select_add_fd( int fd, int rw )
    {
    if ( nselect_fds >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "nselect_fds (%d >= %d) nfiles in select_add_fd!",
		nselect_fds, nfiles );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    select_fds[nselect_fds] = fd;
    FD_SET( fd, &mast_rw2fdset[rw] );
    if ( fd > maxfd )
	maxfd = fd;
    select_fdidx[fd] = nselect_fds;
    ++nselect_fds;
    return 0;
    }


static int
select_mod_fd( int fd, int rw )
    {
    /* select is already slow, thus no optimization is performed */
    if ( select_del_fd( fd ) != 0 )
	return -1;
    return select_add_fd( fd, rw );
    }


static int
select_del_fd( int fd )
    {
    int idx = select_fdidx[fd];

    if ( idx < 0 || idx >= nfiles )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "bad idx (%d) in select_del_fd!", idx );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    if ( nselect_fds <= 0 )
	{
#ifdef FDWATCH_DEBUG
	syslog( LOG_ERR, "nselect_fds (%d <= 0) in select_del_fd!",
		nselect_fds );
#endif
	++nfderrs;
	errno = EINVAL;
	return -1;
	}
    --nselect_fds;
    if ( nselect_fds != idx )
	{
	select_fds[idx] = select_fds[nselect_fds];
	select_fdidx[select_fds[idx]] = idx;
	}

    FD_CLR( fd, &mast_rw2fdset[FDW_READ] );
    FD_CLR( fd, &mast_rw2fdset[FDW_WRITE] );

    if ( fd >= maxfd )
	maxfd_changed = 1;

    return 0;
    }


static int
select_get_maxfd( void )
    {
    if ( maxfd_changed )
	{
	int i;
	maxfd = -1;
	for ( i = 0; i < nselect_fds; ++i )
	    if ( select_fds[i] > maxfd )
		maxfd = select_fds[i];
	maxfd_changed = 0;
	}
    return maxfd;
    }


static int
select_check_fd( int fd )
    {
    return FD_ISSET( fd, &work_rw2fdset[ fd_rw[fd] ] );
    }


static int
select_watch( long timeout_msecs )
    {
    int mfd;
    int r, i, ridx;

    work_rw2fdset[FDW_READ]  = mast_rw2fdset[FDW_READ];
    work_rw2fdset[FDW_WRITE] = mast_rw2fdset[FDW_WRITE];

    mfd = select_get_maxfd();
    if ( timeout_msecs == INFTIM )
	r = select( mfd + 1,
	    &work_rw2fdset[FDW_READ], &work_rw2fdset[FDW_WRITE], (fd_set*) 0,
	    (struct timeval*) 0 );
    else
	{
	struct timeval timeout;
	timeout.tv_sec = timeout_msecs / 1000L;
	timeout.tv_usec = ( timeout_msecs % 1000L ) * 1000L;
	r = select( mfd + 1,
	    &work_rw2fdset[FDW_READ], &work_rw2fdset[FDW_WRITE], (fd_set*) 0,
	    &timeout );
	}
    if ( r <= 0 )
	return r;

    ridx = 0;
    for ( i = 0; i < nselect_fds; ++i )
	if ( select_check_fd( select_fds[i] ) )
	    {
	    select_rfdidx[ridx++] = select_fds[i];
	    if ( ridx == r )
		break;
	    }

    return ridx;	/* not r */
    }


static int
select_get_fd( int ridx )
    {
    if ( ridx < 0 || ridx >= nrevents )
	return -1;
    return select_rfdidx[ridx];
    }

	/* HAVE_SELECT */

#else

# error Unknown fdwatch interface !

#endif /* KQUEUE, EPOLL, DEVPOLL, POLL, SELECT */
