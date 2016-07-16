/* fdwatch.h - header file for fdwatch package - changes by A.D.F.
**
** This package abstracts the use of the select(), poll(), epoll*() or kevent()
** system calls and eventually the use of /dev/poll interface.
** The basic function of these calls is to watch a set of file descriptors
** for read or write activity.
** select() and kevent() originated in the BSD world,
** poll() came from SysV land, /dev/poll came from Sun "cathedral",
** while epoll*() came from Linux "bazar" 2.6
** and their interfaces are somewhat different.
** fdwatch lets you write your code to a single interface,
** with the portability differences hidden inside the package.
**
** Furthermore, if your system implements more than one interface
** then fdwatch will choose, at compile time (see also Makefile),
** whichever call is most advantageous (likely using this order:
** 1) kevent(); 2) epoll*(); 3) /dev/poll; 4) poll(); 5) select()).
**
** Usage is fairly simple.  Call fdwatch_init() and/or fdwatch_get_nfiles()
** to initialize the package and find out how many file descriptors
** are available;  then each time through your main loop,
** call fdwatch_add_fd() for each of the descriptors you want to watch,
** then call fdwatch() to actually perform the watch.
** After it returns you can check which descriptors are ready via
** fdwatch_check_fd().
**
** If your descriptor set hasn't changed from the last time through
** the loop, you can skip calling fdwatch_del_fd() and fdwatch_add_fd()
** to save a little CPU time.
**
** You can use fdwatch_mod_fd() to change event of interest
** from read to write and viceversa.
**
** Copyright © 1999 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Changes (2003,2004) contributed by A.D.F. <adefacc@tin.it> and others.
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

#ifndef _FDWATCH_H_
#define _FDWATCH_H_

#define FDW_NORW  0
#define FDW_READ  1
#define FDW_WRITE 2
#define FDW_MAXRW 3

#ifndef INFTIM
#define INFTIM -1
#endif /* INFTIM */

/* Initialize the fdwatch data structures and figure out
** how many file descriptors the system allows.
** Returns -1 on failure.
*/
extern int fdwatch_init( void );

/* Figure out how many file descriptors the system allows.
** If needed, it initializes the fdwatch data structures.
** Returns -1 on failure.
*/
extern int fdwatch_get_nfiles( void );

/* Figure out how many file descriptors are in watch list.
** If needed, it initializes the fdwatch data structures.
** Returns -1 on failure.
*/
extern int fdwatch_get_nfds( void );

/* Returns the number of event errors happened since initialization
** or since last fdwatch_logstats() call.
** NOTE: event errors should be considered fatal.
*/
extern long fdwatch_get_neverrs( void );


/* Returns the number of fd errors happened since initialization
** or since last fdwatch_logstats() call.
** NOTE: fd errors (happened in add, mod, del fd) should force program exit.
*/
extern long fdwatch_get_nfderrs( void );


/* Check whether a file descriptor is in watch list.
** Returns TRUE/FALSE.
*/
extern int fdwatch_is_fd( int fd );

/* Returns the watch state of a file descriptor:
**      FDW_NORW
**      FDW_READ
**      FDW_WRITE
*/
extern int fdwatch_get_fdw( int fd );

/* Add a descriptor to the watch list.
** rw is either FDW_READ or FDW_WRITE.
*/
extern int fdwatch_add_fd( int fd, void* client_data, int rw );

/* Change interested event of a descriptor already added to the watch list.
** This is useful to spare a system call when using epoll() on Linux 2.6.
** rw is either FDW_READ or FDW_WRITE.
*/
extern int fdwatch_mod_fd( int fd, void* client_data, int rw );

/* Delete a descriptor from the watch list. */
extern int fdwatch_del_fd( int fd );

/* Sync the buffered watch events.  It is useful to remove watched fd(s)
** before they are closed (if this is not automatically done by system poller).
** Returns 0 if successful, or -1 on errors.
*/
extern int fdwatch_sync( void );

/* Do the watch.  Return value is the number of descriptors that are ready,
** or 0 if the timeout expired, or -1 or -2 on errors.
** A timeout of INFTIM means wait indefinitely whereas 0 means "no wait".
*/
extern int fdwatch( long timeout_msecs );

/* Check if a descriptor was ready. */
extern int fdwatch_check_fd( int fd );

/* Get the client data for an event.  The argument is an index into the
** set of ready descriptors returned by fdwatch().
*/
extern void* fdwatch_get_client_data( int ridx );

/* Generate debugging statistics syslog message. */
extern void fdwatch_logstats( long secs );

#endif /* _FDWATCH_H_ */
