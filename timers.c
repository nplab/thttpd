/* timers.c - simple timer routines
**
** Copyright © 1995,1998,2000 by Jef Poskanzer <jef@acme.com>.
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
#include <stdio.h>
#include <syslog.h>

#include "timers.h"

#ifdef notdef
#define TMR_DEBUG	1		/* enable debug mode */
#endif

#define HASH_NONE -1			/* invalid hash */
#define HASH_SIZE 101			/* prime number */
static Timer* timers[HASH_SIZE];
static Timer* free_timers;
static int alloc_count, active_count, free_count;

ClientData JunkClientData;



static unsigned int
hash( Timer* t )
    {
    /* We can hash on the trigger time, even though it can change over
    ** the life of a timer via either the periodic bit or the tmr_reset()
    ** call.  This is because both of those guys call l_resort(), which
    ** recomputes the hash and moves the timer to the appropriate list.
    */
    return (
	( (unsigned int) t->time.tv_sec  ) ^
	( (unsigned int) t->time.tv_usec ) ) % HASH_SIZE;
    }


static void
l_add( Timer* t )
    {
    int h = t->hash;
    register Timer* t2;
    register Timer* t2prev;

    t2 = timers[h];
    if ( t2 == (Timer*) 0 )
	{
	/* The list is empty. */
	timers[h] = t;
	t->prev = t->next = (Timer*) 0;
	}
    else
	{
	if ( t->time.tv_sec < t2->time.tv_sec ||
	     ( t->time.tv_sec == t2->time.tv_sec &&
	       t->time.tv_usec <= t2->time.tv_usec ) )
	    {
	    /* The new timer goes at the head of the list. */
	    timers[h] = t;
	    t->prev = (Timer*) 0;
	    t->next = t2;
	    t2->prev = t;
	    }
	else
	    {
	    /* Walk the list to find the insertion point. */
	    for ((t2prev = t2, t2 = t2->next); t2 != (Timer*) 0;
		 (t2prev = t2, t2 = t2->next))
		{
		if ( t->time.tv_sec < t2->time.tv_sec ||
		     ( t->time.tv_sec == t2->time.tv_sec &&
		       t->time.tv_usec <= t2->time.tv_usec ) )
		    {
		    /* Found it. */
		    t2prev->next = t;
		    t->prev = t2prev;
		    t->next = t2;
		    t2->prev = t;
		    return;
		    }
		}
	    /* Oops, got to the end of the list.  Add to tail. */
	    t2prev->next = t;
	    t->prev = t2prev;
	    t->next = (Timer*) 0;
	    }
	}
    }


static void
l_remove( Timer* t )
    {
    int h = t->hash;

    if ( t->prev == (Timer*) 0 )
	timers[h] = t->next;
    else
	t->prev->next = t->next;
    if ( t->next != (Timer*) 0 )
	t->next->prev = t->prev;
    }


static void
l_resort( Timer* t )
    {
    /* Remove the timer from its old list. */
    l_remove( t );
    /* Recompute the hash. */
    t->hash = (short) hash( t );
    /* And add it back in to its new list, sorted correctly. */
    l_add( t );
    }


void
tmr_init( void )
    {
    int h;

    for ( h = 0; h < HASH_SIZE; ++h )
	timers[h] = (Timer*) 0;
    free_timers = (Timer*) 0;
    alloc_count = active_count = free_count = 0;
    }


Timer*
tmr_create(
    struct timeval* nowP, TimerProc* timer_proc, ClientData client_data,
    long msecs, int periodic )
    {
    Timer* t;

    if ( free_timers != (Timer*) 0 )
	{
	t = free_timers;
	free_timers = t->next;
	--free_count;
	}
    else
	{
	t = (Timer*) malloc( sizeof(Timer) );
	if ( t == (Timer*) 0 )
	    return (Timer*) 0;
	++alloc_count;
	}

    t->timer_proc = timer_proc;
    t->client_data = client_data;
    t->msecs = msecs;
    t->periodic = (short) periodic;
    if ( nowP != (struct timeval*) 0 )
	t->time = *nowP;
    else
	(void) gettimeofday( &t->time, (struct timezone*) 0 );
    t->time.tv_sec += msecs / 1000L;
    t->time.tv_usec += ( msecs % 1000L ) * 1000L;
    if ( t->time.tv_usec >= 1000000L )
	{
	t->time.tv_sec += t->time.tv_usec / 1000000L;
	t->time.tv_usec %= 1000000L;
	}
    /* Compute hash value */
    t->hash = (short) hash( t );
    /* Add the new timer to the proper active list. */
    l_add( t );
    ++active_count;

    return t;
    }


struct timeval*
tmr_timeout( struct timeval* nowP )
    {
    Timer** t  = &timers[0];
    Timer** te = &timers[HASH_SIZE];
    struct timeval *pt0;
    static struct timeval timeout;

    while ( t != te && *t == (Timer*) 0 )
	++t;

    if ( t == te )
	return (struct timeval*) 0;

    pt0 = &( (*t)->time );

    /* Since the lists are sorted, we only need to look at the
    ** first timer on each one.
    */
    for ( ++t; t != te; ++t )
	{
	if ( *t == (Timer*) 0 )
	    continue;
	if ( pt0->tv_sec  < (*t)->time.tv_sec )
	    continue;
	if ( pt0->tv_sec  == (*t)->time.tv_sec &&
	     pt0->tv_usec <= (*t)->time.tv_usec )
	    continue;
	pt0 = &((*t)->time);
	}

    if (  pt0->tv_sec  > nowP->tv_sec ||
	( pt0->tv_sec == nowP->tv_sec &&
	  pt0->tv_usec > nowP->tv_usec )
	)
	{
	timeout.tv_sec  = pt0->tv_sec  - nowP->tv_sec;
	timeout.tv_usec = pt0->tv_usec - nowP->tv_usec;
	if ( timeout.tv_usec < 0L )
	    {
	    timeout.tv_sec--;
	    timeout.tv_usec += 1000000L;
	    }
	return &timeout;
	}

    /* timeout 0 */
    timeout.tv_sec  = 0L;
    timeout.tv_usec = 0L;

    return &timeout;
    }


long
tmr_mstimeout( struct timeval* nowP )
    {
    long msecs;
    Timer** t  = &timers[0];
    Timer** te = &timers[HASH_SIZE];
    struct timeval *pt0;

    while ( t != te && *t == (Timer*) 0 )
	++t;

    if ( t == te )
	return INFTIM;

    pt0 = &( (*t)->time );

    /* Since the lists are sorted, we only need to look at the
    ** first timer on each one.
    */
    for ( ++t; t != te; ++t )
	{
	if ( *t == (Timer*) 0 )
	    continue;
	if ( pt0->tv_sec  < (*t)->time.tv_sec )
	    continue;
	if ( pt0->tv_sec  == (*t)->time.tv_sec &&
	     pt0->tv_usec <= (*t)->time.tv_usec )
	    continue;
	pt0 = &((*t)->time);
	}

    msecs = (long) (
	    ( pt0->tv_sec - nowP->tv_sec ) * 1000L +
	    ( pt0->tv_usec - nowP->tv_usec ) / 1000L );

    if ( msecs < 0L )
	msecs = 0L;

    return msecs;
    }


void
tmr_run( struct timeval* nowP )
    {
    int h;
    Timer* t;
    Timer* next;

    for ( h = 0; h < HASH_SIZE; ++h )
	for ( t = timers[h]; t != (Timer*) 0; t = next )
	    {
#ifdef TMR_DEBUG
	    /* if this timer has been removed, then stop walking this list */
	    if ( t->hash == (short) HASH_NONE )
		{
		syslog( LOG_ERR,
		"tmr_run: timers[%d], PRE callback, t->hash == HASH_NONE", h );
		break;
		}
#endif /* TMR_DEBUG */
	    /* Since the lists are sorted, as soon as we find a timer
	    ** that isn't ready yet, we can go on to the next list.
	    */
	    if ( t->time.tv_sec > nowP->tv_sec ||
		 ( t->time.tv_sec == nowP->tv_sec &&
		   t->time.tv_usec > nowP->tv_usec ) )
		break;
	    (t->timer_proc)( t->client_data, nowP );
#ifdef TMR_DEBUG
	    /* if this timer has been removed, then stop walking this list */
	    if ( t->hash == (short) HASH_NONE )
		{
		syslog( LOG_ERR,
		"tmr_run: timers[%d], POST callback, t->hash == HASH_NONE", h );
		break;
		}
#endif /* TMR_DEBUG */
	    /* This timer is going to be removed from this list or
	    ** to be moved to another position / list,
	    ** so we have to save next pointer now.
	    ** NOTE: a callback MUST NOT cancel or reset its own timer
	    **       thus current timer should be still valid.
	    */
	    next = t->next;

	    /* Eventually remove current timer. */
	    if ( t->periodic == 0 )
		{
		tmr_cancel( t );
		continue;
		}
	    /* Reschedule. */
	    t->time.tv_sec += t->msecs / 1000L;
	    t->time.tv_usec += ( t->msecs % 1000L ) * 1000L;
	    if ( t->time.tv_usec >= 1000000L )
		{
		t->time.tv_sec += t->time.tv_usec / 1000000L;
		t->time.tv_usec %= 1000000L;
		}
	    if ( t->time.tv_sec < nowP->tv_sec )
		{
		/* System clock has been set to a future time and
		** OS seems to not handle this change in a monotonic way
		** OR the program is too busy / loaded and the interval
		** of time is too short to be handled periodically.
		** Adjust it to not consume too much CPU
		** by calling periodic callbacks too often.
		*/
		t->time = *nowP;
		}
	    l_resort( t );
	    }
    }


void
tmr_reset( struct timeval* nowP, Timer* t )
    {
    if ( t->hash == (short) HASH_NONE )
#ifdef TMR_DEBUG
	{
	syslog( LOG_ERR, "tmr_reset: t->hash == HASH_NONE !" );
	return;
	}
#else
	return;
#endif /* TMR_DEBUG */

    t->time = *nowP;
    t->time.tv_sec += t->msecs / 1000L;
    t->time.tv_usec += ( t->msecs % 1000L ) * 1000L;
    if ( t->time.tv_usec >= 1000000L )
	{
	t->time.tv_sec += t->time.tv_usec / 1000000L;
	t->time.tv_usec %= 1000000L;
	}
    l_resort( t );
    }


void
tmr_cancel( Timer* t )
    {
    if ( t->hash == (short) HASH_NONE )
#ifdef TMR_DEBUG
	{
	syslog( LOG_ERR, "tmr_cancel: t->hash == HASH_NONE !" );
	return;
	}
#else
	return;
#endif /* TMR_DEBUG */

    /* Remove it from its active list. */
    l_remove( t );
    --active_count;
    /* Reset the hash. */
    t->hash = (short) HASH_NONE;
    /* And put it on the free list. */
    t->next = free_timers;
    free_timers = t;
    ++free_count;
    t->prev = (Timer*) 0;
    }


void
tmr_cleanup( void )
    {
    Timer* t;

    while ( free_timers != (Timer*) 0 )
	{
	t = free_timers;
	free_timers = t->next;
	--free_count;
	free( (void*) t );
	--alloc_count;
	}
    }


void
tmr_destroy( void )
    {
    int h;

    for ( h = 0; h < HASH_SIZE; ++h )
	while ( timers[h] != (Timer*) 0 )
	    tmr_cancel( timers[h] );
    tmr_cleanup();
    }


/* Generate debugging statistics syslog message. */
void
tmr_logstats( long secs )
    {
    syslog(
	LOG_INFO, "  timers - %d allocated, %d active, %d free",
	alloc_count, active_count, free_count );
    if ( active_count + free_count != alloc_count )
	syslog( LOG_ERR, "timer counts don't add up!" );
    }
