/* tdate_parse - parse string dates into internal form, stripped-down version
**
** Copyright � 1995 by Jef Poskanzer <jef@acme.com>.
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

/* This is a heavily modified version (patched by A.D.F.) of the
** original stripped-down version of date_parse.c, available at
** http://www.acme.com/software/date_parse/
*/

#include <sys/types.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tdate_parse.h"

struct RecNameLen
{
    const char	*name1;
    size_t	len1;
    const char	*name2;
    size_t	len2;
};


/* Returns TRUE if it matches an existing weekday name. */
static int
sscan_wday( const char* cp_wday, size_t len, int* tm_wdayP )
    {
    static struct RecNameLen wday_tab[] = {
	{ "Sun", 3, "Sunday",    6 },
	{ "Mon", 3, "Monday",    6 },
	{ "Tue", 3, "Tuesday",   7 },
	{ "Wed", 3, "Wednesday", 9 },
	{ "Thu", 3, "Thursday",  8 },
	{ "Fri", 3, "Friday",    6 },
	{ "Sat", 3, "Saturday",  8 }
	};

    if (len < 3)
	return 0;

    switch( cp_wday[0] )
	{
	case 's': case 'S':
	    if ( cp_wday[1] == 'u' ||
		 cp_wday[1] == 'U')
		*tm_wdayP = 0;
	    else
		*tm_wdayP = 6;
	    break;
	case 'm': case 'M': *tm_wdayP = 1; break;
	case 't': case 'T':
	    if ( cp_wday[1] == 'u' ||
		 cp_wday[1] == 'U')
		*tm_wdayP = 2;
	    else
		*tm_wdayP = 4;
	    break;
	case 'w': case 'W': *tm_wdayP = 3; break;
	case 'f': case 'F': *tm_wdayP = 5; break;
	default:
	    return 0;
	}

    if ( len == wday_tab[*tm_wdayP].len1 )
	{
	if ( strncasecmp(
		cp_wday,
		wday_tab[*tm_wdayP].name1,
		wday_tab[*tm_wdayP].len1 ) == 0 )
	    return 1;
	return 0;
	}

    if ( len == wday_tab[*tm_wdayP].len2 )
	{
	if ( strncasecmp(
		cp_wday,
		wday_tab[*tm_wdayP].name2,
		wday_tab[*tm_wdayP].len2 ) == 0 )
	    return 1;
	return 0;
	}
    return 0;
    }


/* Returns TRUE if it matches an existing month name. */
static int
sscan_mon( const char* cp_mon, size_t len, int* tm_monP )
    {
    static struct RecNameLen mon_tab[] = {
	{ "Jan", 3, "January",   7 },
	{ "Feb", 3, "February",  8 },
	{ "Mar", 3, "March",     5 },
	{ "Apr", 3, "April",     5 },
	{ "May", 3, "May",       3 },
	{ "Jun", 3, "June",      4 },
	{ "Jul", 3, "July",      4 },
	{ "Aug", 3, "August",    6 },
	{ "Sep", 3, "September", 9 },
	{ "Oct", 3, "October",   7 },
	{ "Nov", 3, "November",  8 },
	{ "Dec", 3, "December",  8 }
	};

    if (len < 3)
	return 0;

    switch( cp_mon[0] )
	{
	case 'j': case 'J':
	    if ( cp_mon[1] == 'a' ||
		 cp_mon[1] == 'A')
		*tm_monP = 0;
	    else
	    if ( cp_mon[2] == 'n' ||
		 cp_mon[2] == 'N')
		*tm_monP = 5;
	    else
		*tm_monP = 6;
	    break;
	case 'f': case 'F': *tm_monP = 1; break;
	case 'm': case 'M':
	    if ( cp_mon[2] == 'r' ||
		 cp_mon[2] == 'R')
		*tm_monP = 2;
	    else
		*tm_monP = 4;
	    break;
	case 'a': case 'A':
	    if ( cp_mon[2] == 'r' ||
		 cp_mon[2] == 'R')
		*tm_monP = 3;
	    else
		*tm_monP = 7;
	    break;
	case 's': case 'S': *tm_monP = 8; break;
	case 'o': case 'O': *tm_monP = 9; break;
	case 'n': case 'N': *tm_monP = 10; break;
	case 'd': case 'D': *tm_monP = 11; break;
	default:
	    return 0;
	}

    if ( len == mon_tab[*tm_monP].len1 )
	{
	if ( strncasecmp(
		cp_mon,
		mon_tab[*tm_monP].name1,
		mon_tab[*tm_monP].len1 ) == 0 )
	    return 1;
	return 0;
	}

    if ( len == mon_tab[*tm_monP].len2 )
	{
	if ( strncasecmp(
		cp_mon,
		mon_tab[*tm_monP].name2,
		mon_tab[*tm_monP].len2 ) == 0 )
	    return 1;
	return 0;
	}
    return 0;
    }


/* HH:MM:SS GMT DD-mth-YY */
/* DD-mth-YY HH:MM:SS GMT */
/* Returns TRUE if it matches one of the above date-time formats. */
static int
sscan_dmyhmsr( char *cp, struct tm *tmP )
    {
    size_t idx = 0;
    --idx;
    do
	{
	++idx;
	}
    while( cp[idx] == ' ' );

    cp += idx;
    idx = 0;

    tmP->tm_wday = 0;

    if ( cp[2] == ':' )
	{
	/* HH:MM:SS GMT DD-mth-YY */

	/* hour, min, sec */
	if (
	    !isdigit( cp[0] ) || !isdigit( cp[1] ) ||
	    cp[2] != ':' ||
	    !isdigit( cp[3] ) || !isdigit( cp[4] ) ||
	    cp[5] != ':' ||
	    !isdigit( cp[6] ) || !isdigit( cp[7] )
	    )
	    return 0;

	tmP->tm_hour = (cp[0] - '0') * 10 + (cp[1] - '0');
	tmP->tm_min  = (cp[3] - '0') * 10 + (cp[4] - '0');
	tmP->tm_sec  = (cp[6] - '0') * 10 + (cp[7] - '0');

	idx += 8;
	if ( cp[idx] != ' ')
	    return 0;
	do
	    {
	    ++idx;
	    }
	while( cp[idx] == ' ' );
	cp += idx;
	idx = 0;

	if ( cp[0] != 'G' ||
	     cp[1] != 'M' ||
	     cp[2] != 'T' ||
	     cp[3] != ' ' )
	     return 0;

	idx += 3;
	do
	    {
	    ++idx;
	    }
	while( cp[idx] == ' ' );
	cp += idx;

	/* day */
	tmP->tm_mday = 0;
	for ( idx = 0; idx < 2 && isdigit( cp[idx] ); ++idx )
	    {
	    tmP->tm_mday = tmP->tm_mday * 10  + (cp[idx] - '0');
	    }
	if ( idx == 0 )
	    return 0;

	if ( cp[idx] != '-')
	    return 0;
	++idx;
	cp += idx;

	/* month */
	tmP->tm_mon = 0;
	for ( idx = 0; isalpha( cp[idx] ); ++idx )
	    ;
	if (! sscan_mon( cp, idx, &(tmP->tm_mon) ) )
	    return 0;

	if ( cp[idx] != '-')
	    return 0;
	++idx;
	cp += idx;

	/* year */
	tmP->tm_year = 0;
	for ( idx = 0; idx < 4 && isdigit( cp[idx] ); ++idx )
	    {
	    tmP->tm_year = tmP->tm_year * 10  + (cp[idx] - '0');
	    }
	if ( idx == 0 )
	    return 0;

	if ( isdigit( cp[idx] ) )
	    return 0;
	}
    else
	{
	/* DD-mth-YY HH:MM:SS GMT */

	/* day */
	tmP->tm_mday = 0;
	for ( idx = 0; idx < 2 && isdigit( cp[idx] ); ++idx )
	    {
	    tmP->tm_mday = tmP->tm_mday * 10  + (cp[idx] - '0');
	    }
	if ( idx == 0 )
	    return 0;

	if ( cp[idx] != '-')
	    return 0;
	++idx;
	cp += idx;

	/* month */
	tmP->tm_mon = 0;
	for ( idx = 0; isalpha( cp[idx] ); ++idx )
	    ;
	if (! sscan_mon( cp, idx, &(tmP->tm_mon) ) )
	    return 0;

	if ( cp[idx] != '-')
	    return 0;
	++idx;
	cp += idx;

	/* year */
	tmP->tm_year = 0;
	for ( idx = 0; idx < 4 && isdigit( cp[idx] ); ++idx )
	    {
	    tmP->tm_year = tmP->tm_year * 10  + (cp[idx] - '0');
	    }
	if ( idx == 0 )
	    return 0;

	if ( cp[idx] != ' ' )
	    return 0;
	do
	    {
	    ++idx;
	    }
	while( cp[idx] == ' ' );

	cp += idx;
	idx = 0;

	/* hour, min, sec */
	if (
	    !isdigit( cp[0] ) || !isdigit( cp[1] ) ||
	    cp[2] != ':' ||
	    !isdigit( cp[3] ) || !isdigit( cp[4] ) ||
	    cp[5] != ':' ||
	    !isdigit( cp[6] ) || !isdigit( cp[7] )
	    )
	    return 0;

	tmP->tm_hour = (cp[0] - '0') * 10 + (cp[1] - '0');
	tmP->tm_min  = (cp[3] - '0') * 10 + (cp[4] - '0');
	tmP->tm_sec  = (cp[6] - '0') * 10 + (cp[7] - '0');

	idx += 8;
	if ( cp[idx] != ' ')
	    return 0;
	do
	    {
	    ++idx;
	    }
	while( cp[idx] == ' ' );
	cp += idx;
	idx = 0;

	if ( cp[0] != 'G' ||
	     cp[1] != 'M' ||
	     cp[2] != 'T' )
	     return 0;
	idx += 3;
	}
    return 1;
    }


/* is leap year */
#define is_leap(y)	( (y) % 4 == 0 && ( (y) % 100 || (y) % 400 == 0 ) )

/* Basically the same as mktime(). */
static time_t
tm_to_time( struct tm* tmP )
    {
    time_t t;
    int tm_year = tmP->tm_year + 1900;
    static int monthtab[12] = {
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

    /* Years since epoch, converted to days. */
    t = ( tmP->tm_year - 70 ) * 365;
    /* Leap days for previous years. */
    t += ( tmP->tm_year - 69 ) / 4;
    /* Days for the beginning of this month. */
    t += monthtab[tmP->tm_mon];
    /* Leap day for this year. */
    if ( tmP->tm_mon >= 2 && is_leap( tm_year ) )
	++t;
    /* Days since the beginning of this month. */
    t += tmP->tm_mday - 1;	/* 1-based field */
    /* Hours, minutes, and seconds. */
    t = t * 24 + tmP->tm_hour;
    t = t * 60 + tmP->tm_min;
    t = t * 60 + tmP->tm_sec;

    return t;
    }


time_t
tdate_parse( char* str )
    {
    struct tm tm;
    char* cp;
    size_t idx = 0;
    size_t len = 0;
    int tm_sec = 0;
    int tm_min = 0;
    int tm_hour = 0;
    int tm_wday = 0;
    int tm_mday = 0;
    int tm_mon  = 0;
    int tm_year = 0;
    time_t t;

    /* Initialize. */
    (void) memset( (char*) &tm, 0, sizeof(struct tm) );

    /* Skip initial whitespace(s). */
    for ( cp = str; *cp == ' ' || *cp == '\t'; ++cp )
	continue;

    len = strlen( cp );
    if ( len < 21 )
	return (time_t) -1;

    if ( isalpha( *cp ) )
	{
	/* wdy[,] ... */

	/* day of week */
	tm_wday = 0;
	for ( idx = 0; isalpha( cp[idx] ); ++idx )
		;
	if (! sscan_wday( cp, idx, &tm_wday ) )
	    return (time_t) -1;

	if ( cp[idx] == ',' )
	    {
	    /* ----------------------------- */
	    /* wdy, DD mth YYYY HH:MM:SS GMT */
	    /* wdy, DD-mth-YY HH:MM:SS GMT   */
	    /* ----------------------------- */

	    ++idx;
	    if ( cp[idx] != ' ')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' );
	    cp += idx;

	    /* day */
	    tm_mday = 0;
	    for ( idx = 0; idx < 2 && isdigit( cp[idx] ); ++idx )
		{
		tm_mday = tm_mday * 10  + (cp[idx] - '0');
		}
	    if ( idx == 0 )
		return (time_t) -1;

	    if ( cp[idx] != ' ' && cp[idx] != '-')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' || cp[idx] == '-' );
	    cp += idx;

	    /* month */
	    tm_mon = 0;
	    for ( idx = 0; isalpha( cp[idx] ); ++idx )
		;
	    if (! sscan_mon( cp, idx, &tm_mon ) )
		return (time_t) -1;

	    if ( cp[idx] != ' ' && cp[idx] != '-')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' || cp[idx] == '-' );
	    cp += idx;

	    /* year */
	    tm_year = 0;
	    for ( idx = 0; idx < 4 && isdigit( cp[idx] ); ++idx )
		{
		tm_year = tm_year * 10  + (cp[idx] - '0');
		}
	    if ( idx == 0 )
		return (time_t) -1;

	    if ( cp[idx] != ' ')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' );
	    cp += idx;
	    idx = 0;

	    /* hour, min, sec */
	    if (!isdigit( cp[0] ) || !isdigit( cp[1] ) ||
		cp[2] != ':' ||
		!isdigit( cp[3] ) || !isdigit( cp[4] ) ||
		cp[5] != ':' ||
		!isdigit( cp[6] ) || !isdigit( cp[7] )
		)
		return (time_t) -1;

	    tm_hour = (cp[0] - '0') * 10 + (cp[1] - '0');
	    tm_min  = (cp[3] - '0') * 10 + (cp[4] - '0');
	    tm_sec  = (cp[6] - '0') * 10 + (cp[7] - '0');

	    idx += 8;
	    while( cp[idx] == ' ')
		++idx;
	    cp += idx;
	    idx = 0;

	    /* Time Zone (always Greenwitch Mean Time) */
	    if ( cp[0] != 'G' ||
		 cp[1] != 'M' ||
		 cp[2] != 'T')
		return (time_t) -1;

	    }
	else
	    {
	    /* -------------------------- */
	    /* wdy mth DD HH:MM:SS YYYY   */
	    /* wdy mth DD HH:MM:SS GMT YY */
	    /* -------------------------- */

	    if ( cp[idx] != ' ')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' );
	    cp += idx;

	    /* month */
	    tm_mon = 0;
	    for ( idx = 0; isalpha( cp[idx] ); ++idx )
		;
	    if (! sscan_mon( cp, idx, &tm_mon ) )
		return (time_t) -1;

	    if ( cp[idx] != ' ')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ');
	    cp += idx;

	    /* day */
	    tm_mday = 0;
	    for ( idx = 0; idx < 2 && isdigit( cp[idx] ); ++idx )
		{
		tm_mday = tm_mday * 10  + (cp[idx] - '0');
		}
	    if ( idx == 0 )
		return (time_t) -1;

	    if ( cp[idx] != ' ')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' );
	    cp += idx;
	    idx = 0;

	    /* hour, min, sec */
	    if (
		!isdigit( cp[0] ) || !isdigit( cp[1] ) ||
		cp[2] != ':' ||
		!isdigit( cp[3] ) || !isdigit( cp[4] ) ||
		cp[5] != ':' ||
		!isdigit( cp[6] ) || !isdigit( cp[7] )
		)
		return (time_t) -1;

	    tm_hour = (cp[0] - '0') * 10 + (cp[1] - '0');
	    tm_min  = (cp[3] - '0') * 10 + (cp[4] - '0');
	    tm_sec  = (cp[6] - '0') * 10 + (cp[7] - '0');

	    idx += 8;
	    if ( cp[idx] != ' ')
		return (time_t) -1;
	    do
		{
		++idx;
		}
	    while( cp[idx] == ' ' );
	    cp += idx;
	    idx = 0;

	    /* Optional Time Zone (always Greenwitch Mean Time) */
	    if ( cp[0] == 'G' )
		{
		if ( cp[1] != 'M' ||
		     cp[2] != 'T' ||
		     cp[3] != ' ' )
		    return (time_t) -1;
		idx = 3;
		do
		    {
		    ++idx;
		    }
		while ( cp[idx] == ' ' );
		cp += idx;
		idx = 0;
		}

	    /* year */
	    tm_year = 0;
	    for ( idx = 0; idx < 4 && isdigit( cp[idx] ); ++idx )
		{
		tm_year = tm_year * 10  + (cp[idx] - '0');
		}
	    if ( idx == 0 )
		return (time_t) -1;

	    if ( isdigit( cp[idx] ) )
		return (time_t) -1;
	    cp += idx;
	    idx = 0;

	    }
	}
    else
    if ( isdigit( *cp ) )
	{
	/* Uncommon date-time formats */
	/* -------------------------- */
	/* HH:MM:SS GMT DD-mth-YY     */
	/* DD-mth-YY HH:MM:SS GMT     */
	/* -------------------------- */
	if ( !sscan_dmyhmsr( cp, &tm ) )
	    return (time_t) -1;
	tm_sec  = tm.tm_sec;
	tm_min  = tm.tm_min;
	tm_hour = tm.tm_hour;
	tm_mday = tm.tm_mday;
	tm_mon  = tm.tm_mon;
	tm_year = tm.tm_year;
	tm_wday = tm.tm_wday;
	}
    else
	/* Unsupported date-time format */
	return (time_t) -1;

    if ( tm_year >  1900 )
	 tm_year -= 1900;
    else
    if ( tm_year < 70 )
	 tm_year += 100;

    /* accepted time: 01-Jan-1970 - 31-Dec-2036 */

    if ( tm_year < 70 || tm_year > 136 ||
	 tm_mday <  1 || tm_mday >  31 ||
         tm_hour <  0 || tm_hour >  23 ||
	 tm_min  <  0 || tm_min  >  59 ||
	 tm_sec  <  0 || tm_sec  >  59 )
	return (time_t) -1;

    tm.tm_sec  = tm_sec;
    tm.tm_min  = tm_min;
    tm.tm_hour = tm_hour;
    tm.tm_mday = tm_mday;
    tm.tm_mon  = tm_mon;
    tm.tm_year = tm_year;
    tm.tm_wday = tm_wday;

    t = tm_to_time( &tm );

    return t;
    }
