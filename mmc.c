/* mmc.c - mmap cache
**
** Copyright � 1998,2001 by Jef Poskanzer <jef@acme.com>.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif /* HAVE_MMAP */

#include "mmc.h"

	/* start of A.D.F.'s modifications */

#ifdef notdef
#define MMC_DEBUG		/* enable debug-code */
#endif
#ifdef notdef
#define MMC_UPD_REFMAP_TIME	/* enable update of time of referenced maps */
#endif				/* (not useful nor required by new mmc cache) */

#define MMC_DUMMY_ADDR	( (void*) 1 )	/* used for zero sized files */

#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif /* FD_CLOEXEC */

/*
** Conversion from a desired limit to a mandatory upper limit.
*/
#define UP_LIMIT_TO_DESIRED(n)		( ( (n) / 5 ) * 4 )
#define DESIRED_TO_UP_LIMIT(n)		( ( (n) * 5 ) / 4 )
/* Same macro to avoid overflow for big numbers */
#define DESIRED_TO_UP_LIMIT2(n)		( ( (n) / 4 ) * 5 )
/*
** Conversion from total number of mapped files to desired number
** for each cache level: total = desired L1 + L2 + L3 + L4 (more or less).
*/
#define DESIRED_MAX_FILES_L1(n)		( ( (n) * 5 ) / 10 )
#define DESIRED_MAX_FILES_L2(n)		( ( (n) * 3 ) / 10 )
#define DESIRED_MAX_FILES_L3(n)		( ( (n) * 2 ) / 10 )
#define DESIRED_MAX_FILES_L4(n)		( ( (n) * 1 ) / 20 )
/*
** Conversion from total size of mapped files to desired number
** for each cache level; NOTE: these are lazy limits
** (the calculated sum for each level is over the total),
** because we don't know which level will map more bytes,
*/
#define DESIRED_MAX_BYTES_L1(n)		(   (n) / 4 )
#define DESIRED_MAX_BYTES_L2(n)		(   (n) / 2 )
#define DESIRED_MAX_BYTES_L3(n)		(   (n) / 2 )
#define DESIRED_MAX_BYTES_L4(n)		( ( (n) / 4 ) * 3 )
/*
** Default values, many of them are also defined in config.h,
** DEF_MUL_* are multipliers of expire age L3 (reference value),
** DEF_DIV_* are divisors    of expire age L3 (reference value).
*/
#ifndef DEFAULT_CLEANUP_TIME
#define DEFAULT_CLEANUP_TIME	10
#endif
#ifndef DEFAULT_EXPIRE_AGE
#define DEFAULT_EXPIRE_AGE	150
#endif
#ifndef DEF_MUL_EXPIRE_AGE_L0
#define DEF_MUL_EXPIRE_AGE_L0	120
#endif
#ifndef DEF_MUL_EXPIRE_AGE_L1
#define DEF_MUL_EXPIRE_AGE_L1	10
#endif
#ifndef DEF_MUL_EXPIRE_AGE_L2
#define DEF_MUL_EXPIRE_AGE_L2	4
#endif
#ifndef DEF_MUL_EXPIRE_AGE_L3
#define DEF_MUL_EXPIRE_AGE_L3	1
#endif
#ifndef DEF_DIV_EXPIRE_AGE_L4
#define DEF_DIV_EXPIRE_AGE_L4	32
#endif
#ifndef DEF_DIV_EXPIRE_AGE_L5
#define DEF_DIV_EXPIRE_AGE_L5	64
#endif
/*
** Conversion from default base expire age to desired age for each level.
*/
#define DESIRED_EXPIRE_AGE_L0(ExpAge)	( ( ExpAge ) * DEF_MUL_EXPIRE_AGE_L0 )
#define DESIRED_EXPIRE_AGE_L1(ExpAge)	( ( ExpAge ) * DEF_MUL_EXPIRE_AGE_L1 )
#define DESIRED_EXPIRE_AGE_L2(ExpAge)	( ( ExpAge ) * DEF_MUL_EXPIRE_AGE_L2 )
#define DESIRED_EXPIRE_AGE_L3(ExpAge)	( ( ExpAge ) * DEF_MUL_EXPIRE_AGE_L3 )
#define DESIRED_EXPIRE_AGE_L4(ExpAge)	( ( ExpAge ) / DEF_DIV_EXPIRE_AGE_L4 )
#define DESIRED_EXPIRE_AGE_L5(ExpAge)	( ( ExpAge ) / DEF_DIV_EXPIRE_AGE_L5 )
/*
** Desired max. free MA (malloc), MM (mmap) and FD (file descriptors)
** structures, already allocated, ready to be reused.
*/
#ifndef DESIRED_FREE_MAC_COUNT
#define DESIRED_FREE_MAC_COUNT	200
#endif
#ifndef DESIRED_FREE_MMC_COUNT
#define DESIRED_FREE_MMC_COUNT	100
#endif
#ifndef DESIRED_FREE_FDC_COUNT
#define DESIRED_FREE_FDC_COUNT	100
#endif
/*
** Default / desired values (change those defined in config.h).
*/
#ifndef DESIRED_MAX_MALLOC_FILES
#define DESIRED_MAX_MALLOC_FILES	5000
#endif
#ifndef DESIRED_MAX_MALLOC_BYTES
#define DESIRED_MAX_MALLOC_BYTES	( 1024 * 1024 * 2 )
#endif
#ifndef DESIRED_MAX_MAPPED_FILES
#define DESIRED_MAX_MAPPED_FILES	2000
#endif
#ifndef DESIRED_MAX_MAPPED_BYTES
#define DESIRED_MAX_MAPPED_BYTES	( 1024 * 1024 * 800 )
#endif
#ifndef DESIRED_MAX_OPENED_FILES
#define DESIRED_MAX_OPENED_FILES	100
#endif
/*
** Default limits for mmapped files L1-L4.
*/
#define DESIRED_MAX_MAPPED_FILES_L1	\
	DESIRED_MAX_FILES_L1( DESIRED_MAX_MAPPED_FILES )
#define DESIRED_MAX_MAPPED_FILES_L2	\
	DESIRED_MAX_FILES_L2( DESIRED_MAX_MAPPED_FILES )
#define DESIRED_MAX_MAPPED_FILES_L3	\
	DESIRED_MAX_FILES_L3( DESIRED_MAX_MAPPED_FILES )
#define DESIRED_MAX_MAPPED_FILES_L4	\
	DESIRED_MAX_FILES_L4( DESIRED_MAX_MAPPED_FILES )

#define DESIRED_MAX_MAPPED_BYTES_L1	\
	DESIRED_MAX_BYTES_L1( DESIRED_MAX_MAPPED_FILES )
#define DESIRED_MAX_MAPPED_BYTES_L2	\
	DESIRED_MAX_BYTES_L2( DESIRED_MAX_MAPPED_FILES )
#define DESIRED_MAX_MAPPED_BYTES_L3	\
	DESIRED_MAX_BYTES_L3( DESIRED_MAX_MAPPED_FILES )
#define DESIRED_MAX_MAPPED_BYTES_L4	\
	DESIRED_MAX_BYTES_L4( DESIRED_MAX_MAPPED_FILES )

#ifndef MAX_FILE_SIZE_L0
#define MAX_FILE_SIZE_L0	(2048)
#endif
#ifndef MAX_FILE_SIZE_L1
#define MAX_FILE_SIZE_L1	(1024 * 16)
#endif
#ifndef MAX_FILE_SIZE_L2
#define MAX_FILE_SIZE_L2	(1024 * 96)
#endif
#ifndef MAX_FILE_SIZE_L3
#define MAX_FILE_SIZE_L3	(1024 * 256)
#endif
#ifndef MAX_FILE_SIZE_L4
#define MAX_FILE_SIZE_L4	(1024 * 512)
#endif
#undef  MAX_FILE_SIZE_L5
#define MAX_FILE_SIZE_L5	(0)	/* must be 0 */

#ifndef INITIAL_HASH_BITS
#define INITIAL_HASH_BITS	10	/* between 8 - 16 */
#endif
#ifndef INITIAL_HASH_SIZE
#define INITIAL_HASH_SIZE	(1 << INITIAL_HASH_BITS)
#endif
#ifndef MAX_HASH_BITS
#define MAX_HASH_BITS		20	/* between INITIAL_HASH_BITS - 20 */
#endif
#ifndef MAX_HASH_SIZE
#define MAX_HASH_SIZE		(1 << MAX_HASH_BITS)
#endif
#ifndef AVG_HASH_CHAIN_LENGTH
#define AVG_HASH_CHAIN_LENGTH	4	/* keep it a power of two (2, 4, 8) */
#endif

#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))

/* defines for mmc_unmap_[un]ref() */
#define NO_LOG	0
#define DO_LOG	1

/* defines for mmc_pmc_cleanup() */
#define NO_AGE	0
#define DO_AGE	1
#define NO_FREE	0
#define DO_FREE	1

/* cache types (keep them in sync with vszCacheDes[]) */
#define MMC_CACHE_TYPE_UNK	0	/* unknown cache type */
#define MMC_CACHE_TYPE_MIN	1
#define MMC_CACHE_TYPE_MA	1	/* malloc */
#define MMC_CACHE_TYPE_MM	2	/* memory map */
#define MMC_CACHE_TYPE_FD	3	/* file descriptor */
#define MMC_CACHE_TYPE_MAX	3

#ifdef HAVE_MMAP
#define MMC_CACHE_TYPE_MA_MM	MMC_CACHE_TYPE_MM
#else
#define MMC_CACHE_TYPE_MA_MM	MMC_CACHE_TYPE_MA
#endif

/* cache zones / levels (indexes in vMapCtl[]) */
#define MMC_CACHE_L0		0
#define MMC_CACHE_L1		1
#define MMC_CACHE_L2		2
#define MMC_CACHE_L3		3
#define MMC_CACHE_L4		4
#define MMC_CACHE_L5		5
#define MMC_CACHE_LMAX		6

/* macro for mmc_is_fdmap() */
#define MMC_IS_FDMAP(fsize)	\
	( ( (fsize) > cfgMaxFileSizeL3 ) &&	\
	  ( (fsize) > cfgMaxFileSizeL4 ) &&	\
		cfgUseFdMap != 0 )

/* The Map struct.
** NOTE (*): PARANOIA CHECK: here we use ctime instead of mtime because
** we want to note not only changes in file contents, but also changes
** to file mode and to its hard and/or soft links.
**
** The typical scenario is that someone could change file mode or move
** its soft or hard links around the file system in a way that
** could prevent a new successful open(), thus, in some of these cases,
** we want to force a new open(), i.e.:   file ctime changes,
** its old cached Map is not found (because ctime is a key value),
** open() is called, a new Map is eventually created and, after some time,
** the old Map is deleted.
*/
typedef struct MapStruct {
    ino_t  ino;			/* inode of the file */
    dev_t  dev;			/* device where file resides */
    off_t  size;		/* size of file */
    time_t ctime;		/* (*) last status change (always >= mtime) */
    time_t reftime;		/* last reference time */
    int    refcount;		/* reference count */
    int    fd;			/* file descriptor */
    void*  addr;		/* file address (if malloced or mmapped) */
    unsigned
    int    hash;		/* hash value */
    struct MapStruct* prev_lru;	/* previous LRU node */
    struct MapStruct* next_lru;	/* next     LRU node */
    struct MapStruct* prev_hash;/* previous hash node */
    struct MapStruct* next_hash;/* next     hash node */
    } Map;

typedef struct MapCtlStruct {
    const
    int     cache_zone;		/* cache zone / level */
    const
    int     cache_type;		/* cache type (MC, MM, FD) */
    Map*    lru_ref;		/* LRU list of referenced maps */
    Map*    lru_unref;		/* LRU list of unreferenced maps */
    Map*    free_maps;		/* free maps (reusable, not yet fred) */
    Map**   hash_table;		/* hash table for this zone */
    int     hash_size;		/* hash size (it can dynamically grow) */
    unsigned
    int     hash_mask;		/* hash mask (it can dinamically change) */
    time_t  expire_age;		/* expire age (seconds) for this zone */
    size_t  max_file_size;	/* max file size allowed in this zone */
    int     desired_max_files;	/* max number of files desired in this zone */
    int     uplimit_max_files;	/* upper limit for the cached files */
    off_t   desired_max_bytes;	/* max number of bytes desired in this zone */
    off_t   uplimit_max_bytes;	/* upper limit for the cached bytes */
    off_t   alloc_bytes;	/* number of allocated bytes in this zone */
    int     alloc_count;	/* number of allocated maps  in this zone */
    int     map_count;		/* total number of maps */
    int     use_count;		/* number of used  maps */
    int     free_count;		/* number of free  maps */
    const
    int     desired_free_count;	/* desired number of free maps */
    } MapCtl;

/* Globals. */
static MapCtl vMapCtl[MMC_CACHE_LMAX] =
    {
	{ MMC_CACHE_L0, MMC_CACHE_TYPE_MA,
		0, 0, 0, 0, 0, 0,
		DESIRED_EXPIRE_AGE_L0( DEFAULT_EXPIRE_AGE ),
		MAX_FILE_SIZE_L0,
		DESIRED_MAX_MALLOC_FILES,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_MALLOC_FILES ),
		DESIRED_MAX_MALLOC_BYTES,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_MALLOC_BYTES ),
		0, 0, 0, 0, 0,
		DESIRED_FREE_MAC_COUNT
	},
	{ MMC_CACHE_L1, MMC_CACHE_TYPE_MA_MM,
		0, 0, 0, 0, 0, 0,
		DESIRED_EXPIRE_AGE_L1( DEFAULT_EXPIRE_AGE ),
		MAX_FILE_SIZE_L1,
		DESIRED_MAX_MAPPED_FILES_L1,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_MAPPED_FILES_L1 ),
		DESIRED_MAX_MAPPED_BYTES_L1,
		DESIRED_TO_UP_LIMIT2( DESIRED_MAX_MAPPED_BYTES_L1 ),
		0, 0, 0, 0, 0,
		DESIRED_FREE_MMC_COUNT
	},
	{ MMC_CACHE_L2, MMC_CACHE_TYPE_MA_MM,
		0, 0, 0, 0, 0, 0,
		DESIRED_EXPIRE_AGE_L2( DEFAULT_EXPIRE_AGE ),
		MAX_FILE_SIZE_L2,
		DESIRED_MAX_MAPPED_FILES_L2,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_MAPPED_FILES_L2 ),
		DESIRED_MAX_MAPPED_BYTES_L2,
		DESIRED_TO_UP_LIMIT2( DESIRED_MAX_MAPPED_BYTES_L2 ),
		0, 0, 0, 0, 0,
		DESIRED_FREE_MMC_COUNT / 2
	},
	{ MMC_CACHE_L3, MMC_CACHE_TYPE_MA_MM,
		0, 0, 0, 0, 0, 0,
		DESIRED_EXPIRE_AGE_L3( DEFAULT_EXPIRE_AGE ),
		MAX_FILE_SIZE_L3,
		DESIRED_MAX_MAPPED_FILES_L3,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_MAPPED_FILES_L3 ),
		DESIRED_MAX_MAPPED_BYTES_L3,
		DESIRED_TO_UP_LIMIT2( DESIRED_MAX_MAPPED_BYTES_L3 ),
		0, 0, 0, 0, 0,
		DESIRED_FREE_MMC_COUNT / 4
	},
	{ MMC_CACHE_L4, MMC_CACHE_TYPE_MA_MM,
		0, 0, 0, 0, 0, 0,
		DESIRED_EXPIRE_AGE_L4( DEFAULT_EXPIRE_AGE ),
		MAX_FILE_SIZE_L4,
		DESIRED_MAX_MAPPED_FILES_L4,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_MAPPED_FILES_L4 ),
		DESIRED_MAX_MAPPED_BYTES_L4,
		DESIRED_TO_UP_LIMIT2( DESIRED_MAX_MAPPED_BYTES_L4 ),
		0, 0, 0, 0, 0,
		DESIRED_FREE_MMC_COUNT / 4
	},
	{ MMC_CACHE_L5, MMC_CACHE_TYPE_FD,
		0, 0, 0, 0, 0, 0,
		DESIRED_EXPIRE_AGE_L5( DEFAULT_EXPIRE_AGE ),
		MAX_FILE_SIZE_L5,
		DESIRED_MAX_OPENED_FILES,
		DESIRED_TO_UP_LIMIT( DESIRED_MAX_OPENED_FILES ),
		0,
		0,
		0, 0, 0, 0, 0,
		DESIRED_FREE_FDC_COUNT
	}
    };

static int    cfgDefaultExpireAge = DEFAULT_EXPIRE_AGE;
static int    cfgCleanupTime      = DEFAULT_CLEANUP_TIME;
static int    cfgDesiredMaxMallocFiles = DESIRED_MAX_MALLOC_FILES;
static off_t  cfgDesiredMaxMallocBytes = DESIRED_MAX_MALLOC_BYTES;
static int    cfgDesiredMaxMappedFiles = DESIRED_MAX_MAPPED_FILES;
static off_t  cfgDesiredMaxMappedBytes = DESIRED_MAX_MAPPED_BYTES;
static int    cfgDesiredMaxOpenedFiles = DESIRED_MAX_OPENED_FILES;
static int    cfgUseFdMap = 0;
static int    cfgOpenNoATime = 0;
static int    cfgCloseOnExec = 0;
static off_t  cfgMaxFileSizeL0 = MAX_FILE_SIZE_L0;
static off_t  cfgMaxFileSizeL1 = MAX_FILE_SIZE_L1;
static off_t  cfgMaxFileSizeL2 = MAX_FILE_SIZE_L2;
static off_t  cfgMaxFileSizeL3 = MAX_FILE_SIZE_L3;
static off_t  cfgMaxFileSizeL4 = MAX_FILE_SIZE_L4;

/*
** Forwards.
** NOTE: GCC requires inline functions to be
**       declared and defined before their use.
*/
static inline void add_lru_ref( MapCtl* const pmc, Map* const m );
static inline void add_lru_unref( MapCtl* const pmc, Map* const m );
static inline void del_lru( Map* const m );
static inline unsigned int hash_fstat( unsigned int hash_mask,
			ino_t ino, dev_t dev, off_t size, time_t ctime );
static        void add_hash( MapCtl* const pmc, Map* m );
static        void del_hash( MapCtl* const pmc, Map* m );

static int  check_hash_lru_size( MapCtl* const pmc );
static Map* find_hash( MapCtl* const pmc, struct stat* const sbP );
static void mmc_really_unmap( MapCtl* const pmc, Map* mm );
static int  mmc_size_to_pmc( MapCtl** ppmc, const off_t st_size );
static void mmc_pmc_unmap_unref( MapCtl* const pmc, const int min_count );
static void mmc_pmc_unmap_ref( MapCtl* const pmc, const int min_count );
static void mmc_pmc_free_list( MapCtl* const pmc, const int min_count );
static void mmc_pmc_oom( MapCtl* const pmc0, const int do_log );
static void mmc_pmc_cleanup( MapCtl* const pmc, struct timeval* const nowP,
				const int do_age, const int do_free );
static void mmc_pmc_destroy( MapCtl* const pmc );
static const char* mmc_cache_type_des( const int cache_type );


/* ---------------- */
/* module functions */
/* ---------------- */


static inline void
add_lru_ref( MapCtl* const pmc, Map* const m )
    {
    m->prev_lru = pmc->lru_ref->prev_lru;
    m->next_lru = pmc->lru_ref;
    pmc->lru_ref->prev_lru->next_lru = m;
    pmc->lru_ref->prev_lru = m;
    }


static inline void
add_lru_unref( MapCtl* const pmc, Map* const m )
    {
    m->prev_lru = pmc->lru_unref->prev_lru;
    m->next_lru = pmc->lru_unref;
    pmc->lru_unref->prev_lru->next_lru = m;
    pmc->lru_unref->prev_lru = m;
    }


static inline void
del_lru( Map* const m )
    {
    m->prev_lru->next_lru = m->next_lru;
    m->next_lru->prev_lru = m->prev_lru;
    }


static inline unsigned int
hash_fstat( unsigned int hash_mask,
	ino_t ino, dev_t dev, off_t size, time_t ctime )
    {
    unsigned int h = 177573;

    h ^= ino;
    h += h << 5;
    h ^= dev;
    h += h << 5;
    h ^= size;
    h += h << 5;
    h ^= ctime;

    return ( h & hash_mask );
    }


static void
add_hash( MapCtl* const pmc, Map* m )
    {
    m->hash = hash_fstat( pmc->hash_mask, m->ino, m->dev, m->size, m->ctime );
    if ( pmc->hash_table[m->hash] == (Map*) 0 )
	{
	pmc->hash_table[m->hash] = m;
	m->prev_hash = m;
	m->next_hash = m;
	}
    else
	{
	Map *p = pmc->hash_table[m->hash];
	m->prev_hash = p->prev_hash;
	m->next_hash = p;
	p->prev_hash->next_hash = m;
	p->prev_hash = m;
	}
    }


static void
del_hash( MapCtl* const pmc, Map* m )
    {
    if ( pmc->hash_table[m->hash] == m )
	{
	if ( m->next_hash == m )
	    {  /* there is only this node on current hash chain */
	    pmc->hash_table[m->hash] = (Map*) 0;
	    return;
	    }
	pmc->hash_table[m->hash] = m->next_hash;
	}
    m->prev_hash->next_hash = m->next_hash;
    m->next_hash->prev_hash = m->prev_hash;
    }


/* Make sure the hash table is big enough. */
static int
check_hash_lru_size( MapCtl* const pmc )
    {
    Map* m;

    /* Are we just starting out? */
    if ( pmc->hash_table == (Map**) 0 )
	{
	switch ( pmc->cache_zone )
	    {
	    case MMC_CACHE_L0:
		pmc->hash_size = INITIAL_HASH_SIZE * 2;
		break;
	    case MMC_CACHE_L1:
	    case MMC_CACHE_L2:
		pmc->hash_size = INITIAL_HASH_SIZE;
		break;
	    case MMC_CACHE_L3:
	    case MMC_CACHE_L4:
	    case MMC_CACHE_L5:
	    default:
		pmc->hash_size = INITIAL_HASH_SIZE / 2;
		break;
	    }
	pmc->hash_mask = pmc->hash_size - 1;

	if ( pmc->lru_ref == (Map*) 0 )
	    {
	    /* allocate sentinel node for referenced map list */
	    pmc->lru_ref = (Map*) malloc( sizeof(Map) );
	    if ( pmc->lru_ref == (Map*) 0 )
		return MMC_ERROR;
	    memset( pmc->lru_ref, 0, sizeof(Map) );
	    pmc->lru_ref->prev_lru = pmc->lru_ref;
	    pmc->lru_ref->next_lru = pmc->lru_ref;
	    }

	if ( pmc->lru_unref == (Map*) 0 )
	    {
	    /* allocate sentinel node for unreferenced map list */
	    pmc->lru_unref = (Map*) malloc( sizeof(Map) );
	    if ( pmc->lru_unref == (Map*) 0 )
		{ /* free previous sentinel node */
		free( pmc->lru_ref );
		pmc->lru_ref = (Map*) 0;
		return MMC_ERROR;
		}
	    memset( pmc->lru_unref, 0, sizeof(Map) );
	    pmc->lru_unref->prev_lru = pmc->lru_unref;
	    pmc->lru_unref->next_lru = pmc->lru_unref;
	    }
	}
    /* Is it big enough for the current number of entries? */
    else if ( pmc->hash_size >= MAX_HASH_SIZE ||
	      pmc->hash_size * AVG_HASH_CHAIN_LENGTH >= pmc->map_count )
	return MMC_NORMAL;
    else
	{
	/* No, got to expand. */
	/* Double the hash size until it's big enough. */
	do
	    {
	    pmc->hash_size <<= 1;
	    }
	while ( pmc->hash_size < MAX_HASH_SIZE &&
		pmc->hash_size * AVG_HASH_CHAIN_LENGTH < pmc->map_count );
	pmc->hash_mask = pmc->hash_size - 1;
	/* Free the old table. */
	free( (void*) pmc->hash_table );
	}

    /* Make the new table. */
    pmc->hash_table = (Map**) calloc( pmc->hash_size, sizeof(Map*) );
    if ( pmc->hash_table == (Map**) 0 )
	return MMC_ERROR;

    /* (memory already zeroed by calloc) */

    /* Re-hash all referenced entries. */
    for ( m = pmc->lru_ref->next_lru; m != pmc->lru_ref; m = m->next_lru )
	add_hash( pmc, m );

    /* Re-hash all unreferenced entries. */
    for ( m = pmc->lru_unref->next_lru; m != pmc->lru_unref; m = m->next_lru )
	add_hash( pmc, m );

    return MMC_NORMAL;
    }


static Map*
find_hash( MapCtl* const pmc, struct stat* const sbP )
    {
    unsigned int h;
    Map* m0;
    Map* m;

    h = hash_fstat( pmc->hash_mask,
		sbP->st_ino, sbP->st_dev, sbP->st_size, sbP->st_ctime );
    m = m0 = pmc->hash_table[h];
    if ( m0 == (Map*) 0 )
	return (Map*) 0;
    do
	{
	if ( m->ino   == sbP->st_ino &&
	     m->dev   == sbP->st_dev &&
	     m->size  == sbP->st_size &&
	     m->ctime == sbP->st_ctime )
	    return m;
	m = m->next_hash;
	}
    while ( m != m0 );

    return (Map*) 0;
    }


static void
mmc_really_unmap( MapCtl* const pmc, Map* m )
    {

    switch( pmc->cache_type )
	{
	case MMC_CACHE_TYPE_MA:
	    /* surely file size is > 0 */
	    pmc->alloc_bytes -= m->size;
	    free( (void*) m->addr );
	    break;

#ifdef HAVE_MMAP
	case MMC_CACHE_TYPE_MM:
	    /* surely file size is > 0 */
	    pmc->alloc_bytes -= m->size;
	    if ( munmap( m->addr, m->size ) != 0 )
		syslog( LOG_ERR, "mmc_really_unmap: munmap - %m" );
	    break;
#endif /* HAVE_MMAP */

	case MMC_CACHE_TYPE_FD:
	    /* fd should be always valid */
	    (void) close( m->fd );
	    /* reset value (not really required) */
	    m->fd = -1;
	    break;

	default:
#ifdef MMC_DEBUG
	    /* it should never happen (SW or HW crash error) */
	    syslog( LOG_ERR,
		"mmc_really_unmap - unknown cache type %d (zone %d)",
			pmc->cache_type, pmc->cache_zone );
	    /* return, probably it will crash anyway */
	    return;
#else
	    break;
#endif
	}

    /* Detach from unreferenced list */
    del_lru( m );

    /* Detach from hash list */
    del_hash( pmc, m );

    /* and move the Map to the free list. */
    --pmc->map_count;
    if ( m->refcount > 0 )
	--pmc->use_count;
    m->next_lru = pmc->free_maps;
    pmc->free_maps = m;
    ++pmc->free_count;
    }


int
mmc_get_value( int value_type )
    {
	switch( value_type )
	{
	case MMC_V_MA_MAP_COUNT:
		return vMapCtl[MMC_CACHE_L0].map_count;
	case MMC_V_MA_USE_COUNT:
		return vMapCtl[MMC_CACHE_L0].use_count;
	case MMC_V_MM_MAP_COUNT:
		return	(
			vMapCtl[MMC_CACHE_L1].map_count +
			vMapCtl[MMC_CACHE_L2].map_count +
			vMapCtl[MMC_CACHE_L3].map_count +
			vMapCtl[MMC_CACHE_L4].map_count
			);
	case MMC_V_MM_USE_COUNT:
		return	(
			vMapCtl[MMC_CACHE_L1].use_count +
			vMapCtl[MMC_CACHE_L2].use_count +
			vMapCtl[MMC_CACHE_L3].use_count +
			vMapCtl[MMC_CACHE_L4].use_count
			);
	case MMC_V_FD_MAP_COUNT:
		return vMapCtl[MMC_CACHE_L5].map_count;
	case MMC_V_FD_USE_COUNT:
		return vMapCtl[MMC_CACHE_L5].use_count;
	case MMC_V_FD_SPA_COUNT:
		return vMapCtl[MMC_CACHE_L5].map_count -
		       vMapCtl[MMC_CACHE_L5].use_count;
	default:
		return -1;
	}
    }


int
mmc_cfg_get_param( int param_type )
    {
	switch( param_type )
	{
	case MMC_P_CLEANUP_TIME:
		return cfgCleanupTime;
	case MMC_P_DEFAULT_EXPIRE_AGE:
		return cfgDefaultExpireAge;
	case MMC_P_DESIRED_MAX_MALLOC_FILES:
		return cfgDesiredMaxMallocFiles;
	case MMC_P_DESIRED_MAX_MALLOC_BYTES:
		return (int) cfgDesiredMaxMallocBytes;
	case MMC_P_DESIRED_MAX_MAPPED_FILES:
		return cfgDesiredMaxMappedFiles;
	case MMC_P_DESIRED_MAX_MAPPED_BYTES:
		return (int) cfgDesiredMaxMappedBytes;
	case MMC_P_DESIRED_MAX_OPENED_FILES:
		return cfgDesiredMaxOpenedFiles;
	case MMC_P_UPLIMIT_MAX_OPENED_FILES:
		return DESIRED_TO_UP_LIMIT(cfgDesiredMaxOpenedFiles);
	case MMC_P_USE_MMAP:
#ifdef HAVE_MMAP
		return 1;
#else
		return 0;
#endif
	case MMC_P_USE_SENDFILE:
		return cfgUseFdMap;
	case MMC_P_USE_O_NOATIME:
		return cfgOpenNoATime;
	case MMC_P_CLOSE_ON_EXEC:
		return cfgCloseOnExec;
	case MMC_P_MAX_FILE_SIZE_L0:
		return (int) cfgMaxFileSizeL0;
	case MMC_P_MAX_FILE_SIZE_L1:
		return (int) cfgMaxFileSizeL1;
	case MMC_P_MAX_FILE_SIZE_L2:
		return (int) cfgMaxFileSizeL2;
	case MMC_P_MAX_FILE_SIZE_L3:
		return (int) cfgMaxFileSizeL3;
	case MMC_P_MAX_FILE_SIZE_L4:
		return (int) cfgMaxFileSizeL4;
	default:
		return -1;
	}
    }


int
mmc_cfg_set_param( int param_type, int param_value )
    {
    int	i = 0;

	switch( param_type )
	{
	case MMC_P_CLEANUP_TIME:
		cfgCleanupTime = param_value;
		if ( cfgCleanupTime < 2 )
		     cfgCleanupTime = 2;
		else
		if ( cfgCleanupTime > 200 )
		     cfgCleanupTime = 200;
		param_value = cfgCleanupTime;
		break;

	case MMC_P_DEFAULT_EXPIRE_AGE:
		if ( param_value < 4 )
		     param_value = 4;
		else
		if ( param_value > 10000 )
		     param_value = 10000;
		cfgDefaultExpireAge = param_value;
		vMapCtl[MMC_CACHE_L0].expire_age =
			DESIRED_EXPIRE_AGE_L0( cfgDefaultExpireAge );
		vMapCtl[MMC_CACHE_L1].expire_age =
			DESIRED_EXPIRE_AGE_L1( cfgDefaultExpireAge );
		vMapCtl[MMC_CACHE_L2].expire_age =
			DESIRED_EXPIRE_AGE_L2( cfgDefaultExpireAge );
		vMapCtl[MMC_CACHE_L3].expire_age =
			DESIRED_EXPIRE_AGE_L3( cfgDefaultExpireAge );
		vMapCtl[MMC_CACHE_L4].expire_age =
			DESIRED_EXPIRE_AGE_L4( cfgDefaultExpireAge );
		vMapCtl[MMC_CACHE_L5].expire_age =
			DESIRED_EXPIRE_AGE_L5( cfgDefaultExpireAge );
		break;

	case MMC_P_DESIRED_MAX_MALLOC_FILES:
		if ( param_value < 2 )
		     param_value = 2;
		else
		if ( param_value > 500000 )
		     param_value = 500000;
		cfgDesiredMaxMallocFiles = param_value;
		vMapCtl[MMC_CACHE_L0].desired_max_files =
			cfgDesiredMaxMallocFiles;
		vMapCtl[MMC_CACHE_L0].uplimit_max_files =
		DESIRED_TO_UP_LIMIT( vMapCtl[MMC_CACHE_L0].desired_max_files );
		break;

	case MMC_P_DESIRED_MAX_MALLOC_BYTES:
		if ( param_value < 100 )
		     param_value = 100;
		else
		if ( param_value > 200000000 )
		     param_value = 200000000;
		cfgDesiredMaxMallocBytes = (off_t) param_value;
		vMapCtl[MMC_CACHE_L0].desired_max_bytes =
			cfgDesiredMaxMallocBytes;
		vMapCtl[MMC_CACHE_L0].uplimit_max_bytes =
		DESIRED_TO_UP_LIMIT( vMapCtl[MMC_CACHE_L0].desired_max_bytes );
		break;

	case MMC_P_DESIRED_MAX_MAPPED_FILES:
		if ( param_value < 2 )
		     param_value = 2;
		else
		if ( param_value > 50000 )
		     param_value = 50000;
		cfgDesiredMaxMappedFiles = param_value;
		vMapCtl[MMC_CACHE_L1].desired_max_files =
		DESIRED_MAX_FILES_L1( cfgDesiredMaxMappedFiles );
		vMapCtl[MMC_CACHE_L2].desired_max_files =
		DESIRED_MAX_FILES_L2( cfgDesiredMaxMappedFiles );
		vMapCtl[MMC_CACHE_L3].desired_max_files =
		DESIRED_MAX_FILES_L3( cfgDesiredMaxMappedFiles );
		vMapCtl[MMC_CACHE_L4].desired_max_files =
		DESIRED_MAX_FILES_L4( cfgDesiredMaxMappedFiles );

		for ( i = MMC_CACHE_L1; i <= MMC_CACHE_L4; ++i )
		    {
		    vMapCtl[i].uplimit_max_files =
			DESIRED_TO_UP_LIMIT( vMapCtl[i].desired_max_files );
		    }
		break;

	case MMC_P_DESIRED_MAX_MAPPED_BYTES:
		if ( param_value < 4096 )
		     param_value = 4096;
		else
		if ( param_value > ( 1024 * 1024 * 1600 ) )
		     param_value = ( 1024 * 1024 * 1600 );
		cfgDesiredMaxMappedBytes = (off_t) param_value;
		vMapCtl[MMC_CACHE_L1].desired_max_bytes =
		DESIRED_MAX_BYTES_L1( cfgDesiredMaxMappedBytes );
		vMapCtl[MMC_CACHE_L2].desired_max_bytes =
		DESIRED_MAX_BYTES_L2( cfgDesiredMaxMappedBytes );
		vMapCtl[MMC_CACHE_L3].desired_max_bytes =
		DESIRED_MAX_BYTES_L3( cfgDesiredMaxMappedBytes );
		vMapCtl[MMC_CACHE_L4].desired_max_bytes =
		DESIRED_MAX_BYTES_L4( cfgDesiredMaxMappedBytes );

		for ( i = MMC_CACHE_L1; i <= MMC_CACHE_L4; ++i )
		    {
		    vMapCtl[i].uplimit_max_bytes =
			DESIRED_TO_UP_LIMIT2( vMapCtl[i].desired_max_bytes );
		    }
		break;

	case MMC_P_DESIRED_MAX_OPENED_FILES:
		if ( param_value < 4 )
		     param_value = 4;
		else
		if ( param_value > 52000 )
		     param_value = 52000;
		cfgDesiredMaxOpenedFiles = param_value;
		vMapCtl[MMC_CACHE_L5].desired_max_files =
			cfgDesiredMaxOpenedFiles;
		vMapCtl[MMC_CACHE_L5].uplimit_max_files =
		DESIRED_TO_UP_LIMIT( vMapCtl[MMC_CACHE_L5].desired_max_files );
		break;

	case MMC_P_UPLIMIT_MAX_OPENED_FILES:
		if ( param_value < 5 )
		     param_value = 5;
		else
		if ( param_value > 65000 )
		     param_value = 65000;
		cfgDesiredMaxOpenedFiles = UP_LIMIT_TO_DESIRED(param_value);
		vMapCtl[MMC_CACHE_L5].desired_max_files =
			cfgDesiredMaxOpenedFiles;
		vMapCtl[MMC_CACHE_L5].uplimit_max_files = param_value;
		break;

	case MMC_P_USE_SENDFILE:
		cfgUseFdMap = !!param_value;
		break;

	case MMC_P_USE_O_NOATIME:
		cfgOpenNoATime =
#ifdef O_NOATIME
		( param_value ? O_NOATIME : 0 );
#else
		param_value = 0;
#endif
		break;

	case MMC_P_CLOSE_ON_EXEC:
		cfgCloseOnExec = !!param_value;
		break;

	case MMC_P_MAX_FILE_SIZE_L0:
		if ( param_value < 0 )
		     param_value = 0;
		else
		if ( param_value > 4096 )
		     param_value = 4096;
		cfgMaxFileSizeL0 = (off_t) param_value;
		if ( cfgMaxFileSizeL0 > cfgMaxFileSizeL1)
		     cfgMaxFileSizeL1 = cfgMaxFileSizeL0 + 1024;
		if ( cfgMaxFileSizeL1 > cfgMaxFileSizeL2)
		     cfgMaxFileSizeL2 = cfgMaxFileSizeL1 + 1024;
		if ( cfgMaxFileSizeL2 > cfgMaxFileSizeL3)
		     cfgMaxFileSizeL3 = cfgMaxFileSizeL2 + 1024;
		/* L4 can be <= L3 */
		param_value = (int) cfgMaxFileSizeL0;
		break;

	case MMC_P_MAX_FILE_SIZE_L1:
		if ( param_value < 32 )
		     param_value = 32;
		else
		if ( param_value > (1024*1024*1024) )
		     param_value = (1024*1024*1024);
		cfgMaxFileSizeL1 = (off_t) param_value;
		if ( cfgMaxFileSizeL0 > cfgMaxFileSizeL1)
		     cfgMaxFileSizeL1 = cfgMaxFileSizeL0 + 1024;
		if ( cfgMaxFileSizeL1 > cfgMaxFileSizeL2)
		     cfgMaxFileSizeL2 = cfgMaxFileSizeL1 + 1024;
		if ( cfgMaxFileSizeL2 > cfgMaxFileSizeL3)
		     cfgMaxFileSizeL3 = cfgMaxFileSizeL2 + 1024;
		/* L4 can be <= L3 */
		param_value = (int) cfgMaxFileSizeL1;
		break;

	case MMC_P_MAX_FILE_SIZE_L2:
		cfgMaxFileSizeL2 = (off_t) param_value;
		if ( cfgMaxFileSizeL2 <= cfgMaxFileSizeL1 )
		     cfgMaxFileSizeL2  = cfgMaxFileSizeL1 + 1024;
		if ( cfgMaxFileSizeL3 <= cfgMaxFileSizeL2 )
		     cfgMaxFileSizeL3  = cfgMaxFileSizeL2 + 1024;
		/* L4 can be <= L3 */
		param_value = (int) cfgMaxFileSizeL2;
		break;

	case MMC_P_MAX_FILE_SIZE_L3:
		cfgMaxFileSizeL3 = (off_t) param_value;
		if ( cfgMaxFileSizeL3 <= cfgMaxFileSizeL1 )
		     cfgMaxFileSizeL3  = cfgMaxFileSizeL2 + 1024;
		if ( cfgMaxFileSizeL3 <= cfgMaxFileSizeL2 )
		     cfgMaxFileSizeL3  = cfgMaxFileSizeL2 + 1024;
		/* L4 can be <= L3 */
		param_value = (int) cfgMaxFileSizeL3;
		break;

	case MMC_P_MAX_FILE_SIZE_L4:
		if ( param_value < 0 )
		     param_value = 0;
		cfgMaxFileSizeL4 = (off_t) param_value;
		break;

	default:
		return -1;
	}
	return param_value;
    }


int
mmc_is_fdmap( const off_t st_size )
    {
    return ( MMC_IS_FDMAP( st_size ) );
    }


static int
mmc_size_to_pmc( MapCtl** ppmc, const off_t st_size )
    {
    if ( st_size < (off_t) 0 )
	return ( MMC_ERROR );

    if ( st_size <= cfgMaxFileSizeL0 )
	*ppmc = &vMapCtl[MMC_CACHE_L0];
    else
    if ( st_size <= cfgMaxFileSizeL1 )
	*ppmc = &vMapCtl[MMC_CACHE_L1];
    else
    if ( st_size <= cfgMaxFileSizeL2 )
	*ppmc = &vMapCtl[MMC_CACHE_L2];
    else
    if ( st_size <= cfgMaxFileSizeL3 )
	*ppmc = &vMapCtl[MMC_CACHE_L3];
    else
    if ( st_size <= cfgMaxFileSizeL4 || cfgUseFdMap == 0 )
	*ppmc = &vMapCtl[MMC_CACHE_L4];
    else
	*ppmc = &vMapCtl[MMC_CACHE_L5];

    return ( MMC_NORMAL );
    }


/*
** INPUT:  filename, sbP, nowP (all required)
** OUTPUT: pfd, paddr
*/
int
mmc_map( int* pfd, void** paddr, const char* filename,
	struct stat* const sbP, struct timeval* const nowP )
    {
    const char *pszFun = "mmc_map";
    int fd;
    Map* m;
    MapCtl *pmc = (MapCtl*) 0;

    /* Check input params */
    if ( sbP == (struct stat*) 0 || nowP == (struct timeval*) 0 )
	{
#ifdef MMC_DEBUG
	syslog( LOG_ERR, "%s: EPARAM: sbP %p, nowP %p (NULL) !",
		pszFun, sbP, nowP );
#endif
	return MMC_EPARAM;
	}

    /* Check for the size of file, we don't want to map zero sized files */
    if ( sbP->st_size == 0 )
	{
	*pfd = EOF;
	*paddr = MMC_DUMMY_ADDR;
	return MMC_NORMAL;
	}

    /* Get the proper cache ptr. */
    if ( mmc_size_to_pmc( &pmc, sbP->st_size ) != MMC_NORMAL )
	{
	syslog( LOG_ERR, "%s: size_to_pmc: st_size %ld",
		pszFun, sbP->st_size );
	return MMC_ERROR;
	}

    /* Check the size of hash table. */
    if ( check_hash_lru_size( pmc ) != MMC_NORMAL )
	{
	syslog( LOG_ERR, "%s: zone %d: check_hash_lru_size()",
			pszFun, pmc->cache_zone );
	return MMC_ERROR;
	}

    /* See if we have it mapped already, via the hash table. */
    m = find_hash( pmc, sbP );

    if ( m != (Map*) 0 )
	{
	/* Yep.  Just return the existing map */
	if ( m->refcount == 0 )
	    {
	    del_lru( m );
	    add_lru_ref( pmc, m );
	    ++pmc->use_count;
	    }
	++m->refcount;
#ifdef MMC_UPD_REFMAP_TIME
	m->reftime = nowP->tv_sec;
#endif
	*pfd   = m->fd;
	*paddr = m->addr;
	return MMC_NORMAL;
	}

    /* Open the file */
    fd = open( filename, O_RDONLY
#ifdef O_NOATIME
	| ( cfgOpenNoATime & O_NOATIME )
#endif
	);
    if ( fd < 0 )
	{
	syslog( LOG_ERR, "%s: open - %m", pszFun );
	return MMC_ERROR;
	}

    /* Find a free Map entry or make a new one. */
    if ( pmc->free_maps != (Map*) 0 )
	{
	m = pmc->free_maps;
	pmc->free_maps = m->next_lru;
	--pmc->free_count;
	}
    else
	{
	m = (Map*) malloc( sizeof(Map) );
	if ( m == (Map*) 0 )
	    {
	    (void) close( fd );
	    syslog( LOG_ERR, "%s: out of memory allocating a Map", pszFun );
	    return MMC_ERROR;
	    }
	++pmc->alloc_count;
	}

    /* Fill in the Map entry. */
    m->ino      = sbP->st_ino;
    m->dev      = sbP->st_dev;
    m->size     = sbP->st_size;
    m->ctime    = sbP->st_ctime;
    m->reftime  = nowP->tv_sec;
    m->refcount = 1;

    switch ( pmc->cache_type )
	{
	case MMC_CACHE_TYPE_MA:
	    /* surely size of file is > 0 */
	    m->fd = EOF;
	    /* Malloc file contents */
	    m->addr = (void*) malloc( m->size );
	    if ( m->addr == (void*) 0 && errno == ENOMEM &&
		 pmc->use_count < pmc->map_count )
		{
		/* Out of address space, we have some unreferenced maps,
		** thus free all of them in LEVELs >= (pmc) and try again.
		*/
		mmc_pmc_oom( pmc, DO_LOG );
		m->addr = (void*) malloc( m->size );
		}
	    if ( m->addr == (void*) 0 )
		{
		syslog( LOG_ERR, "%s: out of memory (file size %ld)",
			pszFun, m->size );
		(void) close( fd );
		free( (void*) m );
		--pmc->alloc_count;
		return MMC_ERROR;
		}
	    /* Read file into memory */
	    if ( read( fd, m->addr, m->size ) != m->size )
		{
		syslog( LOG_ERR, "%s: read - %m", pszFun );
		(void) close( fd );
		free( (void*) m );
		--pmc->alloc_count;
		return MMC_ERROR;
		}
	    pmc->alloc_bytes += m->size;
	    (void) close( fd );
	    break;
#ifdef HAVE_MMAP
	case MMC_CACHE_TYPE_MM:
	    /* surely size of file is > 0 */
	    m->fd = EOF;
	    /* Map the file into memory. */
	    m->addr = mmap( 0, m->size, PROT_READ, MAP_SHARED, fd, 0 );
	    if ( m->addr == (void*) MAP_FAILED && errno == ENOMEM &&
		 pmc->use_count < pmc->map_count )
		{
		/* Out of address space, we have some unreferenced maps,
		** thus free all of them in LEVELs >= (pmc) and try again.
		*/
		mmc_pmc_oom( pmc, DO_LOG );
		m->addr = mmap( 0, m->size, PROT_READ, MAP_SHARED, fd, 0 );
		}
	    if ( m->addr == (void*) MAP_FAILED )
		{
		syslog( LOG_ERR, "%s: mmap - %m (file size %ld)",
			pszFun, m->size );
		(void) close( fd );
		free( (void*) m );
		--pmc->alloc_count;
		return MMC_ERROR;
		}
	    pmc->alloc_bytes += m->size;
	    (void) close( fd );
	    break;
#endif
	case MMC_CACHE_TYPE_FD:
	    m->fd = fd;
	    m->addr = (void*) 0;
	    if ( cfgCloseOnExec )
		{
		/* set close-on-exec flag (useful for spawned subprocesses) */
		if ( fcntl( fd, F_SETFD, FD_CLOEXEC ) != 0 )
		    {
		    syslog( LOG_ERR, "%s: fcntl - %m", pszFun );
		    (void) close( fd );
		    free( (void*) m );
		    --pmc->alloc_count;
		    return MMC_ERROR;
		    }
		}

	    /* if there is cache pressure, then shrink FD cache */
	    if ( pmc->map_count >= pmc->uplimit_max_files )
		mmc_pmc_cleanup( pmc, nowP, NO_AGE, NO_FREE );

	    /* don't close fd */
	    break;

	default:
#ifdef MMC_DEBUG
	    /* this can't happen (SW or HW error) */
	    syslog( LOG_ERR, "%s: unknown cache type %d",
			pszFun, pmc->cache_type );
#endif
	    (void) close( fd );
	    free( (void*) m );
	    --pmc->alloc_count;
	    return MMC_FATAL;
	}

    /* Put the Map into the hash table. */
    add_hash( pmc, m );

    /* Put the Map on the lru referenced list. */
    add_lru_ref( pmc, m );

    ++pmc->map_count;
    ++pmc->use_count;

    /* Assign values to formal parameters */
    *pfd = m->fd;
    *paddr = m->addr;

    /* And return OK */
    return MMC_NORMAL;
    }


/*
** INPUT: fd, addr, sbP, nowP (all required)
** NOTE: *sbP must be the same previously passed to mmc_map().
*/
int
mmc_unmap( int fd, void* addr, struct stat* const sbP,
		struct timeval* const nowP )
    {
    const char *pszFun = "mmc_unmap";
    Map* m = (Map*) 0;
    MapCtl *pmc = (MapCtl*) 0;

    /* Check input params */
    if ( sbP == (struct stat*) 0 || nowP == (struct timeval*) 0 )
	{
#ifdef MMC_DEBUG
	syslog( LOG_ERR, "%s: EPARAM: sbP %p, nowP %p (NULL) !",
		pszFun, sbP, nowP );
#endif
	return MMC_EPARAM;
	}

    /* Check the size of file, we don't want to map or unmap zero sized files */
    if ( sbP->st_size == 0 )
	return MMC_NORMAL;

    /* This should never happen, but the check is good for stability */
    if ( fd == EOF && addr == MMC_DUMMY_ADDR )
	return MMC_NORMAL;

    /* convert size to ptr. to cache level */
    if ( mmc_size_to_pmc( &pmc, sbP->st_size ) == MMC_ERROR )
	{
	syslog( LOG_ERR, "%s: size_to_pmc: st_size %ld",
		pszFun, sbP->st_size );
	return MMC_ERROR;
	}

    /* Check the size of hash table (paranoia check) */
    if ( check_hash_lru_size( pmc ) != MMC_NORMAL )
	{
	syslog( LOG_ERR, "%s: zone %d: check_hash_lru_size()",
		pszFun, pmc->cache_zone );
	return MMC_ERROR;
	}

    /* Find the Map entry for this address.  First try a hash. */
    m = find_hash( pmc, sbP );

    if ( pmc->cache_type == MMC_CACHE_TYPE_FD )
	{
	if ( m == (Map*) 0 )
	    {  /* fatal error */
	    syslog( LOG_ERR, "%s: entry fd %d not found !",
		pszFun, fd );
	    return MMC_ENOENT;
	    }
	if ( m->fd != fd )
	    {  /* fatal error */
	    syslog( LOG_ERR, "%s: found BAD entry fd %d != %d !",
		pszFun, m->fd, fd );
	    return MMC_ENOMATCH;
	    }
	}
    else
	{   /* MMC_CACHE_TYPE_MA || MMC_CACHE_TYPE_MM */
	if ( m == (Map*) 0 )
	    {  /* fatal error */
	    syslog( LOG_ERR, "%s: entry addr %p not found !",
		pszFun, addr );
	    return MMC_ENOENT;
	    }
	if ( m->addr != addr )
	    {  /* fatal error */
	    syslog( LOG_ERR, "%s: found BAD entry addr %p != %p !",
		pszFun, m->addr, addr );
	    return MMC_ENOMATCH;
	    }
	}

    if ( m->refcount <= 0 )
	{
	syslog( LOG_ERR, "%s: found zero or negative (%d) refcount!",
		pszFun, m->refcount );
	return MMC_ERROR;
	}
#ifdef MMC_UPD_REFMAP_TIME
    m->reftime = nowP->tv_sec;
#endif
    if ( --m->refcount == 0 )
	{
	/* remove this entry from referenced and add it to unreferenced list */
#ifndef MMC_UPD_REFMAP_TIME
	m->reftime = nowP->tv_sec;
#endif
	del_lru( m );
	add_lru_unref( pmc, m );
	--pmc->use_count;

	/* If there is cache pressure, then shrink cache. */
	if ( pmc->map_count   > pmc->uplimit_max_files ||
	     pmc->alloc_bytes > pmc->uplimit_max_bytes )
	     mmc_pmc_cleanup( pmc, nowP, NO_AGE, NO_FREE );
	}

    /* OK, return */
    return MMC_NORMAL;
    }


#ifdef MMC_SLOW_MAP_UNMAP
/*
** INPUT:  filename
** OUTPUT: pfd, paddr
*/
int
mmc_slow_map( int* pfd, void** paddr, const char* filename )
    {
    struct timeval tv = { 0 };
    struct stat sb = { 0 };

    /* Stat the file */
    if ( stat( filename, &sb ) != 0 )
	{
#ifdef MMC_DEBUG
	syslog( LOG_ERR, "mmc_slow_map: stat - %m" );
#endif
	if ( errno == ENOENT || errno == ENOTDIR )
	    return MMC_ENOENT;
	else
	    return MMC_ERROR;
	}

    /* Get the current time */
    (void) gettimeofday( &tv, (struct timezone*) 0 );

    return mmc_map( pfd, paddr, filename, &sb, &tv );
    }


/*
** INPUT: fd, addr
*/
int
mmc_slow_unmap( int fd, void* addr )
    {
    int    idxCache;
    struct timeval tv = { 0 };
    struct stat sb = { 0 };
    Map* m = (Map*) 0;
    MapCtl *pmc = (MapCtl*) 0;

    /* Check input parameters */
    if ( ( fd == EOF && addr == (void*) 0 ) ||
	 ( fd != EOF && addr != (void*) 0 ) )
	{
#ifdef MMC_DEBUG
	syslog( LOG_ERR, "mmc_slow_unmap: EPARAM: fd %d addr %p (invalid)",
		fd, addr );
#endif
	return MMC_EPARAM;
	}

    /* Check for zero size flag (we don't map/unmap zero sized files) */
    if ( fd == EOF && addr == MMC_DUMMY_ADDR )
	return MMC_NORMAL;

    /* Get the current time */
    (void) gettimeofday( &tv, (struct timezone*) 0 );

    for ( idxCache = MMC_CACHE_L0; idxCache < MMC_CACHE_LMAX; ++idxCache )
	{
	pmc = &vMapCtl[idxCache];

	/* skip empty / unitialized caches */
	if ( pmc == (MapCtl*) 0 || pmc->lru_ref == (Map*) 0 )
	    continue;

	if ( fd != EOF )
	    {
	    if ( pmc->cache_type != MMC_CACHE_TYPE_FD )
		continue;
	    /* Search for given fd */
	    for ( m = pmc->lru_ref->next_lru;
		m != pmc->lru_ref;
		m = m->next_lru )
		{
		if ( m->fd == fd )
		    break;
		}
	    }
	else
	    {
	    if ( pmc->cache_type == MMC_CACHE_TYPE_FD )
		continue;
	    /* Search for given address */
	    for ( m = pmc->lru_ref->next_lru;
		m != pmc->lru_ref;
		m = m->next_lru )
		{
		if ( m->addr == addr )
		    break;
		}
	    }

	/* Check if a map was found */
	if ( m == pmc->lru_ref )
	    continue;

	/* OK, found ! */
	/* Fill the stat buf */
	sb.st_ino   = m->ino;
	sb.st_dev   = m->dev;
	sb.st_size  = m->size;
	sb.st_ctime = m->ctime;

	/* Now we can unmap it in the usual / fast way */
	return mmc_unmap( fd, addr, &sb, &tv );

	}

    /* Nope, not found */
    return MMC_ENOENT;
    }

#endif /* MMC_SLOW_MAP_UNMAP */


static void
mmc_pmc_unmap_unref( MapCtl* const pmc, const int min_count )
    {
    int unref_maps   = pmc->map_count - pmc->use_count;
    int maps_to_free = 0;
    Map* m0;
    Map* m;

    /* check if something has been allocated */
    /* in theory hash_table might be NULL because its allocation failed */
    if ( pmc->lru_unref  == (Map*)  0 ||
	 pmc->hash_table == (Map**) 0 )
	return;

    if ( min_count == 0 )
	unref_maps += 2;

    if ( min_count >= 0 && min_count < unref_maps )
	maps_to_free = unref_maps - min_count;

    for ( m = pmc->lru_unref->next_lru;
	  m != pmc->lru_unref && maps_to_free > 0;
	  --maps_to_free )
	{
	m0 = m;
	m = m->next_lru;
	mmc_really_unmap( pmc, m0 );
	}

    if ( m == pmc->lru_unref )
	{
	pmc->lru_unref->prev_lru = pmc->lru_unref;
	pmc->lru_unref->next_lru = pmc->lru_unref;
	}
    }


static void
mmc_pmc_unmap_ref( MapCtl* const pmc, const int min_count )
    {
    int ref_maps     = pmc->use_count;
    int maps_to_free = 0;
    Map* m0;
    Map* m;

    /* check if something has been allocated */
    /* in theory hash_table might be NULL because its allocation failed */
    if ( pmc->lru_ref  == (Map*)  0 ||
	 pmc->hash_table == (Map**) 0 )
	return;

    if ( min_count == 0 )
	ref_maps += 2;

    if ( min_count >= 0 && min_count < ref_maps )
	maps_to_free = ref_maps - min_count;

    for ( m = pmc->lru_ref->next_lru;
	  m != pmc->lru_ref && maps_to_free > 0;
	  --maps_to_free )
	{
	m0 = m;
	m = m->next_lru;
	mmc_really_unmap( pmc, m0 );
	}

    if ( m == pmc->lru_ref )
	{
	pmc->lru_ref->prev_lru = pmc->lru_ref;
	pmc->lru_ref->next_lru = pmc->lru_ref;
	}
    }


static void
mmc_pmc_free_list( MapCtl* const pmc, const int min_count )
    {
    Map* m;
    /* Really free excess blocks on the free list. */
    while ( pmc->free_maps != (Map*) 0 &&
	    pmc->free_count > min_count )
	{
	m = pmc->free_maps;
	pmc->free_maps = m->next_lru;
	--pmc->free_count;
	--pmc->alloc_count;
	free( (void*) m );
	}
    }


/* Out of Memory handler, it is called when an allocation fails,
** it tries to free only caches of the same type of current (pmc0).
** Cache levels < of current level are partially fred,
** while those >= current are totally fred.
*/
static void
mmc_pmc_oom( MapCtl* const pmc0, const int do_log )
    {
    int    idxCache = 0;
    int    free_count = 0;
    int    unref_maps = pmc0->map_count - pmc0->use_count;
    MapCtl *pmc;

    if ( do_log )
	{
	char	*pszErrno;
	if ( pmc0->cache_type == MMC_CACHE_TYPE_FD )
	    pszErrno = "EMFILE";
	else
	    pszErrno = "ENOMEM";
	syslog( LOG_WARNING,
	    "mmc: L%d: %s - freeing unreferenced maps (%d)",
		pmc0->cache_zone, pszErrno, unref_maps );
	}

    /* we free at most half unreferenced maps in levels < current */
    /* we free all unreferenced maps in levels >= current */
    for ( idxCache = MMC_CACHE_L0; idxCache < MMC_CACHE_LMAX; ++idxCache )
	{
	pmc = &vMapCtl[idxCache];

	/* We free only caches of the same type of that where OOM occurred */
	if ( pmc->cache_type != pmc0->cache_type )
	    continue;

	/* Compute how many unreferenced maps have to be left */
	if ( pmc->cache_zone < pmc0->cache_zone )
	    {	/* Partial free */
	    unref_maps = pmc->map_count - pmc->use_count;
	    free_count = pmc->desired_free_count / 2;
	    if ( pmc->map_count > pmc->desired_max_files )
		{ /* steady free */
		unref_maps /= 2;
		}
	    else
	    if ( pmc->map_count > pmc->desired_max_files / 8 )
		{ /* progressive free until a lower limit */
		if ( unref_maps > 16 )
		    unref_maps -= unref_maps / 16;
		else
		if ( unref_maps > 0 )
		   --unref_maps;
		}
	    }
	else
	    {	/* Total free */
	    unref_maps = 0;
	    free_count = 0;
	    }

	/* Leave only computed number of unreferenced maps */
	mmc_pmc_unmap_unref( pmc, unref_maps );

	/* Free cached unused maps, we leave only a few free maps */
	mmc_pmc_free_list( pmc, free_count );
	}
    }


static void
mmc_pmc_cleanup( MapCtl* const pmc, struct timeval* const nowP,
			const int do_age, const int do_free )
    {
    Map* m0;
    Map* m;

    /* check if something has been allocated */
    if ( pmc == (MapCtl*) 0 || pmc->lru_unref == (Map*) 0 )
	return;

    /* check hash table size, it might be NULL */
    if ( check_hash_lru_size( pmc ) != MMC_NORMAL )
	{
	syslog( LOG_ERR, "mmc_pmc_cleanup: zone %d: check_hash_lru_size()",
			pmc->cache_zone );
	return;
	}

    /* Really unmap any unreferenced entries until we go under file limit. */
    if ( pmc->map_count > pmc->desired_max_files )
	{
	int	unref_maps   = pmc->map_count - pmc->use_count;
	int	maps_to_free = pmc->map_count - pmc->desired_max_files;

	if ( unref_maps < 1 )
	    return;

	if ( maps_to_free > unref_maps )
	     maps_to_free = unref_maps;
	for ( m = pmc->lru_unref->next_lru;
	      m != pmc->lru_unref && maps_to_free > 0;
	      --maps_to_free )
	    {
	    m0 = m;
	    m = m->next_lru;
	    mmc_really_unmap( pmc, m0 );
	    }
	}

    /* Really unmap any unreferenced entries until we go under byte limit. */
    /* NOTE: alloc_bytes is signed, the total mapped space can be unsigned */
    if ( pmc->alloc_bytes < 0 )
	{
	for ( m = pmc->lru_unref->next_lru;
	      m != pmc->lru_unref &&
	      pmc->alloc_bytes <= 0;
	    )
	    {
	    m0 = m;
	    m = m->next_lru;
	    mmc_really_unmap( pmc, m0 );
	    }
	}

    /* Really unmap any unreferenced entries until we go under byte limit. */
    if ( pmc->alloc_bytes > pmc->desired_max_bytes )
	{
	for ( m = pmc->lru_unref->next_lru;
	      m != pmc->lru_unref &&
	      pmc->alloc_bytes > pmc->desired_max_bytes;
	    )
	    {
	    m0 = m;
	    m = m->next_lru;
	    mmc_really_unmap( pmc, m0 );
	    }
	}

    /* Really unmap any unreferenced entries older than the age limit. */
    if ( do_age )
	{
	time_t now;

	/* Get the current time, if necessary. */
	if ( nowP != (struct timeval*) 0 )
	    now = nowP->tv_sec;
	else
	    now = time( (time_t*) 0 );

	if ( now < pmc->expire_age )
	    now = 0;
	else
	    now -= pmc->expire_age;

	for ( m = pmc->lru_unref->next_lru;
	      m != pmc->lru_unref &&
	      m->reftime < now;
	    )
	    {
	    m0 = m;
	    m = m->next_lru;
	    mmc_really_unmap( pmc, m0 );
	    }
	}

    /* Really free excess blocks on the free list. */
    if ( do_free )
	mmc_pmc_free_list( pmc, pmc->desired_free_count );

    }


void
mmc_cleanup( struct timeval* const nowP )
    {
    int    idxCache;

    for ( idxCache = MMC_CACHE_L0; idxCache < MMC_CACHE_LMAX; ++idxCache )
	{
	mmc_pmc_cleanup( &vMapCtl[idxCache], nowP, DO_AGE, DO_FREE );
	}
    }


static void
mmc_pmc_destroy( MapCtl* const pmc )
    {
    /* unmap and destroy all cached entries */
    mmc_pmc_unmap_unref( pmc, 0 );
    mmc_pmc_unmap_ref( pmc, 0 );
    mmc_pmc_free_list( pmc, 0 );
    }


void
mmc_destroy( void )
    {
    int    idxCache;

    for ( idxCache = MMC_CACHE_L0; idxCache < MMC_CACHE_LMAX; ++idxCache )
	{
	mmc_pmc_destroy( &vMapCtl[idxCache] );
	}
    }


/* Return mmc cache type short description */
static const char *
mmc_cache_type_des( const int cache_type )
    {
    /* keep it in sync with MMC_CACHE_* (cache types) */
    static const char* vszCacheDes[MMC_CACHE_TYPE_MAX+1] =
			{ "??", "MA", "MM", "FD" };

    return( vszCacheDes
		[(
		( cache_type < MMC_CACHE_TYPE_MIN ||
		  cache_type > MMC_CACHE_TYPE_MAX ||
		  cache_type >= sizeof(vszCacheDes) / sizeof(vszCacheDes[0])
		) ? MMC_CACHE_TYPE_UNK : cache_type
		)]
	);
    }


/* Generate debugging statistics syslog message. */
void
mmc_logstats( long secs )
    {
    int    idxCache;

	syslog(
		LOG_INFO,
"  Cache Allocated Active  Used   Free Hash-Size Allocated-Bytes");

    for ( idxCache = MMC_CACHE_L0; idxCache < MMC_CACHE_LMAX; ++idxCache )
	{
	MapCtl *pmc = &vMapCtl[idxCache];

	syslog(
		LOG_INFO,
#ifdef HAVE_INT64T
"  L%d-%s:   %6d %6d %5d %6d %6d   %16ld",
#else
"  L%d-%s:   %6d %6d %5d %6d %6d   %16ld",
#endif
		pmc->cache_zone,
		mmc_cache_type_des( pmc->cache_type ),
		pmc->alloc_count,
		pmc->map_count,
		pmc->use_count,
		pmc->free_count,
		pmc->hash_size, (
#ifdef HAVE_INT64T
		(int64_t)
#endif
		pmc->alloc_bytes )
	);
	if ( idxCache != pmc->cache_zone ||
	     pmc->map_count + pmc->free_count != pmc->alloc_count ||
	     pmc->use_count < 0 || pmc->use_count > pmc->map_count )
	    syslog( LOG_ERR, "mmc: (%d) cache L%d: counts don't add up!",
		idxCache,
		pmc->cache_zone );
	}

    }
