/* mmc.h - header file for mmap cache package
**
** Copyright © 1998 by Jef Poskanzer <jef@acme.com>.
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

#ifndef _MMC_H_
#define _MMC_H_

/* return codes (errors must be negative) */
#define MMC_NORMAL	(0)		/* all OK */
#define MMC_ERROR	(-1)		/* error */
#define MMC_FATAL	(-2)		/* fatal error (you should exit) */
#define MMC_EPARAM	(-10)		/* error in input parameters */
#define MMC_ENOENT	(-100)		/* entry not found */
#define MMC_ENOMATCH	(-101)		/* entry found but not matching */

/* type of parameters */
#define MMC_P_CLEANUP_TIME		0
#define MMC_P_DEFAULT_EXPIRE_AGE	1
#define MMC_P_DESIRED_MAX_MALLOC_FILES	2
#define MMC_P_DESIRED_MAX_MALLOC_BYTES	3
#define MMC_P_DESIRED_MAX_MAPPED_FILES	4
#define MMC_P_DESIRED_MAX_MAPPED_BYTES	5
#define MMC_P_DESIRED_MAX_OPENED_FILES	6
#define MMC_P_UPLIMIT_MAX_OPENED_FILES	7
#define MMC_P_USE_MMAP			8
#define MMC_P_USE_SENDFILE		9
#define MMC_P_USE_O_NOATIME		10
#define MMC_P_CLOSE_ON_EXEC		11
#define MMC_P_MAX_FILE_SIZE_L0		20
#define MMC_P_MAX_FILE_SIZE_L1		21
#define MMC_P_MAX_FILE_SIZE_L2		22
#define MMC_P_MAX_FILE_SIZE_L3		23
#define MMC_P_MAX_FILE_SIZE_L4		24

/* type of current work parameters */
#define MMC_V_MA_MAP_COUNT		100
#define MMC_V_MA_USE_COUNT		101
#define MMC_V_MM_MAP_COUNT		110
#define MMC_V_MM_USE_COUNT		111
#define MMC_V_FD_MAP_COUNT		120
#define MMC_V_FD_USE_COUNT		121
#define MMC_V_FD_SPA_COUNT		122

/* Get current param value (MMC_V_*)
*/
extern int mmc_get_value( int value_type );

/* Get config. param value (MMC_P_*)
*/
extern int mmc_cfg_get_param( int param_type );

/* Set config. param value (MMC_P_*)
*/
extern int mmc_cfg_set_param( int param_type, int param_value );

/* Returns a boolean value (TRUE/FALSE) whether a file with given st_size
** should use fdMap (instead of maMap or mmMap method).
*/
extern int mmc_is_fdmap( const off_t st_size );

/* Returns MMC_NORMAL if everything succeded otherwise MMC_* (error).
/* In output parameters it returns a file descriptor or
** a pointer to a malloc()ed area or o pointer to an mmap()ed area
** for the given file.
** You must pass a valid stat buffer on the file and the current time.
** If you have a stat buffer on the file, pass it in, otherwise pass 0.
** Same for the current time.
*/
extern int mmc_map( int* pfd, void** paddr, const char* filename,
			struct stat* const sbP, struct timeval* const nowP );

/* Returns MMC_NORMAL if everything succeded otherwise MMC_* (error).
** Done with a file descriptor or memory ptr. that was returned by mmc_map().
** You must pass the same stat buffer on the file you passed to mmc_map()
** and the current time.
** If you have a stat buffer on the file, pass it in, otherwise pass 0.
** Same for the current time.
*/
extern int mmc_unmap( int fd, void* addr,
			struct stat* const sbP, struct timeval* const nowP );

/* Slow functions, don't use / enable them unless you use only a few
** maps; this because they are really slow (they use less parameters).
*/
#ifdef notdef
#define MMC_SLOW_MAP_UNMAP
#endif

#ifdef MMC_SLOW_MAP_UNMAP

/* Returns MMC_NORMAL if everything succeded otherwise MMC_* (error).
** It does the same thing as mmc_map() but it does not require
** a stat buf and current time, thus it is a bit slower.
*/
extern int mmc_slow_map( int* pfd, void** paddr, const char* filename );

/* Returns MMC_NORMAL if everything succeded otherwise MMC_* (error).
** It tries to unmap a fd or an addr (as mmc_unmap) without using a stat buf,
** thus it is painfully slow (linear search).
*/
extern int mmc_slow_unmap( int fd, void* addr );

#endif /* MMC_SLOW_MAP_UNMAP */

/* Clean up the mmc package, freeing any unused storage.
** This should be called periodically, say every 10 - 120 seconds.
** If you have the current time, pass it in, otherwise pass 0.
*/
extern void mmc_cleanup( struct timeval* const nowP );

/* Free all storage, usually in preparation for exiting. */
extern void mmc_destroy( void );

/* Generate debugging statistics syslog message. */
extern void mmc_logstats( long secs );

#endif /* _MMC_H_ */
