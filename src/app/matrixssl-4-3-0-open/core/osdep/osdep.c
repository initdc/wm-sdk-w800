/**
 *      @file    osdep.c
 *      @version eec42aa (HEAD -> master, tag: 4-3-0-open)
 *
 *      WIN32 platform PScore .
 */
/*
 *      Copyright (c) 2013-2016 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "wm_osal.h"
#include "wm_crypto_hard.h"

#include "../coreApi.h"
#include "osdep.h"

#if 1

/******************************************************************************/
/* TIME */

//static LARGE_INTEGER hiresStart;   /* zero-time */
//static LARGE_INTEGER hiresFreq;    /* tics per second */

int osdepTimeOpen(void)
{
    return PS_SUCCESS;
}

void osdepTimeClose(void)
{
}

/* PScore Public API implementations */
int32 psGetTime(psTime_t *t, void *userPtr)
{
	if (t == NULL) {
		return tls_os_get_time() / HZ;
	} 

	t->tv_sec = tls_os_get_time() / HZ;
	t->tv_usec = (tls_os_get_time() % HZ) * 1000 * 1000 / HZ;
	
	return t->tv_sec;
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
	if (now.tv_usec < then.tv_usec) {
		now.tv_sec--;
		now.tv_usec += 1000000; /* borrow 1 second worth of usec */
	}
	return (int32)((now.tv_sec - then.tv_sec) * 1000) + 
		((now.tv_usec - then.tv_usec)/ 1000);
}

int32 psCompareTime(psTime_t a, psTime_t b, void *userPtr)
{
/*
	Time comparison.  1 if 'a' is less than or equal.  0 if 'a' is greater
*/
	if (a.tv_sec < b.tv_sec) {
		return 1;
	}
	if (a.tv_sec == b.tv_sec && a.tv_usec <= b.tv_usec) {
		return 1;
	}
	return 0;
}

/******************************************************************************/
/* MUTEX */

# ifdef USE_MULTITHREADING

int32_t osdepMutexOpen(void)
{
    return PS_SUCCESS;
}

void osdepMutexClose(void)
{
}

int32_t psCreateMutex(psMutex_t *mutex, uint32_t flags)
{
    return PS_SUCCESS;
}

void psLockMutex(psMutex_t *mutex)
{
}

void psUnlockMutex(psMutex_t *mutex)
{
}

void psDestroyMutex(psMutex_t *mutex)
{
}
# endif /* USE_MULTITHREADING */

/******************************************************************************/
/* ENTROPY */
//static HCRYPTPROV hProv;        /* Crypto context for random bytes */

int osdepEntropyOpen(void)
{
    return PS_SUCCESS;
}

void osdepEntropyClose(void)
{
}

int32 psGetEntropy(unsigned char *bytes, uint32 size, void *userPtr)
{
	int i = 0;
	tls_crypto_random_init(tls_os_get_time(), CRYPTO_RNG_SWITCH_32);
	int ret = tls_crypto_random_bytes(bytes, size);
    tls_crypto_random_stop();
#if 0
	printf("psGetEntropy:\n");
	for(; i < size; i++)
	{
		printf("%02x ", bytes[i]);
	}
	printf("\n");
#endif
	return ret;
}

/******************************************************************************/
/* TRACE */

int osdepTraceOpen(void)
{
    return PS_SUCCESS;
}

void osdepTraceClose(void)
{
}

void _psTrace(const char *msg)
{
    printf("%s", msg);
}

/* Message should contain one %s, unless value is NULL */
void _psTraceStr(const char *message, const char *value)
{
    if (value)
    {
        printf(message, value);
    }
    else
    {
        printf("%s", message);
    }
}

/* message should contain one %d */
void _psTraceInt(const char *message, int32 value)
{
    printf(message, value);
}

/* message should contain one %p */
void _psTracePtr(const char *message, const void *value)
{
    printf(message, value);
}

/******************************************************************************/
/* DEBUGGING */

# ifdef HALT_ON_PS_ERROR
void osdepBreak(void)
{
    /* System halt on psError (and assert) */
    DebugBreak();
}
# endif /* HALT_ON_PS_ERROR */

/******************************************************************************/
/* FILE SYSTEM */

# ifdef MATRIX_USE_FILE_SYSTEM
/*
    Memory info:
    Caller must free 'buf' parameter on success
    Callers do not need to free buf on function failure
 */
psRes_t psGetFileBuf(psPool_t *pool, const char *fileName, unsigned char **buf,
    psSizeL_t *bufLen)
{
    return PS_SUCCESS;
}
# endif /* MATRIX_USE_FILE_SYSTEM */
#if 0
int     halOpen(void)
{
	return 0;
}
void    halAlert(void)
{}
void    halClose(void)
{}
#endif

#endif

/******************************************************************************/
